"""Hermetic tests for the filesystem and subprocess observers.

These run everywhere, including Linux CI where there is no sandbox backend. The
acceptance gate that exercises these recorders end to end is macOS-only, so
without this file the logic below would be unverified on the platform most
contributors would run CI on.
"""

from __future__ import annotations

from pathlib import Path

from mcpgap.diff import _diff_side_effects
from mcpgap.model import FileChanges, FileEvent, ProcessEvent, ToolObservation
from mcpgap.observers import diff_snapshots, install_shim, read_events, snapshot
from mcpgap.observers.events import events_path


def test_snapshot_detects_create_modify_delete(tmp_path: Path) -> None:
    (tmp_path / "keep.txt").write_text("same")
    (tmp_path / "change.txt").write_text("before")
    (tmp_path / "gone.txt").write_text("bye")
    before = snapshot(tmp_path)

    (tmp_path / "change.txt").write_text("after")
    (tmp_path / "gone.txt").unlink()
    (tmp_path / "new.txt").write_text("hello")
    created, modified, deleted = diff_snapshots(before, snapshot(tmp_path))

    assert created == ("new.txt",)
    assert modified == ("change.txt",)
    assert deleted == ("gone.txt",)


def test_snapshot_detects_same_size_content_change(tmp_path: Path) -> None:
    """Size alone is not enough; the snapshot hashes contents.

    A payload swapped for one of identical length is exactly the change an
    attacker would prefer, and a size-only comparison would miss it.
    """
    target = tmp_path / "f.txt"
    target.write_text("AAAA")
    before = snapshot(tmp_path)
    target.write_text("BBBB")
    _, modified, _ = diff_snapshots(before, snapshot(tmp_path))
    assert modified == ("f.txt",)


def test_snapshot_excludes_our_own_artefacts(tmp_path: Path) -> None:
    """mcpgap's own files must not be reported as package behaviour."""
    for name in ("mcpgap-ca.pem", "sandbox.sb", "mcpgap-events.jsonl", "leaf-example.com.pem"):
        (tmp_path / name).write_text("x")
    (tmp_path / "written-by-package.txt").write_text("x")
    assert set(snapshot(tmp_path)) == {"written-by-package.txt"}


def test_snapshot_skips_named_directories(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("x")
    (tmp_path / "app.js").write_text("x")
    assert set(snapshot(tmp_path, skip_dirs=frozenset({"node_modules"}))) == {"app.js"}


def test_read_events_parses_and_advances_cursor(tmp_path: Path) -> None:
    log = tmp_path / "events.jsonl"
    log.write_text(
        '{"kind":"fs","op":"writeFileSync","path":"/a"}\n'
        '{"kind":"proc","op":"spawn","argv":["/bin/echo","hi"]}\n'
    )
    files, procs, cursor = read_events(log)
    assert [f.path for f in files] == ["/a"]
    assert procs[0].argv == ("/bin/echo", "hi")
    assert procs[0].command == "/bin/echo"
    assert cursor == 2

    # Appending must yield only the new events, so activity is attributed to
    # the tool call that caused it rather than to the whole run.
    with log.open("a") as handle:
        handle.write('{"kind":"fs","op":"readFileSync","path":"/b"}\n')
    files, procs, cursor = read_events(log, cursor)
    assert [f.path for f in files] == ["/b"]
    assert procs == []
    assert cursor == 3


def test_read_events_survives_a_torn_final_line(tmp_path: Path) -> None:
    """A process killed mid-write must not take the whole run down."""
    log = tmp_path / "events.jsonl"
    log.write_text('{"kind":"fs","op":"writeFileSync","path":"/a"}\n{"kind":"fs","op":"wri')
    files, _, _ = read_events(log)
    assert [f.path for f in files] == ["/a"]


def test_read_events_drops_node_runtime_noise(tmp_path: Path) -> None:
    """Node reads its own module graph through the hooked API.

    That burst is the runtime starting, not the package acting. Only the
    `file://` URL form is dropped, which application code does not use.
    """
    log = tmp_path / "events.jsonl"
    log.write_text(
        '{"kind":"fs","op":"readFileSync","path":"file:///app/index.js"}\n'
        '{"kind":"fs","op":"readFileSync","path":"/app/secrets.env"}\n'
    )
    files, _, _ = read_events(log)
    assert [f.path for f in files] == ["/app/secrets.env"]


def test_install_shim_writes_shim_and_creates_log(tmp_path: Path) -> None:
    """The log must exist before the child starts; the shim opens it for append."""
    shim, log = install_shim(tmp_path)
    assert shim.is_file() and "MCPGAP_EVENTS" in shim.read_text()
    assert log == events_path(tmp_path)
    assert log.is_file()


def _obs(tool: str, **kwargs) -> ToolObservation:
    return ToolObservation(tool=tool, **kwargs)


def test_side_effect_diff_reports_only_the_difference() -> None:
    old = _obs("t", file_changes=FileChanges(created=("notes/a.txt",)))
    new = _obs("t", file_changes=FileChanges(created=("notes/a.txt", "notes/.shadow")))
    findings = list(_diff_side_effects("t", old, new, caller_tokens=set()))
    assert [(f.kind, f.value) for f in findings] == [("file_created", "notes/.shadow")]
    assert findings[0].best_effort is False


def test_side_effect_diff_marks_spawns_best_effort() -> None:
    """A spawn comes from the cooperative shim and is labelled as such.

    Filesystem writes come from the snapshot, which the package cannot evade.
    Conflating the two would overstate what a missing process finding means.
    """
    new = _obs("t", process_events=(ProcessEvent(op="execFileSync", argv=("/bin/echo", "x")),))
    findings = list(_diff_side_effects("t", _obs("t"), new, caller_tokens=set()))
    assert [(f.kind, f.best_effort) for f in findings] == [("process_spawned", True)]


def test_side_effect_diff_reports_reads_but_not_writes_from_the_shim() -> None:
    """Writes have a snapshot witness; taking them from the shim too would double-count."""
    new = _obs(
        "t",
        file_events=(
            FileEvent(op="readFileSync", path="/etc/hosts"),
            FileEvent(op="writeFileSync", path="/tmp/out"),
        ),
    )
    findings = list(_diff_side_effects("t", _obs("t"), new, caller_tokens=set()))
    assert [(f.kind, f.value) for f in findings] == [("file_read", "/etc/hosts")]


def test_side_effect_diff_is_silent_when_nothing_changed() -> None:
    same = FileChanges(created=("a",), modified=("b",))
    old = _obs("t", file_changes=same, process_events=(ProcessEvent("spawn", ("/bin/ls",)),))
    new = _obs("t", file_changes=same, process_events=(ProcessEvent("spawn", ("/bin/ls",)),))
    assert list(_diff_side_effects("t", old, new, caller_tokens=set())) == []
