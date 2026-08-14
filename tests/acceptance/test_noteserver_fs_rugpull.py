"""Acceptance gate for filesystem and subprocess recording.

The postmark-mcp gate cannot exercise these recorders: that package touches no
files and spawns no subprocesses, so a correct recorder and a silently broken
one both report nothing. This file closes that gap with a synthetic fixture
(`tests/fixtures/noteserver`) that genuinely writes files and spawns processes.

The fixture mirrors the postmark rug pull in a different medium. v1 and v2 have
a byte-identical declared tool surface -- same names, descriptions and schemas.
v2's `saveNote` still writes the file the caller asked for, and additionally
writes an undeclared shadow copy and passes the note body to a subprocess. Both
extras are inert, but they have the shape a real leak would have.

`test_recorders_are_not_silently_dead` is the load-bearing test here. Everything
else would pass against a recorder that observed nothing at all, which is the
exact failure this project exists to refuse.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from mcpgap.scan import diff_observations, scan_package_version

pytestmark = pytest.mark.sandbox

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "noteserver"
CLEAN = "v1"
RUGGED = "v2"


@pytest.fixture(scope="module")
def scans(tmp_path_factory: pytest.TempPathFactory):
    work = tmp_path_factory.mktemp("mcpgap-noteserver")
    out = {}
    for version in (CLEAN, RUGGED):
        root = work / version / "package"
        shutil.copytree(FIXTURES / version, root)
        out[version] = scan_package_version(root, package="noteserver", version=version, runs=3)
    return out


@pytest.fixture(scope="module")
def report(scans):
    return diff_observations(scans[CLEAN], scans[RUGGED])


def test_recorders_are_not_silently_dead(scans) -> None:
    """The guard: prove the recorders observe anything at all.

    A recorder that returns empty results satisfies every differential
    assertion below, because nothing differs from nothing. Against postmark-mcp
    that emptiness is genuine; here it would mean the preload shim never loaded
    or the snapshot never ran. Assert positively that both mechanisms fired.
    """
    for version, observation in scans.items():
        save = observation.observations["saveNote"]
        assert save.file_changes.created, (
            f"{version}: saveNote wrote a note, but the filesystem snapshot saw "
            "no created file -- the snapshot recorder is not working"
        )
        assert save.file_events, (
            f"{version}: saveNote called fs.writeFileSync, but the preload shim "
            "recorded no filesystem events -- the shim is not loaded"
        )
    spawns = scans[RUGGED].observations["saveNote"].process_events
    assert spawns, (
        "v2's saveNote spawns /bin/echo, but no process event was recorded -- "
        "the subprocess recorder is not working"
    )


def test_diff_surfaces_the_undeclared_shadow_file(report) -> None:
    """The gate: a file v2 writes and v1 does not, under identical inputs."""
    findings = report.findings_for("saveNote")
    assert findings, "no finding reported for saveNote between v1 and v2"

    shadow = [f for f in findings if "shadow" in str(f.value) and f.kind.startswith("file_")]
    assert shadow, (
        f"diff did not surface the undeclared shadow file; got {[f.describe() for f in findings]}"
    )
    assert shadow[0].kind == "file_created"


def test_diff_surfaces_the_undeclared_subprocess(report) -> None:
    """A subprocess v2 spawns and v1 does not.

    Reported as best-effort: the shim that sees this is cooperative, and a
    package determined to hide a spawn can. Absence of a process finding is not
    evidence that nothing was spawned.
    """
    spawns = [f for f in report.findings_for("saveNote") if f.kind == "process_spawned"]
    assert spawns, "diff did not surface the added subprocess spawn"
    assert "/bin/echo" in str(spawns[0].value)


def test_declared_surface_is_unchanged(report) -> None:
    """Same premise as the postmark gate, in a different medium.

    A declared-metadata scanner sees nothing here either: the names,
    descriptions and schemas are byte-identical across the two versions.
    """
    assert not report.declared_added
    assert not report.declared_removed
    assert not report.declared_schema_changed


def test_caller_requested_file_is_not_flagged(report) -> None:
    """Attribution control.

    Both versions write `notes/<nonce>.txt`, the file our own probe input asked
    for. It is not a difference between the versions and must not be reported.
    Flagging a package for doing exactly what it was asked to do would be the
    false positive that makes a tool like this useless.
    """
    spurious = [
        f
        for f in report.findings_for("saveNote")
        if f.kind.startswith("file_") and "shadow" not in str(f.value)
    ]
    assert not spurious, f"flagged caller-requested writes: {[f.describe() for f in spurious]}"


def test_self_diff_reports_nothing(scans) -> None:
    report = diff_observations(scans[CLEAN], scans[CLEAN])
    assert not report.findings


def test_no_tool_was_unstable_across_runs(scans) -> None:
    """Filesystem observation must not introduce nondeterminism.

    Each run stages a fresh copy of the package in a fresh temporary directory,
    so absolute paths differ between runs by construction. If those paths leaked
    into the observation unnormalised, every tool would be UNSTABLE and no
    verdict could be issued -- our own plumbing reported as a finding.
    """
    for version, observation in scans.items():
        assert not observation.unstable_tools, (
            f"{version}: runs disagreed for {sorted(observation.unstable_tools)}"
        )
