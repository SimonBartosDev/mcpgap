"""Filesystem observation by snapshotting the sandbox's writable tree.

This is the *complete* half of filesystem observation, and it is complete for a
specific reason worth stating: the sandbox confines writes to the run's working
directory, and `tests/regression/test_sandbox_containment.py` asserts that a
write anywhere else is refused. So if the code under test wrote anything at all,
it wrote it here, and diffing this tree finds it. No cooperation from the
package is required and there is nothing for it to unhook.

Reads are a different matter. Nothing about a read leaves a trace on disk, so
they come from the preload shim, which is best-effort. The two are kept apart in
the model rather than blended into one "filesystem activity" number, because one
is a guarantee and the other is an attempt.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

# Paths mcpgap itself creates inside the working directory. Excluded from
# snapshots so the tool does not report its own machinery as package behaviour.
# Every exclusion is a blind spot, so the list is short and each entry is here
# because we wrote the file, not because it was inconvenient.
OUR_OWN_ARTEFACTS = (
    "mcpgap-ca.pem",  # ephemeral proxy CA
    "sandbox.sb",  # generated seatbelt profile
    "mcpgap-events.jsonl",  # preload shim's event log
    "mcpgap-shim.cjs",  # the preload shim itself
)
OUR_OWN_PREFIXES = ("leaf-",)  # per-host TLS leaf certs minted by the proxy


@dataclass(frozen=True, slots=True)
class FileState:
    size: int
    digest: str


def _is_ours(relative: Path) -> bool:
    """Whether mcpgap created this file rather than the package under test.

    Only the shim, its log, the proxy CA and leaf certs, and the generated
    seatbelt profile. The child's HOME is a directory we create but do not fill,
    so anything appearing there is the package's own behaviour and is kept.
    """
    name = relative.name
    return name in OUR_OWN_ARTEFACTS or any(name.startswith(p) for p in OUR_OWN_PREFIXES)


def snapshot(root: Path, *, skip_dirs: frozenset[str] = frozenset()) -> dict[str, FileState]:
    """Hash every regular file under `root`, keyed by path relative to it."""
    states: dict[str, FileState] = {}
    if not root.is_dir():
        return states
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:  # pragma: no cover - rglob guarantees containment
            continue
        if skip_dirs & set(relative.parts):
            continue
        if _is_ours(relative):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        states[str(relative)] = FileState(len(data), hashlib.sha256(data).hexdigest())
    return states


def diff_snapshots(
    before: dict[str, FileState], after: dict[str, FileState]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Return (created, modified, deleted) paths between two snapshots."""
    created = tuple(sorted(set(after) - set(before)))
    deleted = tuple(sorted(set(before) - set(after)))
    modified = tuple(
        sorted(path for path in set(before) & set(after) if before[path] != after[path])
    )
    return created, modified, deleted
