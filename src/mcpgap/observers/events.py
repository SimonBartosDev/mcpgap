"""Read the preload shim's event log.

The shim appends one JSON object per line to a file in the working directory.
Events are sliced by line offset around each tool call, the same way outbound
requests are sliced by index, so activity is attributed to the tool that caused
it rather than to the run as a whole.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcpgap.model import FileEvent, ProcessEvent

EVENTS_FILENAME = "mcpgap-events.jsonl"
SHIM_FILENAME = "mcpgap-shim.cjs"

# Node reads its own entry point and module graph through the same API we hook,
# so the log opens with a burst of activity that is the runtime starting up
# rather than the package doing anything. Dropping it is a judgement call, so it
# is narrow: only Node's `file://` URL form, which application code does not use.
_RUNTIME_NOISE_PREFIXES = ("file://",)


def shim_path(workdir: Path) -> Path:
    return workdir / SHIM_FILENAME


def events_path(workdir: Path) -> Path:
    return workdir / EVENTS_FILENAME


def install_shim(workdir: Path) -> tuple[Path, Path]:
    """Copy the shim into the working directory and create its log.

    The shim must live inside the sandbox's readable tree, and the log must
    exist before the child starts because the shim opens it for append at load.
    """
    source = Path(__file__).parent / "shim.cjs"
    destination = shim_path(workdir)
    destination.write_bytes(source.read_bytes())
    log = events_path(workdir)
    log.touch()
    return destination, log


def read_events(log: Path, start_line: int = 0) -> tuple[list[FileEvent], list[ProcessEvent], int]:
    """Parse events from `start_line`; return (file events, process events, next line)."""
    if not log.is_file():
        return [], [], start_line
    lines = log.read_text(errors="replace").splitlines()
    files: list[FileEvent] = []
    procs: list[ProcessEvent] = []
    for raw in lines[start_line:]:
        raw = raw.strip()
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            # A torn final line can happen if the process died mid-write. Skip
            # it rather than failing the run; the loss is bounded to one event.
            continue
        if payload.get("kind") == "fs":
            path = str(payload.get("path", ""))
            if path.startswith(_RUNTIME_NOISE_PREFIXES):
                continue
            files.append(FileEvent(op=str(payload.get("op", "")), path=path))
        elif payload.get("kind") == "proc":
            argv = tuple(str(a) for a in payload.get("argv", []))
            if argv:
                procs.append(ProcessEvent(op=str(payload.get("op", "")), argv=argv))
    return files, procs, len(lines)
