"""Sandbox interface.

Only the macOS seatbelt backend exists today. This interface is here so a Linux
container backend can be added without reshaping the caller, and so that
"there is no sandbox on this platform" is an explicit, loud condition rather
than a silent fallback to running malware unconfined.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Protocol


class SandboxUnavailable(RuntimeError):
    """Raised when no sandbox backend can confine this platform.

    Never caught to fall back to an unsandboxed run. We execute code from
    strangers on purpose; doing that unconfined is not a degraded mode, it is a
    different and unacceptable act.
    """


class Sandbox(Protocol):
    """Confines a child process: no ambient credentials, no network but ours."""

    def available(self) -> bool: ...

    def spawn(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        workdir: Path,
        allow_tcp_port: int | None = None,
    ) -> subprocess.Popen[bytes]:
        """Start `argv` confined.

        `workdir` is the only writable location. `allow_tcp_port` is the single
        loopback port the child may reach -- the recording proxy. Everything
        else is denied at the kernel, not by asking the child nicely.
        """
        ...
