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

# Environment variables that must never reach the child. `build_child_env`
# starts from nothing, so this is belt-and-braces for callers passing their own.
FORBIDDEN_ENV_PREFIXES = ("AWS_", "GITHUB_", "GH_", "NPM_", "OPENAI_", "ANTHROPIC_")


def build_child_env(workdir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build the child's environment from nothing.

    Started empty rather than filtered from `os.environ`, so a credential we
    never thought of cannot be inherited. `HOME` and `TMPDIR` point into the
    working directory: on macOS a child whose HOME is unreadable crashes
    reaching for the user's keychain, and on any platform the code under test
    has no business seeing the real home.

    Platform-independent, so both backends share it and cannot drift apart.
    """
    home = workdir / "home"
    home.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": "C",
    }
    for key, value in (extra or {}).items():
        if key.startswith(FORBIDDEN_ENV_PREFIXES):
            raise ValueError(f"refusing to pass credential-shaped variable {key!r} to sandbox")
        env[key] = value
    return env


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
