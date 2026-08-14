"""Platform sandboxing for untrusted package code."""

from __future__ import annotations

import sys

from mcpgap.sandbox.base import Sandbox, SandboxUnavailable
from mcpgap.sandbox.seatbelt import SeatbeltSandbox

__all__ = ["Sandbox", "SandboxUnavailable", "SeatbeltSandbox", "default_sandbox"]


def default_sandbox() -> Sandbox:
    """Return the backend for this platform, or refuse.

    There is deliberately no "unconfined" backend to fall back to.
    """
    if sys.platform == "darwin":
        sandbox = SeatbeltSandbox()
        if sandbox.available():
            return sandbox
        raise SandboxUnavailable("macOS detected but sandbox-exec is missing.")
    raise SandboxUnavailable(
        f"no sandbox backend for platform {sys.platform!r}. "
        "Only macOS seatbelt is implemented; a Linux container backend is not built yet."
    )
