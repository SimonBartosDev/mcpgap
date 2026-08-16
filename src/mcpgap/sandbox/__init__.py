"""Platform sandboxing for untrusted package code.

Two backends, with deliberately different strengths. Both refuse to run rather
than degrade: there is no unconfined mode to fall back to.

* macOS: seatbelt. Filters network by *address*, so egress can be pinned to the
  recording proxy on loopback and nothing else.
* Linux: Landlock. Filters network by *port*, and does not govern UDP at all.
  Strictly weaker, documented in `landlock.py` and pinned by tests.

`tests/regression/test_sandbox_containment.py` runs the same denial assertions
against whichever backend the host provides, so neither can quietly become the
weaker one without a test noticing.
"""

from __future__ import annotations

import sys

from mcpgap.sandbox.base import Sandbox, SandboxUnavailable
from mcpgap.sandbox.landlock import LandlockSandbox, landlock_abi
from mcpgap.sandbox.seatbelt import SeatbeltSandbox

__all__ = [
    "LandlockSandbox",
    "Sandbox",
    "SandboxUnavailable",
    "SeatbeltSandbox",
    "default_sandbox",
    "landlock_abi",
]


def default_sandbox() -> Sandbox:
    """Return the backend for this platform, or refuse.

    There is deliberately no "unconfined" backend. Running code from strangers
    without confinement is not a degraded mode, it is a different act.
    """
    if sys.platform == "darwin":
        sandbox = SeatbeltSandbox()
        if sandbox.available():
            return sandbox
        raise SandboxUnavailable("macOS detected but sandbox-exec is missing.")
    if sys.platform == "linux":
        landlock = LandlockSandbox()
        if landlock.available():
            return landlock
        raise SandboxUnavailable(
            f"Linux detected but Landlock ABI is {landlock_abi()}; version 4 or later is "
            "required for network restriction. Namespace-based sandboxes are not used "
            "because unprivileged user namespaces are restricted on the hosts this "
            "targets -- see src/mcpgap/sandbox/landlock.py."
        )
    raise SandboxUnavailable(
        f"no sandbox backend for platform {sys.platform!r}; only macOS and Linux are implemented."
    )
