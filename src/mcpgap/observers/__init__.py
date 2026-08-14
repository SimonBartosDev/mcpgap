"""Observation layers beyond the network.

Two mechanisms with deliberately different strengths:

* `filesystem` snapshots the sandbox's writable tree. Complete for writes,
  because the sandbox confines writes to that tree and nothing the package does
  can opt out.
* `events` reads the preload shim's log, covering reads and subprocess spawns.
  Best-effort: the package can unhook it.

They are not merged. A guarantee and an attempt should not be reported as the
same kind of fact.
"""

from mcpgap.observers.events import install_shim, read_events
from mcpgap.observers.filesystem import diff_snapshots, snapshot

__all__ = ["diff_snapshots", "install_shim", "read_events", "snapshot"]
