"""Linux sandbox backend built on Landlock.

## Why Landlock and not bubblewrap

Bubblewrap is the conventional answer and it does not work here. Measured on the
Ubuntu 24.04 runners this project targets (`tools/probe_linux_sandbox.py`):

    apparmor_restrict_unprivileged_userns = 1
    unshare -Ur  -> uid_map: Operation not permitted
    unshare -Urn -> uid_map: Operation not permitted
    bwrap --unshare-net -> loopback: Failed RTM_NEWADDR: Operation not permitted
    bwrap --dev         -> setting up uid map: Permission denied

Unprivileged user namespaces are restricted by AppArmor, so every
namespace-based sandbox is unavailable without root. Landlock needs no
namespaces and no privileges, and the same host reports ABI 7.

## How the restriction is applied

A short helper process, spawned with the running interpreter, applies
`PR_SET_NO_NEW_PRIVS`, builds the ruleset, calls `landlock_restrict_self`, then
`execv`s the real command. Landlock is inherited across exec, so the target runs
restricted.

The restriction is deliberately *not* applied in `subprocess`'s `preexec_fn`.
That callback runs after `fork()` in a process that holds the proxy's threads,
and doing ctypes work there risks deadlocking on a lock held by another thread
at the moment of the fork. The helper is a fresh, single-threaded interpreter.

## Where this is weaker than the macOS backend, and why

Landlock's network support restricts TCP **by port**, not by address. We allow
exactly one port -- the recording proxy's -- so a connection to any other port
is refused. But a connection to *that* port on an external host is permitted,
and the port is discoverable from `HTTPS_PROXY` in the child's own environment.

Landlock also does not govern UDP at all, so UDP-based exfiltration, DNS
included, is not blocked.

Neither hole exists under seatbelt, which filters by address. Both are pinned by
tests in `tests/regression/test_sandbox_containment.py` that assert the current
behaviour, so the gap stays visible and closing it later fails a test rather
than passing silently. Closing them properly needs a network namespace, which
these hosts do not permit.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from mcpgap.sandbox.base import SandboxUnavailable, build_child_env

# Landlock filesystem access rights, by the ABI version that introduced them.
# Everything in `handled_access_fs` is denied unless a rule permits it, so the
# set must be as wide as the kernel supports -- a right we fail to handle is a
# right the sandboxed process keeps unconditionally.
_FS_RIGHTS_BY_ABI: tuple[tuple[int, int], ...] = (
    (1, (1 << 13) - 1),  # execute..make_sym
    (2, 1 << 13),  # refer
    (3, 1 << 14),  # truncate
    (5, 1 << 15),  # ioctl_dev
)

_ACCESS_NET_CONNECT_TCP = 1 << 1

# Rights that mean something only for a directory. Landlock rejects a rule that
# grants any of these on a regular file or device node with EINVAL -- which is
# how `/dev/null` broke the first Linux run, since a plain "read" set that
# includes READ_DIR is invalid on a character device. Every rule is masked by
# whether its target is a directory.
_DIRECTORY_ONLY_RIGHTS = (
    (1 << 3)  # read_dir
    | (1 << 4)  # remove_dir
    | (1 << 5)  # remove_file
    | (1 << 6)  # make_char
    | (1 << 7)  # make_dir
    | (1 << 8)  # make_reg
    | (1 << 9)  # make_sock
    | (1 << 10)  # make_fifo
    | (1 << 11)  # make_block
    | (1 << 12)  # make_sym
    | (1 << 13)  # refer
)

# Directories a Node runtime needs to read, outside any per-run directory.
_SYSTEM_READ_DIRS = (
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc",
    "/opt",
    "/proc",
    "/sys/kernel/mm/transparent_hugepage",
)

# Device nodes the runtime uses. Writable, because a process that cannot write
# to /dev/null behaves in ways that have nothing to do with the package.
_SYSTEM_DEV_FILES = (
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
    "/dev/tty",
    "/dev/full",
)

# The helper runs in a fresh interpreter with no access to this package, so it
# is passed as source rather than imported. Keep it stdlib-only.
_HELPER = r"""
import ctypes, json, os, sys

SYS_CREATE, SYS_ADD_RULE, SYS_RESTRICT = 444, 445, 446
PR_SET_NO_NEW_PRIVS = 38
RULE_PATH_BENEATH, RULE_NET_PORT = 1, 2

cfg = json.loads(sys.argv[1])
argv = sys.argv[2:]

libc = ctypes.CDLL("libc.so.6", use_errno=True)


class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64),
                ("handled_access_net", ctypes.c_uint64)]


class PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class NetPortAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("port", ctypes.c_uint64)]


def die(message):
    sys.stderr.write("mcpgap-landlock: " + message + "\n")
    raise SystemExit(127)


if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
    die("PR_SET_NO_NEW_PRIVS failed errno=%d" % ctypes.get_errno())

attr = RulesetAttr(handled_access_fs=cfg["handled_fs"], handled_access_net=cfg["handled_net"])
fd = libc.syscall(SYS_CREATE, ctypes.byref(attr), ctypes.sizeof(attr), 0)
if fd < 0:
    die("landlock_create_ruleset failed errno=%d" % ctypes.get_errno())

for path, access in cfg["paths"]:
    try:
        parent = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        continue  # a path that does not exist cannot be granted; not an error
    rule = PathBeneathAttr(allowed_access=access & cfg["handled_fs"], parent_fd=parent)
    if libc.syscall(SYS_ADD_RULE, fd, RULE_PATH_BENEATH, ctypes.byref(rule), 0) < 0:
        die("landlock_add_rule(path=%s) failed errno=%d" % (path, ctypes.get_errno()))
    os.close(parent)

for port in cfg["ports"]:
    rule = NetPortAttr(allowed_access=cfg["handled_net"], port=port)
    if libc.syscall(SYS_ADD_RULE, fd, RULE_NET_PORT, ctypes.byref(rule), 0) < 0:
        die("landlock_add_rule(port=%d) failed errno=%d" % (port, ctypes.get_errno()))

if libc.syscall(SYS_RESTRICT, fd, 0) != 0:
    die("landlock_restrict_self failed errno=%d" % ctypes.get_errno())
os.close(fd)

try:
    os.execv(argv[0], argv)
except OSError as exc:
    die("exec %s failed: %s" % (argv[0], exc))
"""


def landlock_abi() -> int:
    """Return the kernel's Landlock ABI version, or 0 if unavailable."""
    if sys.platform != "linux":
        return 0
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
        abi = libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
    except OSError:
        return 0
    return abi if abi > 0 else 0


def _handled_fs(abi: int) -> int:
    handled = 0
    for since, bits in _FS_RIGHTS_BY_ABI:
        if abi >= since:
            handled |= bits
    return handled


def _resolve(path: str | Path) -> str:
    return str(Path(path).resolve())


class LandlockSandbox:
    """Confines a child with Landlock. No root, no namespaces."""

    # Access sets, expressed as "everything handled" filtered per rule.
    READ_ONLY = (1 << 0) | (1 << 2) | (1 << 3)  # execute, read_file, read_dir
    READ_WRITE = (1 << 16) - 1  # every right; masked to handled at rule time

    def available(self) -> bool:
        # ABI 4 introduced network restriction. Below that we could confine the
        # filesystem but not egress, and a sandbox that cannot stop the package
        # phoning home is not one this tool should silently accept.
        return landlock_abi() >= 4

    def build_config(
        self,
        *,
        workdir: Path,
        read_paths: list[Path] | None = None,
        allow_tcp_port: int | None = None,
    ) -> dict:
        abi = landlock_abi()
        handled_fs = _handled_fs(abi)
        paths: list[tuple[str, int]] = []

        def grant(path: str | Path, access: int) -> None:
            target = Path(path)
            if not target.exists():
                return
            # Directory-only rights on a file are rejected outright, so mask
            # them off rather than letting one device node abort the ruleset.
            if not target.is_dir():
                access &= ~_DIRECTORY_ONLY_RIGHTS
            paths.append((_resolve(target), access))

        for directory in _SYSTEM_READ_DIRS:
            grant(directory, self.READ_ONLY)
        for device in _SYSTEM_DEV_FILES:
            grant(device, self.READ_WRITE)
        for extra in read_paths or []:
            grant(extra, self.READ_ONLY)
        # The run directory is the only writable location, mirroring seatbelt.
        grant(workdir, self.READ_WRITE)
        return {
            "handled_fs": handled_fs,
            "handled_net": _ACCESS_NET_CONNECT_TCP,
            "paths": paths,
            "ports": [allow_tcp_port] if allow_tcp_port is not None else [],
        }

    def child_env(self, workdir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Shared with the seatbelt backend; see `base.build_child_env`."""
        return build_child_env(workdir, extra)

    def spawn(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        workdir: Path,
        allow_tcp_port: int | None = None,
        read_paths: list[Path] | None = None,
    ) -> subprocess.Popen[bytes]:
        if not self.available():
            raise SandboxUnavailable(
                f"Landlock ABI {landlock_abi()} is insufficient (need >= 4 for network "
                "restriction). mcpgap will not run untrusted package code unconfined; "
                "there is no fallback by design."
            )
        config = self.build_config(
            workdir=workdir, read_paths=read_paths, allow_tcp_port=allow_tcp_port
        )
        # The interpreter must stay readable for the helper to start; it lives
        # under a system path already granted read+execute.
        return subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", _HELPER, json.dumps(config), *argv],
            cwd=str(cwd),
            env=dict(env, PATH=env.get("PATH", os.defpath)),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
