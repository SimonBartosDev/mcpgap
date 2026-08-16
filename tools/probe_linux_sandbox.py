#!/usr/bin/env python3
"""Report what sandboxing primitives this Linux host actually offers.

Written because the seatbelt backend was built by probing rather than guessing,
and the Linux backend should be built the same way. Two of the three seatbelt
footguns found during that work were things no amount of reading documentation
would have surfaced -- they only appeared when a rule silently failed to match.

Prints facts, exits 0 regardless. This is a measurement, not a test.
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# Landlock syscall numbers on x86_64 / aarch64. Landlock is the promising
# primitive here: unprivileged, no namespaces required, and from ABI 4 it can
# restrict outbound TCP.
_SYS_LANDLOCK_CREATE_RULESET = {"x86_64": 444, "aarch64": 444}


def header(title: str) -> None:
    print(f"\n=== {title} ===")


def run(cmd: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, f"{type(exc).__name__}: {exc}"


def read(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except OSError as exc:
        return f"<unreadable: {exc.__class__.__name__}>"


def main() -> int:
    header("host")
    print(f"platform : {platform.platform()}")
    print(f"machine  : {platform.machine()}")
    print(f"kernel   : {platform.release()}")
    print(f"python   : {sys.version.split()[0]}")
    print(f"euid     : {os.geteuid()}")

    header("distro")
    print(read("/etc/os-release")[:400])

    header("namespace policy")
    for knob in (
        "/proc/sys/kernel/unprivileged_userns_clone",
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
        "/proc/sys/user/max_user_namespaces",
    ):
        print(f"{knob} = {read(knob)}")

    header("tools on PATH")
    for tool in ("bwrap", "unshare", "nsenter", "ip", "setpriv", "firejail", "landlock-restrict"):
        print(f"{tool:18} {shutil.which(tool) or 'MISSING'}")

    header("unshare: user + net namespace (no root)")
    code, out = run(["unshare", "--user", "--net", "--map-root-user", "true"])
    print(f"unshare -Urn true -> rc={code} {out[:200]}")
    code, out = run(["unshare", "--user", "--map-root-user", "true"])
    print(f"unshare -Ur  true -> rc={code} {out[:200]}")

    header("bubblewrap")
    if shutil.which("bwrap"):
        code, out = run(["bwrap", "--version"])
        print(f"version -> rc={code} {out[:120]}")
        code, out = run(["bwrap", "--ro-bind", "/", "/", "--unshare-net", "true"])
        print(f"--unshare-net -> rc={code} {out[:200]}")
        code, out = run(["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "true"])
        print(f"--dev         -> rc={code} {out[:200]}")
    else:
        print("bwrap absent; checking whether apt could install it")
        code, out = run(["apt-cache", "policy", "bubblewrap"], timeout=30)
        print(f"apt-cache policy -> rc={code}\n{out[:300]}")

    header("LSMs")
    print(f"/sys/kernel/security/lsm = {read('/sys/kernel/security/lsm')}")

    header("landlock ABI")
    syscall_no = _SYS_LANDLOCK_CREATE_RULESET.get(platform.machine())
    if syscall_no is None:
        print(f"no known syscall number for {platform.machine()}")
    else:
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION=1)
            abi = libc.syscall(syscall_no, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
            if abi < 0:
                print(f"landlock unavailable (errno {ctypes.get_errno()})")
            else:
                print(f"landlock ABI version = {abi}")
                print("  ABI >= 1: filesystem restriction")
                print("  ABI >= 4: LANDLOCK_ACCESS_NET_CONNECT_TCP (outbound TCP by port)")
        except OSError as exc:
            print(f"could not load libc: {exc}")

    header("seccomp")
    print(f"CONFIG via /proc/self/status Seccomp = {[
        line for line in read('/proc/self/status').splitlines() if line.startswith('Seccomp')
    ]}")

    header("node")
    code, out = run(["node", "--version"])
    print(f"node -> rc={code} {out[:80]}")
    print(f"node path: {shutil.which('node')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
