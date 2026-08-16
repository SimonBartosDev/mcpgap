"""macOS seatbelt (`sandbox-exec`) backend.

## What this profile actually does

Reads of *system* paths are allowed. The entire `/Users` tree -- every user's
home directory -- is denied in a single rule, then the run's own working
directory and the interpreter prefix are allowed back. Writes are confined to
the working directory. Network is denied except one loopback port.

That is deliberately not the "default-deny reads with a narrow allowlist" this
was first designed as. Node aborts on startup without broad system reads, and
the abort is silent -- no stderr, no sandbox log entry -- so the minimal read
set could not be determined empirically. Rather than claim a tighter posture
than is implemented, the profile denies the whole user namespace in one rule.
That is robust in the way that matters: a credential location invented next year
under `$HOME` is covered automatically, whereas an enumerated denylist of
`~/.ssh`, `~/.aws`, `~/.npmrc` would silently miss it.

The exposure this leaves is read access to system files, which are world-
readable anyway, and to any user data stored outside `/Users` -- an external
volume, for instance. SECURITY.md states this rather than glossing it.

## Two footguns found while building this

1. **Paths must be resolved.** `/tmp` is a symlink to `/private/tmp` and
   seatbelt matches the resolved path, so a rule written against `/tmp/...`
   never fires. For an `allow` rule that surfaces as an immediate permission
   error. For a `deny` rule it surfaces as nothing at all -- containment simply
   evaporates, with no diagnostic. Every path here goes through `realpath`.

2. **`HOME` must be redirected.** With `/Users` denied but `HOME` still pointing
   at the real home, Node crashes with `SecItemCopyMatching failed -67674`: it
   asks the Security framework for the user's keychain, which it can no longer
   read. Pointing `HOME` and `TMPDIR` into the working directory fixes that and
   is correct hygiene regardless -- the child should never see the real home.

Rule order matters: seatbelt applies the **last** matching rule, so the
`/Users` deny is written before the workdir allow that re-permits it.

`tests/regression/test_sandbox_containment.py` asserts each denial actually
denies. A containment rule with no test asserting refusal is not containment.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from mcpgap.sandbox.base import SandboxUnavailable, build_child_env

# Trees that hold user data. Denied wholesale rather than enumerated by
# credential filename, so new secrets are covered without a code change.
_USER_DATA_TREES = ("/Users", "/Volumes")


def _resolve(path: str | Path) -> str:
    """Resolve symlinks. See footgun 1 in the module docstring."""
    return str(Path(path).resolve())


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


class SeatbeltSandbox:
    """Confines a child with `sandbox-exec`."""

    def available(self) -> bool:
        return shutil.which("sandbox-exec") is not None

    def build_profile(
        self,
        *,
        workdir: Path,
        read_paths: list[Path] | None = None,
        allow_tcp_port: int | None = None,
    ) -> str:
        workdir_resolved = _resolve(workdir)
        lines = [
            "(version 1)",
            "(deny default)",
            "",
            ";; The package may spawn helpers; we want to observe that rather",
            ";; than make it impossible.",
            "(allow process* signal sysctl* mach* ipc* file-ioctl)",
            "",
            ";; System reads are permitted; see the module docstring for why",
            ";; this is not a narrow allowlist.",
            "(allow file-read*)",
            "",
            ";; ...but the whole user namespace is denied. One rule, so new",
            ";; credential locations are covered without editing a list.",
        ]
        lines += [f'(deny file-read* (subpath "{_quote(_resolve(t))}"))' for t in _USER_DATA_TREES]

        lines += [
            "",
            ";; Re-permit only what this run needs. Seatbelt applies the LAST",
            ";; matching rule, so these must come after the deny above.",
            f'(allow file-read* (subpath "{_quote(workdir_resolved)}"))',
        ]
        for path in read_paths or []:
            lines.append(f'(allow file-read* (subpath "{_quote(_resolve(path))}"))')

        lines += [
            "",
            ";; Writes: this run's working directory only.",
            f'(allow file-write* (subpath "{_quote(workdir_resolved)}"))',
            '(allow file-write-data (literal "/dev/null"))',
            "",
            ";; Network: nothing but the recording proxy on loopback. With no",
            ";; port allowed this denies all egress, including by raw IP.",
        ]
        if allow_tcp_port is not None:
            lines.append(f'(allow network-outbound (remote ip "localhost:{allow_tcp_port}"))')
        return "\n".join(lines) + "\n"

    def child_env(self, workdir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Shared with the Landlock backend; see `base.build_child_env`."""
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
                "sandbox-exec not found. mcpgap will not run untrusted package "
                "code unconfined; there is no fallback by design."
            )
        profile = self.build_profile(
            workdir=workdir,
            read_paths=read_paths,
            allow_tcp_port=allow_tcp_port,
        )
        profile_path = workdir / "sandbox.sb"
        profile_path.write_text(profile)

        return subprocess.Popen(  # noqa: S603
            ["sandbox-exec", "-f", str(profile_path), *argv],
            cwd=str(cwd),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
