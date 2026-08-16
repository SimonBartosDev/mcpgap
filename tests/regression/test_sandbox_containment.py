"""Asserts the sandbox actually denies what SECURITY.md says it denies.

Every test here checks a *refusal*. That is the point: during development two
seatbelt rules silently failed to match their intended paths, and a rule that
does not match produces no error at all -- an `allow` that never fires shows up
as a permission problem, but a `deny` that never fires shows up as nothing,
and containment quietly disappears. Only a test that asserts the denial catches
that class of defect.

The shared tests run against whichever backend the host provides, so neither
can quietly become the weaker one. Backend-specific sections then pin the
things that genuinely differ:

* seatbelt -- `/tmp` is a symlink to `/private/tmp` and rules match resolved
  paths; `HOME` must be redirected or Node crashes reaching for the keychain.
* Landlock -- network is filtered by *port*, not address, and UDP is not
  governed at all. Those are real holes the macOS backend does not have, and
  they are asserted as present so that closing them later fails a test rather
  than passing unnoticed.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from mcpgap.sandbox import LandlockSandbox, SeatbeltSandbox, default_sandbox, landlock_abi
from mcpgap.sandbox.base import Sandbox

pytestmark = pytest.mark.sandbox

NODE = shutil.which("node")
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform == "linux"

# A host outside the sandbox, addressed by IP so no DNS is involved.
EXTERNAL_IP = "104.16.0.35"


@pytest.fixture(scope="module")
def sandbox() -> Sandbox:
    try:
        return default_sandbox()
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        pytest.fail(f"no sandbox backend available; containment is unverified, not untested: {exc}")


def run_js(
    sandbox: Sandbox,
    workdir: Path,
    script: str,
    *,
    allow_tcp_port: int | None = None,
) -> str:
    assert NODE, "node is required for sandbox containment tests"
    node = Path(NODE).resolve()
    env = sandbox.child_env(workdir)
    proc = sandbox.spawn(
        [str(node), "-e", script],
        cwd=workdir,
        env=env,
        workdir=workdir,
        allow_tcp_port=allow_tcp_port,
        read_paths=[node.parent.parent],
    )
    out, err = proc.communicate(timeout=60)
    return (out.decode() + err.decode()).strip()


# --------------------------------------------------------------------------
# Shared: both backends must satisfy these.
# --------------------------------------------------------------------------


def test_node_starts_at_all(sandbox: Sandbox, tmp_path: Path) -> None:
    """Sanity check, so a denial below cannot be an artefact of a dead process.

    Without this, every 'DENIED' assertion would also pass if Node simply never
    ran -- which is exactly how the first seatbelt profile failed.
    """
    assert "ALIVE" in run_js(sandbox, tmp_path, "console.log('ALIVE')")


@pytest.mark.parametrize("secret", [".ssh", ".aws", ".npmrc", ".config/gh"])
def test_cannot_read_credentials_in_the_real_home(
    sandbox: Sandbox, tmp_path: Path, secret: str
) -> None:
    target = Path.home() / secret
    script = (
        f"try{{require('fs').statSync({str(target)!r});console.log('LEAK')}}"
        "catch(e){console.log('DENIED')}"
    )
    assert "LEAK" not in run_js(sandbox, tmp_path, script)


def test_cannot_write_outside_the_workdir(sandbox: Sandbox, tmp_path: Path) -> None:
    target = Path.home() / ".mcpgap_containment_probe"
    script = (
        f"try{{require('fs').writeFileSync({str(target)!r},'x');console.log('LEAK')}}"
        "catch(e){console.log('DENIED')}"
    )
    assert "LEAK" not in run_js(sandbox, tmp_path, script)
    assert not target.exists(), "sandboxed process wrote outside its working directory"


def test_can_write_inside_the_workdir(sandbox: Sandbox, tmp_path: Path) -> None:
    """The allow rule must fire, not just the deny rules.

    A backend that denied everything would satisfy every refusal above while
    making the scanner useless.
    """
    script = (
        "const p=process.env.HOME+'/probe';require('fs').writeFileSync(p,'x');console.log('WROTE')"
    )
    assert "WROTE" in run_js(sandbox, tmp_path, script)


def test_cannot_reach_an_external_host_by_name(sandbox: Sandbox, tmp_path: Path) -> None:
    script = "require('dns').lookup('registry.npmjs.org',(e,a)=>console.log(e?'DENIED':'LEAK '+a))"
    assert "LEAK" not in run_js(sandbox, tmp_path, script)


def test_cannot_reach_an_external_host_by_raw_ip(sandbox: Sandbox, tmp_path: Path) -> None:
    """The rule that matters: DNS filtering alone would not stop this."""
    script = (
        f"require('net').connect(443,'{EXTERNAL_IP}')"
        ".on('error',()=>console.log('DENIED'))"
        ".on('connect',()=>console.log('LEAK'))"
    )
    assert "LEAK" not in run_js(sandbox, tmp_path, script)


def test_allowed_loopback_port_is_reachable(sandbox: Sandbox, tmp_path: Path) -> None:
    """The egress allowlist must permit exactly one destination -- and permit it."""
    import socket
    import threading

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve() -> None:
        try:
            conn, _ = server.accept()
            conn.sendall(b"hi")
            conn.close()
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    script = (
        f"require('net').connect({port},'127.0.0.1')"
        ".on('error',e=>console.log('BLOCKED',e.code))"
        ".on('connect',()=>console.log('REACHED'))"
    )
    try:
        assert "REACHED" in run_js(sandbox, tmp_path, script, allow_tcp_port=port)
    finally:
        server.close()


def test_environment_is_built_from_nothing(sandbox: Sandbox, tmp_path: Path) -> None:
    env = sandbox.child_env(tmp_path)
    assert set(env) == {"PATH", "HOME", "TMPDIR", "LANG"}
    assert Path(env["HOME"]) != Path.home()


def test_credential_shaped_variables_are_refused(sandbox: Sandbox, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="credential-shaped"):
        sandbox.child_env(tmp_path, {"AWS_SECRET_ACCESS_KEY": "x"})


# --------------------------------------------------------------------------
# seatbelt-specific
# --------------------------------------------------------------------------


@pytest.mark.skipif(not IS_MACOS, reason="seatbelt profile is macOS-only")
def test_profile_paths_are_symlink_resolved() -> None:
    """`/tmp/x` must appear as `/private/tmp/x`, or the rule matches nothing."""
    # S108: the literal /tmp path is the subject of the test, not a mistake.
    profile = SeatbeltSandbox().build_profile(workdir=Path("/tmp/mcpgap-probe"))  # noqa: S108
    assert '"/private/tmp/mcpgap-probe"' in profile
    assert '(subpath "/tmp/mcpgap-probe")' not in profile


@pytest.mark.skipif(not IS_MACOS, reason="seatbelt profile is macOS-only")
def test_user_data_deny_precedes_workdir_allow() -> None:
    """Seatbelt applies the last matching rule, so ordering is load-bearing."""
    workdir = Path.home() / "mcpgap-order-probe"
    profile = SeatbeltSandbox().build_profile(workdir=workdir)
    deny_at = profile.index('(deny file-read* (subpath "/Users"))')
    allow_at = profile.index(f'(allow file-read* (subpath "{workdir}"))')
    assert deny_at < allow_at


# --------------------------------------------------------------------------
# Landlock-specific, including its known holes
# --------------------------------------------------------------------------


@pytest.mark.skipif(not IS_LINUX, reason="Landlock is Linux-only")
def test_landlock_abi_is_sufficient() -> None:
    """Below ABI 4 there is no network restriction, and we refuse to run."""
    assert landlock_abi() >= 4, (
        f"Landlock ABI {landlock_abi()} cannot restrict network; the backend "
        "must refuse rather than run a package unconfined"
    )


@pytest.mark.skipif(not IS_LINUX, reason="Landlock is Linux-only")
def test_landlock_handles_every_fs_right_the_kernel_supports() -> None:
    """A right absent from `handled_access_fs` is one the child keeps entirely.

    Landlock denies only what the ruleset declares it handles, so under-declaring
    is silent: the sandbox looks configured and simply does not restrict that
    operation.
    """
    config = LandlockSandbox().build_config(workdir=Path("/tmp"))  # noqa: S108
    abi = landlock_abi()
    assert config["handled_fs"] & (1 << 13), "REFER unhandled (ABI 2)"
    if abi >= 3:
        assert config["handled_fs"] & (1 << 14), "TRUNCATE unhandled (ABI 3)"
    if abi >= 5:
        assert config["handled_fs"] & (1 << 15), "IOCTL_DEV unhandled (ABI 5)"


@pytest.mark.skipif(not IS_LINUX, reason="Landlock is Linux-only")
def test_known_hole_external_host_reachable_on_the_allowed_port(
    sandbox: Sandbox, tmp_path: Path
) -> None:
    """Documents a real weakness rather than pretending it is not there.

    Landlock filters outbound TCP by port, not by address, so the port we open
    for the recording proxy is open to every host -- and the child can read that
    port straight out of `HTTPS_PROXY`. Seatbelt does not have this hole because
    it filters by address.

    Asserting the weakness keeps it visible. If a future change closes it (a
    network namespace, once the hosts permit one), this test fails and forces
    the documentation to be updated with it.
    """
    script = (
        f"const s=require('net').connect(443,'{EXTERNAL_IP}');"
        "s.setTimeout(4000,()=>{console.log('TIMEOUT');s.destroy()});"
        "s.on('error',e=>console.log('BLOCKED',e.code));"
        "s.on('connect',()=>{console.log('REACHED');s.destroy()})"
    )
    result = run_js(sandbox, tmp_path, script, allow_tcp_port=443)
    assert "BLOCKED" not in result, (
        "Landlock appears to filter by address now, not just by port. That is "
        "strictly better -- update landlock.py and SECURITY.md, then delete this test."
    )


@pytest.mark.skipif(not IS_LINUX, reason="Landlock is Linux-only")
def test_known_hole_udp_is_not_restricted(sandbox: Sandbox, tmp_path: Path) -> None:
    """Landlock governs TCP only; UDP egress, DNS included, is not blocked.

    Asserted rather than hidden. `test_cannot_reach_an_external_host_by_name`
    passes on Linux because Node's resolver fails without a reachable DNS
    server, not because UDP was refused -- and those are different facts.
    """
    script = (
        "const s=require('dgram').createSocket('udp4');"
        "s.send(Buffer.from('x'),53,'1.1.1.1',e=>{console.log(e?'BLOCKED':'SENT');s.close()})"
    )
    result = run_js(sandbox, tmp_path, script)
    assert "BLOCKED" not in result, (
        "UDP appears restricted now. If that is deliberate, update landlock.py "
        "and SECURITY.md, then delete this test."
    )
