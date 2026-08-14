"""Asserts the sandbox actually denies what SECURITY.md says it denies.

Every test here checks a *refusal*. That is the point: during development two
seatbelt rules silently failed to match their intended paths, and a rule that
does not match produces no error at all -- an `allow` that never fires shows up
as a permission problem, but a `deny` that never fires shows up as nothing,
and containment quietly disappears. Only a test that asserts the denial catches
that class of defect.

Specifically pinned:

* `/tmp` is a symlink to `/private/tmp`, and seatbelt matches resolved paths.
  A rule written against an unresolved path never fires.
* `HOME` must not point at the real home, or Node crashes reaching for the
  user's keychain once `/Users` is denied.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from mcpgap.sandbox import SeatbeltSandbox

pytestmark = pytest.mark.sandbox

NODE = shutil.which("node")


@pytest.fixture(scope="module")
def sandbox() -> SeatbeltSandbox:
    sb = SeatbeltSandbox()
    if not sb.available():
        pytest.fail("sandbox-exec is unavailable; containment is unverified, not merely untested")
    return sb


def run_js(
    sandbox: SeatbeltSandbox,
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


def test_node_starts_at_all(sandbox: SeatbeltSandbox, tmp_path: Path) -> None:
    """Sanity check, so a denial below cannot be an artefact of a dead process.

    Without this, every 'DENIED' assertion would also pass if Node simply never
    ran -- which is exactly how the first version of this profile failed.
    """
    assert "ALIVE" in run_js(sandbox, tmp_path, "console.log('ALIVE')")


@pytest.mark.parametrize("secret", [".ssh", ".aws", ".npmrc", ".config/gh"])
def test_cannot_read_credentials_in_the_real_home(
    sandbox: SeatbeltSandbox, tmp_path: Path, secret: str
) -> None:
    target = Path.home() / secret
    script = (
        f"try{{require('fs').statSync({str(target)!r});console.log('LEAK')}}"
        "catch(e){console.log('DENIED')}"
    )
    assert "LEAK" not in run_js(sandbox, tmp_path, script)


def test_cannot_write_outside_the_workdir(sandbox: SeatbeltSandbox, tmp_path: Path) -> None:
    target = Path.home() / ".mcpgap_containment_probe"
    script = (
        f"try{{require('fs').writeFileSync({str(target)!r},'x');console.log('LEAK')}}"
        "catch(e){console.log('DENIED')}"
    )
    assert "LEAK" not in run_js(sandbox, tmp_path, script)
    assert not target.exists(), "sandboxed process wrote outside its working directory"


def test_can_write_inside_the_workdir(sandbox: SeatbeltSandbox, tmp_path: Path) -> None:
    """The allow rule must fire, not just the deny rules.

    This is the `/tmp` -> `/private/tmp` footgun: an unresolved path in an allow
    rule silently never matches and the run fails for a reason that looks
    unrelated.
    """
    script = (
        "const p=process.env.HOME+'/probe';require('fs').writeFileSync(p,'x');console.log('WROTE')"
    )
    assert "WROTE" in run_js(sandbox, tmp_path, script)


def test_cannot_reach_an_external_host_by_name(sandbox: SeatbeltSandbox, tmp_path: Path) -> None:
    script = "require('dns').lookup('registry.npmjs.org',(e,a)=>console.log(e?'DENIED':'LEAK '+a))"
    assert "LEAK" not in run_js(sandbox, tmp_path, script)


def test_cannot_reach_an_external_host_by_raw_ip(sandbox: SeatbeltSandbox, tmp_path: Path) -> None:
    """The rule that matters: DNS filtering alone would not stop this."""
    script = (
        "require('net').connect(443,'104.16.0.35')"
        ".on('error',()=>console.log('DENIED'))"
        ".on('connect',()=>console.log('LEAK'))"
    )
    assert "LEAK" not in run_js(sandbox, tmp_path, script)


def test_allowed_loopback_port_is_reachable(sandbox: SeatbeltSandbox, tmp_path: Path) -> None:
    """The egress allowlist must permit exactly one destination -- and permit it.

    A profile that denied everything would pass every test above while making
    the scanner useless.
    """
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


def test_environment_is_built_from_nothing(sandbox: SeatbeltSandbox, tmp_path: Path) -> None:
    env = sandbox.child_env(tmp_path)
    assert set(env) == {"PATH", "HOME", "TMPDIR", "LANG"}
    assert Path(env["HOME"]) != Path.home()


def test_credential_shaped_variables_are_refused(sandbox: SeatbeltSandbox, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="credential-shaped"):
        sandbox.child_env(tmp_path, {"AWS_SECRET_ACCESS_KEY": "x"})


def test_profile_paths_are_symlink_resolved(sandbox: SeatbeltSandbox) -> None:
    """Pins the footgun directly, independent of any child process.

    `/tmp/x` must appear in the profile as `/private/tmp/x`; if it appears
    verbatim the rule will never match anything.
    """
    # S108: the literal /tmp path is the subject of the test, not a mistake --
    # this asserts it gets rewritten to its resolved form.
    profile = sandbox.build_profile(workdir=Path("/tmp/mcpgap-probe"))  # noqa: S108
    assert '"/private/tmp/mcpgap-probe"' in profile
    assert '(subpath "/tmp/mcpgap-probe")' not in profile


def test_user_data_deny_precedes_workdir_allow(sandbox: SeatbeltSandbox) -> None:
    """Seatbelt applies the last matching rule, so ordering is load-bearing.

    If the workdir allow were emitted before the `/Users` deny, a workdir inside
    a home directory would become unreadable and the scan would fail in a way
    that looks like a broken package rather than a broken profile.
    """
    workdir = Path.home() / "mcpgap-order-probe"
    profile = sandbox.build_profile(workdir=workdir)
    deny_at = profile.index('(deny file-read* (subpath "/Users"))')
    allow_at = profile.index(f'(allow file-read* (subpath "{workdir}"))')
    assert deny_at < allow_at
