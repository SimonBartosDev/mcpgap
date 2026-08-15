"""Acceptance gate for install-script observation.

Install-time code is the attack class mcpgap was blind to for longest, and it
is not a hypothetical one: a `postinstall` that runs on every `npm install` is
how a large share of real npm supply-chain attacks execute.

The fixture (`tests/fixtures/hookserver`) is built so that only one thing
differs between the versions:

* `package.json` declares the identical hook command in both -- literally
  `node scripts/postinstall.js`.
* `index.js`, and therefore the entire declared tool surface, is byte-identical.
* Only the *contents* of `scripts/postinstall.js` change. v2 additionally posts
  to a collector host.

So a scanner that reads manifests sees nothing at all -- the declared install
surface is unchanged -- which is the same premise as the postmark gate, moved
to install time. The destination uses the reserved `.invalid` TLD, so the
fixture cannot reach a real host even if run unsandboxed.

`test_install_scripts_actually_ran` is the load-bearing guard: every
differential assertion below would pass against a scanner that never executed
the hooks at all, which is precisely the state this feature replaced.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from mcpgap.model import INSTALL_PREFIX, Verdict
from mcpgap.scan import diff_observations, scan_package_version

pytestmark = pytest.mark.sandbox

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "hookserver"
CLEAN = "v1"
RUGGED = "v2"
HOOK = "<root>:postinstall"
COLLECTOR = "collector.attacker.invalid"


@pytest.fixture(scope="module")
def scans(tmp_path_factory: pytest.TempPathFactory):
    work = tmp_path_factory.mktemp("mcpgap-hookserver")
    out = {}
    for version in (CLEAN, RUGGED):
        root = work / version / "package"
        shutil.copytree(FIXTURES / version, root)
        out[version] = scan_package_version(root, package="hookserver", version=version, runs=3)
    return out


@pytest.fixture(scope="module")
def report(scans):
    return diff_observations(scans[CLEAN], scans[RUGGED])


def test_install_scripts_actually_ran(scans) -> None:
    """The guard: prove the hooks were executed and observed.

    Before this feature, `--ignore-scripts` meant they never ran. A scanner in
    that state reports no install findings, and so does a working one against a
    package with no hooks. Assert positively that the hook was discovered and
    that running it left the trace we know it leaves.
    """
    for version, observation in scans.items():
        assert HOOK in observation.declared_scripts, (
            f"{version}: postinstall hook was not discovered in package.json"
        )
        assert HOOK in observation.install_observations, (
            f"{version}: postinstall was declared but never executed"
        )
        changes = observation.install_observations[HOOK].file_changes
        assert any("install-marker" in path for path in changes.created), (
            f"{version}: postinstall writes install-marker.txt, but no such file "
            f"was observed being created; got {changes.created}"
        )


def test_declared_install_surface_is_unchanged(report) -> None:
    """The premise: a manifest reader sees nothing.

    Both versions declare the byte-identical command. Only the script file it
    points at differs, which no amount of manifest analysis will reveal.
    """
    assert not report.scripts_added
    assert not report.scripts_removed
    assert not report.scripts_changed, (
        "the declared hook command is identical in both versions; a change here "
        "would mean the fixture no longer isolates behaviour from declaration"
    )
    assert not report.declared_schema_changed


def test_diff_surfaces_the_install_time_exfiltration_attempt(report) -> None:
    """The gate: v2's postinstall reaches for a host v1's never touched."""
    findings = report.install_findings()
    assert findings, "no install-script finding reported between v1 and v2"

    to_collector = [f for f in findings if COLLECTOR in f.host or COLLECTOR in str(f.value)]
    assert to_collector, (
        f"diff did not surface the install-time request to {COLLECTOR}; got "
        f"{[f.describe() for f in findings]}"
    )
    assert report.install_verdicts[HOOK] is Verdict.UNDECLARED_BEHAVIOUR


def test_install_finding_is_attributed_to_the_hook_not_a_tool(report) -> None:
    """Install findings must not be mistaken for tool findings.

    They are tagged with an `install:` prefix and kept in their own verdict map,
    so they cannot silently enter the denominator of a per-tool rate. A hook is
    not a tool, and a rate that quietly mixes them means something different
    from what its name says.
    """
    for finding in report.install_findings():
        assert finding.tool.startswith(INSTALL_PREFIX)
    assert HOOK not in report.verdicts
    assert not any(name.startswith(INSTALL_PREFIX) for name in report.concluded_tools)


def test_tools_are_not_implicated_by_the_install_change(report) -> None:
    """The server itself is byte-identical; only the hook changed."""
    assert all(v is not Verdict.UNDECLARED_BEHAVIOUR for v in report.verdicts.values())


def test_self_diff_reports_nothing(scans) -> None:
    report = diff_observations(scans[CLEAN], scans[CLEAN])
    assert not report.findings
    assert not report.scripts_changed


def test_install_observation_is_stable_across_runs(scans) -> None:
    for version, observation in scans.items():
        assert not observation.unstable_tools, (
            f"{version}: runs disagreed for {sorted(observation.unstable_tools)}"
        )
