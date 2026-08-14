"""THE ACCEPTANCE GATE.

Pins the one publicly documented malicious MCP server: `postmark-mcp` v1.0.16
(OSV MAL-2025-47604, disclosed 2025-09-25 by Koi Security), which added

    Bcc: 'phan@giftshop.club',

to the `sendEmail` tool and BCC'd every outgoing email to the author.

If this file does not pass, the project does not ship. Everything else in the
repository is scaffolding around making it pass.

The single most important test here is not the one that finds the BCC. It is
`test_host_level_view_is_blind_to_the_change`. The added BCC opens no new
connection -- same host, same endpoint, same request count -- so every scanner
that watches hosts, DNS or connection counts is structurally incapable of
seeing it. That test asserts our own host-level view stays silent while the
body-level diff speaks, and it would fail loudly if anyone later "optimised"
detection down to destination matching.
"""

from __future__ import annotations

import pytest

from mcpgap.model import Attribution, Verdict
from mcpgap.scan import diff_observations, scan_package_version
from tests.support import corpus

pytestmark = pytest.mark.sandbox

PACKAGE = "postmark-mcp"
CLEAN = "1.0.15"
MALICIOUS = "1.0.16"
POSTMARK_HOST = "api.postmarkapp.com"


@pytest.fixture(scope="module")
def scans(tmp_path_factory: pytest.TempPathFactory):
    """Observe both versions under identical inputs.

    Fixture errors propagate as FixtureError, never as assertion failures, so a
    missing or corrupt fixture can never be mistaken for a detection failure.
    """
    work = tmp_path_factory.mktemp("mcpgap-gate")
    out = {}
    for version in (CLEAN, MALICIOUS):
        root = corpus.unpack(version, work / version)
        out[version] = scan_package_version(root, package=PACKAGE, version=version, runs=3)
    return out


@pytest.fixture(scope="module")
def report(scans):
    return diff_observations(scans[CLEAN], scans[MALICIOUS])


def test_send_email_was_actually_exercised(scans) -> None:
    """Guard against the whole suite passing vacuously on empty observations.

    Without this, a scanner that silently observed nothing would satisfy every
    negative control below and look green. A tool we did not exercise is
    CANNOT_CONCLUDE, and that must never be dressed up as a pass.
    """
    for version, observation in scans.items():
        assert "sendEmail" in observation.declared_tools, (
            f"v{version}: sendEmail was never even discovered via tools/list"
        )
        assert "sendEmail" not in observation.not_exercised, (
            f"v{version}: sendEmail was discovered but never successfully called"
        )
        assert observation.observations["sendEmail"].requests, (
            f"v{version}: sendEmail ran but produced no outbound request to observe"
        )


def test_diff_surfaces_the_added_bcc(report) -> None:
    """The gate proper: the added BCC destination must appear in the diff."""
    findings = report.findings_for("sendEmail")
    assert findings, "no finding reported for sendEmail between v1.0.15 and v1.0.16"

    bcc = [f for f in findings if f.value == corpus.ATTACKER_BCC]
    assert bcc, (
        f"diff did not surface the added BCC address {corpus.ATTACKER_BCC!r}; "
        f"got {[f.describe() for f in findings]}"
    )

    finding = bcc[0]
    assert finding.host == POSTMARK_HOST
    assert finding.pointer.lower().endswith("bcc")
    assert finding.attribution is Attribution.UNATTRIBUTED, (
        "the BCC address came from neither our inputs nor the declared config, "
        "so it must be reported as unattributed"
    )
    assert finding.evidence.body, "a finding must carry the raw request as evidence"
    assert report.verdicts["sendEmail"] is Verdict.UNDECLARED_BEHAVIOUR


def test_host_level_view_is_blind_to_the_change(report) -> None:
    """The differentiator, asserted as a negative.

    Every existing MCP scanner analyses declared metadata or destinations. This
    rug pull changes neither. If this test ever fails, either the fixture has
    drifted or someone has reduced detection to host matching -- in which case
    the tool no longer catches the case it was built for.
    """
    assert not report.destinations_added, (
        f"expected no new destination, got {sorted(report.destinations_added)}"
    )
    assert not report.destinations_removed
    assert not report.declared_added
    assert not report.declared_removed
    assert not report.declared_schema_changed, (
        "the declared tool surface is byte-identical between these versions; "
        "a declared-metadata scanner sees nothing here"
    )


def test_clean_sibling_tool_is_not_implicated(report) -> None:
    """`sendEmailWithTemplate` is genuinely clean in v1.0.16.

    The attacker backdoored `sendEmail` only, so template-sent mail was never
    exfiltrated. A differ that smeared one tool's finding across the package
    would flag this too, and that would be an accusation we cannot evidence.
    """
    assert not report.findings_for("sendEmailWithTemplate")
    assert report.verdicts["sendEmailWithTemplate"] is Verdict.CONSISTENT


def test_caller_supplied_destination_is_not_flagged(report) -> None:
    """Attribution control.

    `sendEmail` accepts `attachmentUrls` and fetches whatever the caller passes,
    in both versions. Because that destination is attributable to our own nonce
    input, it is not undeclared behaviour and must not be reported. This is the
    false-positive the nonce-tagging scheme exists to prevent.
    """
    spurious = [
        f
        for f in report.findings
        if f.attribution is Attribution.UNATTRIBUTED and f.host != POSTMARK_HOST
    ]
    assert not spurious, (
        f"flagged caller-directed egress as undeclared: {[f.describe() for f in spurious]}"
    )


def test_self_diff_reports_nothing(scans) -> None:
    """Diffing a version against itself must be silent.

    This catches a differ that manufactures findings from identical input --
    unstable pointer generation, or matching requests in a way that pairs them
    wrongly. It does **not** catch run-to-run nondeterminism, because both sides
    are the same observation object; that is covered separately by
    `test_no_tool_was_unstable_across_runs` below, which compares the three real
    runs against each other.
    """
    report = diff_observations(scans[CLEAN], scans[CLEAN])
    assert not report.findings
    assert not report.destinations_added
    assert all(v is not Verdict.UNDECLARED_BEHAVIOUR for v in report.verdicts.values())


def test_no_tool_was_unstable_across_runs(scans) -> None:
    """One observation is not a measurement.

    Each version is run three times and the runs must agree. A tool whose runs
    disagreed would be UNSTABLE, and a verdict derived from a single arbitrary
    run would be exactly the coin-flip this project's rules exist to prevent.
    """
    for version, observation in scans.items():
        assert observation.runs == 3
        assert not observation.unstable_tools, (
            f"v{version}: runs disagreed for {sorted(observation.unstable_tools)}; "
            "no verdict should be issued from disagreeing runs"
        )
