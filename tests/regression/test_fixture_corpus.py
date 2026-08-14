"""Pins the integrity of the vendored postmark-mcp fixtures.

This test exists so that a failure of the acceptance gate can be attributed.
If the gate fails while this passes, the scanner did not detect the rug pull.
If this fails too, the fixtures are the problem and the gate result says nothing
about detection either way. On a previous project a regression test was twice
written that would have passed against the buggy code; separating "the input was
present and correct" from "the code did the right thing" is how that is avoided.
"""

from __future__ import annotations

import hashlib

import pytest

from tests.support import corpus


@pytest.mark.parametrize("version", ["1.0.15", "1.0.16"])
def test_fixture_archive_is_present(version: str) -> None:
    assert corpus.available(version), (
        f"fixture for {version} is missing; run `python3 tools/build_fixtures.py`"
    )


@pytest.mark.parametrize("version", ["1.0.15", "1.0.16"])
def test_fixture_index_matches_pinned_hash(version: str) -> None:
    source = corpus.read_index(version).encode("utf-8")
    assert hashlib.sha256(source).hexdigest() == corpus.EXPECTED_INDEX_SHA256[version]


def test_the_only_source_difference_is_the_bcc_line() -> None:
    """The fixture pair must isolate the change under test.

    If the two versions differed in any other way, a passing gate would not
    prove the scanner found the BCC -- it might have found the other change.
    """
    old = corpus.read_index("1.0.15").splitlines()
    new = corpus.read_index("1.0.16").splitlines()

    import difflib

    changed = [
        line
        for line in difflib.unified_diff(old, new, lineterm="", n=0)
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]
    assert changed == [f"+        Bcc: '{corpus.ATTACKER_BCC}',"]


def test_clean_version_does_not_contain_the_attacker_address() -> None:
    assert corpus.ATTACKER_BCC not in corpus.read_index("1.0.15")


def test_malicious_version_declares_the_same_four_tools() -> None:
    """The rug pull changed behaviour without changing the declared surface.

    This is the premise of the whole gate: a declared-metadata scanner sees
    nothing here, because nothing it looks at changed.
    """
    expected = {"sendEmail", "sendEmailWithTemplate", "listTemplates", "getDeliveryStats"}
    for version in ("1.0.15", "1.0.16"):
        source = corpus.read_index(version)
        assert {name for name in expected if f'"{name}",' in source} == expected


def test_unpack_refuses_to_write_into_the_repository() -> None:
    with pytest.raises(corpus.FixtureError, match="refusing to unpack"):
        corpus.unpack("1.0.15", corpus.REPO_ROOT / "fixtures" / "scratch")


def test_unpack_verifies_hash_and_yields_a_runnable_tree(tmp_path) -> None:
    root = corpus.unpack("1.0.16", tmp_path / "v1.0.16")
    assert (root / "index.js").is_file()
    assert (root / "package.json").is_file()
    assert corpus.ATTACKER_BCC in (root / "index.js").read_text()
