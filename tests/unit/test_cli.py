"""Smoke tests for the CLI entry point."""

from __future__ import annotations

import pytest

from mcpgap import __version__
from mcpgap.cli import build_parser, main


def test_version_flag_reports_package_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_parser_builds() -> None:
    assert build_parser().prog == "mcpgap"
