"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from mcpgap import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpgap",
        description="Observe what an MCP server does, and compare it to what it declares.",
    )
    parser.add_argument("--version", action="version", version=f"mcpgap {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv if argv is not None else sys.argv[1:])
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
