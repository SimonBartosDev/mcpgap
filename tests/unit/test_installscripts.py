"""Hermetic tests for lifecycle-hook enumeration.

The regression these pin is the one that would do real damage: `prepare` means
different things depending on whose package.json it appears in. npm runs it for
the root package and for git dependencies, and does **not** run it for a
dependency installed from a registry tarball -- but the hook is still present in
the published manifest, so a single shared hook list happily finds and runs it.

That is not theoretical. Every one of the eight lifecycle hooks in
`postmark-mcp`'s 126-package dependency tree is a `prepare`: `axios` runs
`husky`, `path-to-regexp` runs `ts-scripts install && npm run build`,
`ip-address` reconfigures git hooks. None of them run on a normal install.
Running them would invoke tooling that is not present, produce a pile of
failures, and report as package behaviour a set of commands npm would never have
executed.

Same defect shape as reusing a heuristic list across two contexts where its
meaning inverts, which is a mistake this codebase's author has paid for before.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcpgap.installscripts import (
    DEPENDENCY_HOOKS,
    ROOT_HOOKS,
    declared_scripts,
    enumerate_install_scripts,
)


def _package(directory: Path, name: str, scripts: dict[str, str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "package.json").write_text(json.dumps({"name": name, "scripts": scripts}))


def test_prepare_runs_for_the_root_package(tmp_path: Path) -> None:
    _package(tmp_path, "root", {"prepare": "npm run build"})
    keys = [s.key for s in enumerate_install_scripts(tmp_path)]
    assert keys == ["<root>:prepare"]


def test_prepare_is_ignored_for_a_registry_dependency(tmp_path: Path) -> None:
    """The core regression. npm does not run a dependency's `prepare`."""
    _package(tmp_path, "root", {})
    _package(tmp_path / "node_modules" / "axios", "axios", {"prepare": "husky"})
    assert enumerate_install_scripts(tmp_path) == []


def test_dependency_install_hooks_are_found(tmp_path: Path) -> None:
    _package(tmp_path, "root", {})
    _package(
        tmp_path / "node_modules" / "evil",
        "evil",
        {"preinstall": "a", "install": "b", "postinstall": "c", "prepare": "ignored"},
    )
    keys = [s.key for s in enumerate_install_scripts(tmp_path)]
    assert keys == ["evil:install", "evil:postinstall", "evil:preinstall"]


def test_hook_lists_differ_and_prepare_is_the_difference() -> None:
    """Pins the asymmetry itself, so merging the two lists fails loudly."""
    assert "prepare" in ROOT_HOOKS
    assert "prepare" not in DEPENDENCY_HOOKS
    assert set(DEPENDENCY_HOOKS) < set(ROOT_HOOKS)


def test_scoped_packages_are_enumerated(tmp_path: Path) -> None:
    _package(tmp_path, "root", {})
    _package(
        tmp_path / "node_modules" / "@scope" / "pkg",
        "@scope/pkg",
        {"postinstall": "node setup.js"},
    )
    scripts = enumerate_install_scripts(tmp_path)
    assert [s.key for s in scripts] == ["@scope/pkg:postinstall"]
    assert scripts[0].relative_cwd == "node_modules/@scope/pkg"


def test_enumeration_order_is_stable(tmp_path: Path) -> None:
    """Comparing two versions requires a deterministic sequence."""
    _package(tmp_path, "root", {"postinstall": "x"})
    for name in ("zeta", "alpha", "mid"):
        _package(tmp_path / "node_modules" / name, name, {"postinstall": "y"})
    keys = [s.key for s in enumerate_install_scripts(tmp_path)]
    assert keys == [
        "<root>:postinstall",
        "alpha:postinstall",
        "mid:postinstall",
        "zeta:postinstall",
    ]


def test_blank_and_missing_commands_are_skipped(tmp_path: Path) -> None:
    _package(tmp_path, "root", {"postinstall": "   ", "install": ""})
    assert enumerate_install_scripts(tmp_path) == []


def test_unreadable_manifest_does_not_abort_enumeration(tmp_path: Path) -> None:
    """One broken dependency manifest must not hide every other hook."""
    _package(tmp_path, "root", {"postinstall": "ok"})
    broken = tmp_path / "node_modules" / "broken"
    broken.mkdir(parents=True)
    (broken / "package.json").write_text("{not json")
    assert [s.key for s in enumerate_install_scripts(tmp_path)] == ["<root>:postinstall"]


def test_declared_scripts_is_the_command_text(tmp_path: Path) -> None:
    """The declared install surface, comparable across versions like a schema."""
    _package(tmp_path, "root", {"postinstall": "node scripts/postinstall.js"})
    assert declared_scripts(tmp_path) == {"<root>:postinstall": "node scripts/postinstall.js"}


def test_no_node_modules_is_not_an_error(tmp_path: Path) -> None:
    _package(tmp_path, "root", {"postinstall": "x"})
    assert [s.key for s in enumerate_install_scripts(tmp_path)] == ["<root>:postinstall"]
