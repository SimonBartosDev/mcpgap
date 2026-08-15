"""Enumerate and run npm lifecycle scripts under observation.

Install-time code is a major attack class and, until now, one mcpgap was
entirely blind to: dependencies were installed with `--ignore-scripts` and the
hooks were never executed at all. They are now executed, but only inside the
sandbox, with the sealed proxy as the sole egress and the preload shim
recording filesystem and subprocess activity.

## The hook list is context-dependent, and getting that wrong matters

npm runs a *different* set of hooks for the root package than for a dependency
installed from a registry tarball:

* Root package: `preinstall`, `install`, `postinstall`, and `prepare`.
* Registry dependency: `preinstall`, `install`, `postinstall`. **Not `prepare`.**

`prepare` is a development hook. It runs when you install from a git URL or pack
a tarball, not when a consumer installs the published package -- but it is still
present in the published `package.json`, so a naive enumeration finds it and
happily runs it.

That is not hypothetical. Every lifecycle hook in `postmark-mcp`'s 126-package
dependency tree is a `prepare`: `axios` runs `husky`, `path-to-regexp` runs
`ts-scripts install && npm run build`, `ip-address` reconfigures git hooks. None
of them run on a normal install. Executing them would invoke tooling that is not
installed, produce a pile of failures, and report as package behaviour a set of
commands npm would never have run.

Reusing one hook list across both contexts is the same defect shape as reusing a
heuristic list whose meaning inverts between contexts. Hence two lists.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

# What npm actually runs, per context. Do not merge these.
ROOT_HOOKS = ("preinstall", "install", "postinstall", "prepare")
DEPENDENCY_HOOKS = ("preinstall", "install", "postinstall")

ROOT_LABEL = "<root>"


@dataclass(frozen=True, slots=True)
class InstallScript:
    """One lifecycle hook declared by a package."""

    package: str
    hook: str
    command: str
    # Directory the hook runs in, relative to the staged package root.
    relative_cwd: str

    @property
    def key(self) -> str:
        return f"{self.package}:{self.hook}"

    @property
    def is_root(self) -> bool:
        return self.package == ROOT_LABEL


def _read_manifest(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def enumerate_install_scripts(package_root: Path) -> list[InstallScript]:
    """Find every lifecycle hook npm would actually run for this tree.

    Ordered root-first, then dependencies by name, so the sequence is stable
    across runs and across versions -- a prerequisite for comparing them.
    """
    scripts: list[InstallScript] = []

    root_manifest = _read_manifest(package_root / "package.json") or {}
    root_scripts = root_manifest.get("scripts") or {}
    for hook in ROOT_HOOKS:
        command = root_scripts.get(hook)
        if isinstance(command, str) and command.strip():
            scripts.append(
                InstallScript(package=ROOT_LABEL, hook=hook, command=command, relative_cwd=".")
            )

    modules = package_root / "node_modules"
    if not modules.is_dir():
        return scripts

    found: list[InstallScript] = []
    for manifest_path in modules.rglob("package.json"):
        directory = manifest_path.parent
        # Only a package's own manifest, not nested fixtures or test data.
        if directory.parent.name != "node_modules" and not directory.parent.name.startswith("@"):
            continue
        manifest = _read_manifest(manifest_path)
        if manifest is None:
            continue
        declared = manifest.get("scripts") or {}
        name = str(manifest.get("name") or directory.name)
        for hook in DEPENDENCY_HOOKS:
            command = declared.get(hook)
            if isinstance(command, str) and command.strip():
                found.append(
                    InstallScript(
                        package=name,
                        hook=hook,
                        command=command,
                        relative_cwd=str(directory.relative_to(package_root)),
                    )
                )
    scripts.extend(sorted(found, key=lambda s: (s.package, s.hook)))
    return scripts


def declared_scripts(package_root: Path) -> dict[str, str]:
    """The declared install surface: hook key -> command text.

    This is to install scripts what `tools/list` is to tools. Comparing it
    across versions catches a changed command; comparing observed behaviour
    catches a hook whose command is unchanged but whose script file is not --
    the install-time analogue of the postmark rug pull.
    """
    return {script.key: script.command for script in enumerate_install_scripts(package_root)}
