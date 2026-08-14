"""Scan orchestration: install, run, observe, diff."""

from __future__ import annotations

from pathlib import Path

from mcpgap.diff import diff_versions
from mcpgap.model import DiffReport, VersionObservation
from mcpgap.observe import declared_config, observe_version
from mcpgap.probes import DEFAULT_SEED


def scan_package_version(
    package_root: Path,
    *,
    package: str,
    version: str,
    runs: int = 3,
    workdir: Path | None = None,
    seed: str = DEFAULT_SEED,
    env: dict[str, str] | None = None,
) -> VersionObservation:
    """Install and run one version, calling each declared tool `runs` times.

    `runs` defaults to 3 because one observation is not a measurement: tools
    whose runs disagree are reported UNSTABLE rather than resolved by picking
    whichever run we happened to see first.
    """
    work = workdir or package_root.parent / "_mcpgap_work"
    work.mkdir(parents=True, exist_ok=True)

    observation, arguments = observe_version(
        package_root,
        package=package,
        version=version,
        workdir=work,
        runs=runs,
        seed=seed,
    )
    config = dict(declared_config(package_root, seed))
    config.update(env or {})
    return VersionObservation(
        package=observation.package,
        version=observation.version,
        declared_tools=observation.declared_tools,
        observations=observation.observations,
        runs=observation.runs,
        unstable_tools=observation.unstable_tools,
        probe_arguments=arguments,
        config_values=config,
    )


def diff_observations(old: VersionObservation, new: VersionObservation) -> DiffReport:
    """Compare two versions observed under identical inputs."""
    return diff_versions(
        old,
        new,
        caller_arguments=new.probe_arguments or old.probe_arguments,
        config_values=new.config_values or old.config_values,
    )
