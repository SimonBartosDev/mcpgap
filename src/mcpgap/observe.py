"""Install a package version, run it under the sandbox, and record what it does.

Install and run are separate phases with different privileges:

* **Install** happens *outside* the sandbox, with network, using
  `npm install --ignore-scripts`. `--ignore-scripts` stops lifecycle scripts
  executing -- but it is not a sandbox, and it means install-time behaviour is
  a class of attack we do not observe at all. The README says so plainly.
* **Run** happens inside the sandbox with no network but the recording proxy.

Each version is run `runs` times. One observation is not a measurement: tools
whose runs disagree are marked UNSTABLE rather than settled by taking whichever
run happened first.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcpgap.mcpclient import HandshakeError, McpError, StdioMcpClient
from mcpgap.model import ObservedRequest, ToolObservation, VersionObservation
from mcpgap.normalize import SuppressionLog, normalise_headers
from mcpgap.probes import DEFAULT_SEED, arguments_for, nonce
from mcpgap.proxy import SealedProxy
from mcpgap.sandbox import SeatbeltSandbox
from mcpgap.sandbox.base import SandboxUnavailable


class InstallError(RuntimeError):
    """Dependency installation failed. Not a finding about the package."""


def install_dependencies(package_root: Path, timeout: int = 300) -> None:
    """Install the package's declared dependencies, without running its scripts."""
    manifest = package_root / "package.json"
    if not manifest.is_file():
        raise InstallError(f"no package.json in {package_root}")
    if not json.loads(manifest.read_text()).get("dependencies"):
        return
    result = subprocess.run(  # noqa: S607
        [
            "npm",
            "install",
            "--ignore-scripts",  # lifecycle scripts are an attack vector
            "--no-audit",
            "--no-fund",
            "--loglevel=error",
        ],
        cwd=str(package_root),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise InstallError(f"npm install failed in {package_root}:\n{result.stderr[-2000:]}")


def declared_config(package_root: Path, seed: str = DEFAULT_SEED) -> dict[str, str]:
    """Synthesise values for the configuration a package declares it needs.

    `.env.example` is the conventional place an MCP server states its required
    configuration. Values are nonce-tagged like tool arguments, so anything the
    package sends that came from its own config is attributable rather than
    mysterious.
    """
    example = package_root / ".env.example"
    if not example.is_file():
        return {}
    config: dict[str, str] = {}
    for raw in example.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if not key:
            continue
        token = nonce(seed, "__config__", key)
        if "EMAIL" in key.upper() or "SENDER" in key.upper():
            config[key] = f"{token}@example.invalid"
        elif "STREAM" in key.upper():
            # Postmark rejects unknown message streams; "outbound" is the
            # universal default and is not a value we need to trace.
            config[key] = "outbound"
        else:
            config[key] = token
    return config


@dataclass(slots=True)
class RunResult:
    declared_tools: dict[str, dict[str, Any]]
    per_tool: dict[str, ToolObservation]
    arguments: dict[str, dict[str, Any]]


def _request_key(request: ObservedRequest, log: SuppressionLog | None = None) -> str:
    """A stable identity for a request, used to compare runs and versions."""
    headers = normalise_headers(request.host, request.headers, log)
    body = request.json_body()
    body_repr = json.dumps(body, sort_keys=True) if body is not None else repr(request.body)
    return json.dumps(
        {
            "method": request.method,
            "host": request.host,
            "port": request.port,
            "path": request.path,
            "headers": headers,
            "body": body_repr,
        },
        sort_keys=True,
    )


def _single_run(
    package_root: Path,
    workdir: Path,
    *,
    seed: str,
    timeout: float,
) -> RunResult:
    sandbox = SeatbeltSandbox()
    node = _node_binary()
    config = declared_config(package_root, seed)

    with SealedProxy(workdir) as proxy:
        env = sandbox.child_env(workdir, {**config, **proxy.child_env()})
        process = sandbox.spawn(
            [str(node), "index.js"],
            cwd=package_root,
            env=env,
            workdir=workdir,
            allow_tcp_port=proxy.port,
            read_paths=[node.parent.parent, package_root],
        )
        client = StdioMcpClient(process, timeout=timeout)
        try:
            client.initialize()
            declared = client.list_tools()
            per_tool: dict[str, ToolObservation] = {}
            arguments: dict[str, dict[str, Any]] = {}

            for name, spec in declared.items():
                schema = spec.get("inputSchema") or {}
                args = arguments_for(name, schema, seed=seed)
                before = len(proxy.requests)
                error: str | None = None
                try:
                    client.call_tool(name, args)
                except McpError as exc:
                    # Some optional parameters change what a tool does. If the
                    # full argument set is rejected, fall back to the required
                    # minimum rather than losing the observation entirely.
                    args = arguments_for(name, schema, seed=seed, required_only=True)
                    before = len(proxy.requests)
                    try:
                        client.call_tool(name, args)
                    except McpError as retry_exc:
                        error = f"{exc} | required-only retry: {retry_exc}"
                arguments[name] = args
                per_tool[name] = ToolObservation(
                    tool=name,
                    requests=tuple(proxy.requests[before:]),
                    error=error,
                )
            return RunResult(declared, per_tool, arguments)
        finally:
            client.close()


def _node_binary() -> Path:
    import shutil

    found = shutil.which("node")
    if not found:
        raise InstallError("node not found on PATH; required to run MCP servers")
    return Path(found).resolve()


def observe_version(
    package_root: Path,
    *,
    package: str,
    version: str,
    workdir: Path,
    runs: int = 3,
    seed: str = DEFAULT_SEED,
    timeout: float = 90.0,
) -> tuple[VersionObservation, dict[str, dict[str, Any]]]:
    """Run one version `runs` times and fold the results into an observation.

    Returns the observation and the arguments used, which the differ needs in
    order to attribute values back to the inputs we supplied.
    """
    sandbox = SeatbeltSandbox()
    if not sandbox.available():
        raise SandboxUnavailable(
            "no sandbox available; refusing to run untrusted package code unconfined"
        )
    install_dependencies(package_root)

    results: list[RunResult] = []
    for index in range(runs):
        run_dir = workdir / f"run-{index}"
        run_dir.mkdir(parents=True, exist_ok=True)
        try:
            results.append(_single_run(package_root, run_dir, seed=seed, timeout=timeout))
        except HandshakeError:
            # A handshake failure is loud on purpose: it means we learned
            # nothing, which is not the same as learning the server is clean.
            raise

    declared = results[0].declared_tools
    unstable: set[str] = set()
    folded: dict[str, ToolObservation] = {}

    for name in declared:
        keys = [
            tuple(sorted(_request_key(r) for r in result.per_tool[name].requests))
            for result in results
            if name in result.per_tool
        ]
        if len(keys) != len(results) or len(set(keys)) > 1:
            unstable.add(name)
        folded[name] = results[0].per_tool.get(name, ToolObservation(tool=name, error="not run"))

    return (
        VersionObservation(
            package=package,
            version=version,
            declared_tools=declared,
            observations=folded,
            runs=runs,
            unstable_tools=frozenset(unstable),
        ),
        results[0].arguments,
    )
