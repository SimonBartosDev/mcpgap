"""Install a package version, run it under the sandbox, and record what it does.

Install and run are separate phases with different privileges:

* **Resolve and download** happens *outside* the sandbox, with network, using
  `npm install --ignore-scripts`. That fetches the dependency tree without
  executing any of it.
* **Lifecycle scripts** then run *inside* the sandbox, before the server
  starts, exactly as npm would order them -- but confined, with the recording
  proxy as the only egress. This is the only code mcpgap runs that no tool call
  asked for, which is why it runs under the strictest conditions available.
* **Run** happens inside the sandbox with no network but the recording proxy.

Each version is run `runs` times. One observation is not a measurement: tools
whose runs disagree are marked UNSTABLE rather than settled by taking whichever
run happened first.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcpgap.installscripts import InstallScript, declared_scripts, enumerate_install_scripts
from mcpgap.mcpclient import HandshakeError, McpError, StdioMcpClient
from mcpgap.model import (
    INSTALL_PREFIX,
    FileChanges,
    FileEvent,
    ObservedRequest,
    ProcessEvent,
    ToolObservation,
    VersionObservation,
)
from mcpgap.normalize import SuppressionLog, normalise_headers
from mcpgap.observers import diff_snapshots, install_shim, read_events, snapshot
from mcpgap.observers.events import shim_path
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
    install: dict[str, ToolObservation]


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


#  node_modules is excluded from filesystem snapshots. That loses nothing: it
#  is shared read-only from the install directory, which sits outside the
#  sandbox's writable tree, so the package cannot write there in the first
#  place. Hashing it would add thousands of files per snapshot for no signal.
_SNAPSHOT_SKIP = frozenset({"node_modules"})


def _stage_package(package_root: Path, run_dir: Path) -> Path:
    """Give the run its own writable copy of the package.

    Two reasons. Filesystem observation needs the package's own directory to be
    writable, and it is not: the sandbox permits writes only under the run
    directory. And a fresh copy per run keeps runs independent, so the N-runs
    agreement check compares three genuinely separate executions rather than
    three passes over one accumulating directory.

    `node_modules` is shared by symlink rather than copied -- it is large, and
    it stays read-only, which is what we want.
    """
    staged = run_dir / "package"
    staged.mkdir(parents=True, exist_ok=True)
    for entry in package_root.iterdir():
        if entry.name == "node_modules":
            continue
        target = staged / entry.name
        if entry.is_dir():
            shutil.copytree(entry, target, dirs_exist_ok=True, symlinks=True)
        else:
            shutil.copy2(entry, target)
    modules = package_root / "node_modules"
    link = staged / "node_modules"
    if modules.is_dir() and not link.exists():
        link.symlink_to(modules, target_is_directory=True)
    return staged


def _relativise(text: str, workdir: Path) -> str:
    """Rewrite run-specific absolute paths to a stable placeholder.

    Every run gets a fresh temporary directory, and the two versions being
    compared get different ones again. Left raw, an absolute path would differ
    across every run and every version, so all three runs would disagree and
    every tool would be reported UNSTABLE -- an artefact of our own plumbing
    presented as a finding about the package.
    """
    for root in (str(workdir.resolve()), str(workdir)):
        text = text.replace(root, "<run>")
    return text


def _normalise_request(request: ObservedRequest, workdir: Path) -> ObservedRequest:
    """Strip run-specific paths out of a recorded request.

    Packages echo their working directory into request bodies -- an install
    script reporting `cwd`, for instance. Since every run and every version gets
    a fresh temporary directory, an un-normalised body differs on every single
    run, which marks the tool UNSTABLE and, worse, makes the version diff report
    a change that is purely an artefact of where we happened to stage the files.

    This is the same defect as `_relativise` was introduced to fix for file and
    process events; the network channel needs it too. All three channels are
    normalised here so a future one is not forgotten in isolation.
    """
    body = request.body
    if body is not None:
        body = _relativise(body.decode("utf-8", "surrogateescape"), workdir).encode(
            "utf-8", "surrogateescape"
        )
    return ObservedRequest(
        host=request.host,
        port=request.port,
        method=request.method,
        path=_relativise(request.path, workdir),
        headers={k: _relativise(v, workdir) for k, v in request.headers.items()},
        body=body,
    )


def _normalise_events(
    files: list[FileEvent], procs: list[ProcessEvent], workdir: Path
) -> tuple[tuple[FileEvent, ...], tuple[ProcessEvent, ...]]:
    return (
        tuple(FileEvent(op=e.op, path=_relativise(e.path, workdir)) for e in files),
        tuple(
            ProcessEvent(op=e.op, argv=tuple(_relativise(a, workdir) for a in e.argv))
            for e in procs
        ),
    )


def _observation_key(observation: ToolObservation) -> str:
    """Everything that must agree across runs before a verdict is issued."""
    return json.dumps(
        {
            "requests": sorted(_request_key(r) for r in observation.requests),
            "files": sorted(f"{e.op}:{e.path}" for e in observation.file_events),
            "procs": sorted(" ".join(e.argv) for e in observation.process_events),
            "changes": sorted(observation.file_changes.as_set()),
            "error": observation.error is not None,
        },
        sort_keys=True,
    )


def _run_install_scripts(
    scripts: list[InstallScript],
    *,
    staged: Path,
    workdir: Path,
    sandbox: SeatbeltSandbox,
    node: Path,
    package_root: Path,
    base_env: dict[str, str],
    events_log: Path,
    proxy: SealedProxy,
    cursor: int,
    timeout: float,
) -> tuple[dict[str, ToolObservation], int]:
    """Execute each lifecycle hook inside the sandbox and record what it did.

    This is the only place mcpgap deliberately runs code that has not been
    asked for by a tool call. It runs confined: no network but the recording
    proxy, writes limited to the run directory, no ambient credentials, and a
    timeout. A hook that fails is still an observation -- a script that tried to
    reach the network and was refused tells us more than one that did not try.
    """
    observations: dict[str, ToolObservation] = {}
    # npm puts the local bin directory on PATH for lifecycle scripts.
    bin_dir = staged / "node_modules" / ".bin"
    env = dict(base_env)
    env["PATH"] = f"{bin_dir}:{node.parent}:{env.get('PATH', '')}"

    for script in scripts:
        cwd = (staged / script.relative_cwd).resolve()
        if not cwd.is_dir():
            continue
        before_requests = len(proxy.requests)
        fs_before = snapshot(workdir, skip_dirs=_SNAPSHOT_SKIP)

        # `error` means "we did not get to observe this", not "the script
        # failed". A hook that exits non-zero ran, and everything it did up to
        # that point was recorded, so it stays comparable across versions --
        # in sealed mode a script that tries to reach the network is *expected*
        # to fail, and treating that as an abstention would discard the most
        # interesting observation we have.
        error: str | None = None
        process = sandbox.spawn(
            ["/bin/sh", "-c", script.command],
            cwd=cwd,
            env=env,
            workdir=workdir,
            allow_tcp_port=proxy.port,
            read_paths=[node.parent.parent, package_root],
        )
        try:
            process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            # Cut short, so what we saw is a prefix of what it does. That is an
            # incomplete observation and must not be compared as if complete.
            error = f"timed out after {timeout}s"

        # The child has exited, but a connection it opened may still be being
        # parsed on a proxy thread. Wait for the proxy to go quiet before
        # reading, or the last request is recorded on some runs and not others.
        proxy.wait_idle()
        raw_files, raw_procs, cursor = read_events(events_log, cursor)
        file_events, process_events = _normalise_events(raw_files, raw_procs, workdir)
        created, modified, deleted = diff_snapshots(
            fs_before, snapshot(workdir, skip_dirs=_SNAPSHOT_SKIP)
        )
        observations[script.key] = ToolObservation(
            tool=f"{INSTALL_PREFIX}{script.key}",
            requests=tuple(
                _normalise_request(r, workdir) for r in proxy.requests[before_requests:]
            ),
            file_events=file_events,
            process_events=process_events,
            file_changes=FileChanges(created, modified, deleted),
            error=error,
        )
    return observations, cursor


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
    staged = _stage_package(package_root, workdir)
    _, events_log = install_shim(workdir)
    event_cursor = 0

    with SealedProxy(workdir) as proxy:
        env = sandbox.child_env(
            workdir,
            {
                **config,
                **proxy.child_env(),
                "MCPGAP_EVENTS": str(events_log),
            },
        )
        # The shim must load before the package's entry point so that ESM named
        # imports of builtins resolve to the patched functions.
        existing = env.get("NODE_OPTIONS", "")
        env["NODE_OPTIONS"] = f"{existing} --require {shim_path(workdir)}".strip()

        # Lifecycle hooks run before the server starts, as npm would run them,
        # but inside the sandbox rather than outside it.
        install_observations, event_cursor = _run_install_scripts(
            enumerate_install_scripts(staged),
            staged=staged,
            workdir=workdir,
            sandbox=sandbox,
            node=node,
            package_root=package_root,
            base_env=env,
            events_log=events_log,
            proxy=proxy,
            cursor=event_cursor,
            timeout=timeout,
        )

        process = sandbox.spawn(
            [str(node), "index.js"],
            cwd=staged,
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
            # Baseline taken after startup, so module loading is not attributed
            # to whichever tool happens to be called first.
            _, _, event_cursor = read_events(events_log, 0)
            fs_before = snapshot(workdir, skip_dirs=_SNAPSHOT_SKIP)

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

                proxy.wait_idle()
                raw_files, raw_procs, event_cursor = read_events(events_log, event_cursor)
                file_events, process_events = _normalise_events(raw_files, raw_procs, workdir)
                fs_after = snapshot(workdir, skip_dirs=_SNAPSHOT_SKIP)
                created, modified, deleted = diff_snapshots(fs_before, fs_after)
                fs_before = fs_after

                arguments[name] = args
                per_tool[name] = ToolObservation(
                    tool=name,
                    requests=tuple(_normalise_request(r, workdir) for r in proxy.requests[before:]),
                    file_events=tuple(file_events),
                    process_events=tuple(process_events),
                    file_changes=FileChanges(created, modified, deleted),
                    error=error,
                )
            return RunResult(declared, per_tool, arguments, install_observations)
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
    folded_install: dict[str, ToolObservation] = {}

    for key in results[0].install:
        keys = [
            _observation_key(result.install[key]) for result in results if key in result.install
        ]
        if len(keys) != len(results) or len(set(keys)) > 1:
            unstable.add(f"{INSTALL_PREFIX}{key}")
        folded_install[key] = results[0].install[key]

    for name in declared:
        keys = [
            _observation_key(result.per_tool[name]) for result in results if name in result.per_tool
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
            declared_scripts=declared_scripts(package_root),
            install_observations=folded_install,
        ),
        results[0].arguments,
    )
