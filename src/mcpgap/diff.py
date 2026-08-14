"""Compare two versions observed under identical inputs.

The differential check is the strong one. Single-version analysis has to decide
whether a value is suspicious, which is a judgement with an irreducible false
positive rate. Comparing two versions driven with byte-identical nonce inputs
asks a much narrower question -- *what is in the new version's request that was
not in the old one's* -- and that has an answer rather than an opinion.

Two views are produced and kept apart:

* `findings` -- differences inside request bodies and headers.
* `destinations_added` / `destinations_removed` -- the host-level view.

They are not merged, because for the case this tool was built around the second
is empty while the first is not. A single blended score would hide exactly the
distinction that matters.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from collections.abc import Iterator
from typing import Any

from mcpgap.model import (
    Attribution,
    DiffReport,
    Finding,
    ObservedRequest,
    Verdict,
    VersionObservation,
)


def _flatten(value: Any, pointer: str = "") -> Iterator[tuple[str, Any]]:
    """Yield (JSON Pointer, leaf value) for every leaf in a JSON document."""
    if isinstance(value, dict):
        for key, sub in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from _flatten(sub, f"{pointer}/{escaped}")
    elif isinstance(value, list):
        for index, sub in enumerate(value):
            yield from _flatten(sub, f"{pointer}/{index}")
    else:
        yield pointer, value


def _encodings(token: str) -> tuple[str, ...]:
    """Forms a value we supplied might take by the time it is sent."""
    raw = token.encode()
    return (
        token,
        token.lower(),
        token.upper(),
        urllib.parse.quote(token),
        base64.b64encode(raw).decode(),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
    )


def attribute(value: Any, caller_tokens: set[str], config_tokens: set[str]) -> Attribution:
    """Decide where `value` came from, by exact matching -- never by shape.

    Substring matching is used rather than equality because tools legitimately
    wrap what we give them: a message id becomes `<probe123@host>`, a URL gets a
    query string appended. Wrapping a value we supplied does not make it
    unattributable.
    """
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    for token in caller_tokens:
        if any(form in text for form in _encodings(token)):
            return Attribution.CALLER_INPUT
    for token in config_tokens:
        if any(form in text for form in _encodings(token)):
            return Attribution.DECLARED_CONFIG
    return Attribution.UNATTRIBUTED


def _tokens_from(value: Any) -> set[str]:
    """Every probe nonce appearing anywhere in a value."""
    found: set[str] = set()
    if isinstance(value, str):
        for chunk in value.replace("@", " ").replace("/", " ").replace(".", " ").split():
            if chunk.startswith("probe") and len(chunk) == 17:
                found.add(chunk)
    elif isinstance(value, dict):
        for sub in value.values():
            found |= _tokens_from(sub)
    elif isinstance(value, list):
        for sub in value:
            found |= _tokens_from(sub)
    return found


def _match_requests(
    old: tuple[ObservedRequest, ...], new: tuple[ObservedRequest, ...]
) -> list[tuple[ObservedRequest | None, ObservedRequest]]:
    """Pair up requests between versions by destination and path."""
    remaining = list(old)
    pairs: list[tuple[ObservedRequest | None, ObservedRequest]] = []
    for request in new:
        match = next(
            (
                candidate
                for candidate in remaining
                if candidate.host == request.host
                and candidate.method == request.method
                and candidate.path.split("?")[0] == request.path.split("?")[0]
            ),
            None,
        )
        if match is not None:
            remaining.remove(match)
        pairs.append((match, request))
    return pairs


def diff_versions(
    old: VersionObservation,
    new: VersionObservation,
    *,
    caller_arguments: dict[str, dict[str, Any]] | None = None,
    config_values: dict[str, str] | None = None,
) -> DiffReport:
    """Produce the report for `old` -> `new`."""
    caller_arguments = caller_arguments or {}
    config_tokens = _tokens_from(config_values or {})

    findings: list[Finding] = []
    verdicts: dict[str, Verdict] = {}

    for tool in sorted(set(old.declared_tools) | set(new.declared_tools)):
        old_obs = old.observations.get(tool)
        new_obs = new.observations.get(tool)

        if tool in old.unstable_tools or tool in new.unstable_tools:
            verdicts[tool] = Verdict.UNSTABLE
            continue
        if old_obs is None or new_obs is None or not old_obs.exercised or not new_obs.exercised:
            # Never seen working in both versions, so there is nothing to
            # compare. This is an abstention, not a clean bill of health.
            verdicts[tool] = Verdict.CANNOT_CONCLUDE
            continue

        caller_tokens = _tokens_from(caller_arguments.get(tool, {}))
        tool_findings = list(
            _diff_tool(tool, old_obs.requests, new_obs.requests, caller_tokens, config_tokens)
        )
        findings.extend(tool_findings)
        verdicts[tool] = (
            Verdict.UNDECLARED_BEHAVIOUR
            if any(f.attribution is Attribution.UNATTRIBUTED for f in tool_findings)
            else Verdict.CONSISTENT
        )

    def _schemas(observation: VersionObservation) -> dict[str, str]:
        return {
            name: json.dumps(spec, sort_keys=True)
            for name, spec in observation.declared_tools.items()
        }

    old_schemas = _schemas(old)
    new_schemas = _schemas(new)

    return DiffReport(
        package=new.package,
        old_version=old.version,
        new_version=new.version,
        findings=tuple(findings),
        verdicts=verdicts,
        declared_added=frozenset(new_schemas) - frozenset(old_schemas),
        declared_removed=frozenset(old_schemas) - frozenset(new_schemas),
        declared_schema_changed=frozenset(
            name
            for name in set(old_schemas) & set(new_schemas)
            if old_schemas[name] != new_schemas[name]
        ),
        destinations_added=new.destinations() - old.destinations(),
        destinations_removed=old.destinations() - new.destinations(),
    )


def _diff_tool(
    tool: str,
    old_requests: tuple[ObservedRequest, ...],
    new_requests: tuple[ObservedRequest, ...],
    caller_tokens: set[str],
    config_tokens: set[str],
) -> Iterator[Finding]:
    for old_request, new_request in _match_requests(old_requests, new_requests):
        new_body = new_request.json_body()
        if new_body is None:
            continue

        if old_request is None:
            # A request with no counterpart in the old version. Report only the
            # unattributable parts of it; the rest came from us.
            for pointer, value in _flatten(new_body):
                how = attribute(value, caller_tokens, config_tokens)
                if how is Attribution.UNATTRIBUTED:
                    yield Finding(
                        tool=tool,
                        kind="request_added",
                        host=new_request.host,
                        path=new_request.path,
                        pointer=pointer,
                        value=value,
                        attribution=how,
                        evidence=new_request,
                    )
            continue

        old_body = old_request.json_body()
        old_leaves = dict(_flatten(old_body)) if old_body is not None else {}
        for pointer, value in _flatten(new_body):
            if pointer in old_leaves and old_leaves[pointer] == value:
                continue
            kind = "request_field_added" if pointer not in old_leaves else "request_field_changed"
            yield Finding(
                tool=tool,
                kind=kind,
                host=new_request.host,
                path=new_request.path,
                pointer=pointer,
                value=value,
                attribution=attribute(value, caller_tokens, config_tokens),
                evidence=new_request,
            )
