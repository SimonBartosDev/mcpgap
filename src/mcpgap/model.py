"""Data model for observations, findings and verdicts.

The vocabulary here is the product. In particular `Verdict` has four values and
not two, because "we did not manage to test this" and "we tested this and it was
fine" are different facts and collapsing them is the failure mode this tool
exists to avoid.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    """Per-tool conclusion.

    CONSISTENT and UNDECLARED_BEHAVIOUR are claims. CANNOT_CONCLUDE and UNSTABLE
    are refusals to make a claim, and they are first-class: a tool we never
    managed to exercise is CANNOT_CONCLUDE, never CONSISTENT.
    """

    CONSISTENT = "consistent"
    UNDECLARED_BEHAVIOUR = "undeclared_behaviour"
    CANNOT_CONCLUDE = "cannot_conclude"
    UNSTABLE = "unstable"


class Attribution(StrEnum):
    """Where a value observed in an outbound request came from.

    Attribution is decided by exact matching against nonce-tagged inputs, not by
    heuristics about what a value looks like. UNATTRIBUTED means we could not
    trace it to anything we supplied -- it is a prompt to look, not a verdict.
    """

    CALLER_INPUT = "caller_input"
    DECLARED_CONFIG = "declared_config"
    UNATTRIBUTED = "unattributed"


@dataclass(frozen=True, slots=True)
class ObservedRequest:
    """A single outbound request recorded at the sandbox boundary."""

    host: str
    port: int
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None

    @property
    def destination(self) -> str:
        """Host-level identity, which is all a conventional scanner records."""
        return f"{self.host}:{self.port}"

    def json_body(self) -> Any | None:
        if not self.body:
            return None
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None


@dataclass(frozen=True, slots=True)
class BlockedConnection:
    """An egress attempt the sandbox refused.

    Recorded as an observation in its own right. A package that bypasses the
    proxy does not thereby become invisible; it becomes this.
    """

    host: str
    port: int
    reason: str


@dataclass(frozen=True, slots=True)
class FileEvent:
    """A filesystem operation seen by the preload shim.

    Best-effort: the shim is cooperative and can be bypassed. Writes have an
    independent, non-bypassable witness in `FileChanges` below; reads do not,
    and that asymmetry is deliberate rather than an oversight.
    """

    op: str
    path: str


@dataclass(frozen=True, slots=True)
class ProcessEvent:
    """A subprocess spawn seen by the preload shim. Best-effort, as above."""

    op: str
    argv: tuple[str, ...]

    @property
    def command(self) -> str:
        return self.argv[0] if self.argv else ""


@dataclass(frozen=True, slots=True)
class FileChanges:
    """Files created, modified or deleted in the sandbox's writable tree.

    Complete, not best-effort: the sandbox refuses writes outside this tree, so
    anything written at all is written here and shows up in the snapshot diff.
    """

    created: tuple[str, ...] = ()
    modified: tuple[str, ...] = ()
    deleted: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.created or self.modified or self.deleted)

    def as_set(self) -> frozenset[tuple[str, str]]:
        return frozenset(
            [("created", p) for p in self.created]
            + [("modified", p) for p in self.modified]
            + [("deleted", p) for p in self.deleted]
        )


@dataclass(frozen=True, slots=True)
class ToolObservation:
    """What one tool did, across one run."""

    tool: str
    requests: tuple[ObservedRequest, ...] = ()
    blocked: tuple[BlockedConnection, ...] = ()
    file_events: tuple[FileEvent, ...] = ()
    process_events: tuple[ProcessEvent, ...] = ()
    file_changes: FileChanges = FileChanges()
    error: str | None = None

    @property
    def exercised(self) -> bool:
        return self.error is None


@dataclass(frozen=True, slots=True)
class VersionObservation:
    """Everything observed for one version of one package."""

    package: str
    version: str
    declared_tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    observations: dict[str, ToolObservation] = field(default_factory=dict)
    runs: int = 0
    unstable_tools: frozenset[str] = frozenset()
    # The nonce-tagged inputs we supplied, kept so the differ can attribute
    # observed values back to them by exact matching rather than by guessing.
    probe_arguments: dict[str, dict[str, Any]] = field(default_factory=dict)
    config_values: dict[str, str] = field(default_factory=dict)

    @property
    def not_exercised(self) -> frozenset[str]:
        """Declared tools we never got a clean observation for."""
        return frozenset(
            name
            for name in self.declared_tools
            if name not in self.observations or not self.observations[name].exercised
        )

    def destinations(self) -> frozenset[str]:
        """The host-level view: every distinct destination contacted."""
        return frozenset(
            req.destination for obs in self.observations.values() for req in obs.requests
        )


@dataclass(frozen=True, slots=True)
class Finding:
    """A fact about an observed difference, with the evidence attached.

    Deliberately not "an alert" and not a severity. `pointer` is a JSON Pointer
    into the request body; `value` is what was found there.
    """

    tool: str
    kind: str
    value: Any
    attribution: Attribution = Attribution.UNATTRIBUTED
    # Network findings carry the request they were found in. Filesystem and
    # subprocess findings have no request, so this is None for them and the
    # fact lives in `value`.
    host: str = ""
    path: str = ""
    pointer: str = ""
    evidence: ObservedRequest | None = None
    # Whether the mechanism that produced this finding can be evaded by the
    # code under test. Snapshot-derived filesystem writes cannot; anything from
    # the cooperative preload shim can. Reported, never silently averaged in.
    best_effort: bool = False

    def describe(self) -> str:
        qualifier = " [best-effort]" if self.best_effort else ""
        if self.evidence is None:
            return f"{self.tool}: {self.kind} -- {self.value!r}{qualifier}"
        return (
            f"{self.tool}: {self.kind} at {self.pointer} in request to "
            f"{self.host}{self.path} -- value {self.value!r} "
            f"({self.attribution}){qualifier}"
        )


@dataclass(frozen=True, slots=True)
class DiffReport:
    """The result of comparing two versions.

    `destination_changes` is kept separate from `findings` on purpose: it is the
    host-level view, and for the postmark-mcp case it is empty while `findings`
    is not. That contrast is the point of the tool, so the report keeps both
    rather than merging them into one number.
    """

    package: str
    old_version: str
    new_version: str
    findings: tuple[Finding, ...] = ()
    verdicts: dict[str, Verdict] = field(default_factory=dict)
    declared_added: frozenset[str] = frozenset()
    declared_removed: frozenset[str] = frozenset()
    declared_schema_changed: frozenset[str] = frozenset()
    destinations_added: frozenset[str] = frozenset()
    destinations_removed: frozenset[str] = frozenset()

    def findings_for(self, tool: str) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.tool == tool)

    @property
    def concluded_tools(self) -> dict[str, Verdict]:
        """Tools we actually reached a conclusion about.

        Any rate we publish uses this as its denominator. Tools we could not
        exercise, and tools whose runs disagreed, are excluded -- counting our
        own ignorance against the package would inflate the accusation.
        """
        return {
            name: v
            for name, v in self.verdicts.items()
            if v in (Verdict.CONSISTENT, Verdict.UNDECLARED_BEHAVIOUR)
        }
