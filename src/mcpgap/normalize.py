"""Neutralise volatile fields before comparing observations.

A list like this is exactly the kind of artefact that has burned this codebase's
author before: a set of markers tuned for one context, reused in another where
its meaning had inverted. So two rules apply here.

1. **Rules are scoped, never global.** Each carries the host it applies to
   (`None` meaning any) and a written reason. A rule that is right for
   `api.postmarkapp.com` is not thereby right for an arbitrary attachment host.
2. **Suppression is logged.** Every field a rule removes is recorded in the run
   log. Removing a field is a judgement call, and a judgement that leaves no
   trace cannot be audited -- which is the whole thesis of this project applied
   to its own internals.

In sealed mode there is very little genuine volatility, because the canned
responses are fixed. The list is short on purpose: anything suppressed here is
something the diff can no longer see.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class HeaderRule:
    header: str
    reason: str
    host_suffix: str | None = None

    def applies_to(self, host: str) -> bool:
        return self.host_suffix is None or host.endswith(self.host_suffix)


# Deliberately minimal. Each entry has to justify blinding the diff.
HEADER_RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        "content-length",
        "derived from the body, which is compared directly; keeping it would "
        "report one change twice",
    ),
    HeaderRule(
        "host",
        "restates the connection's authority, which is already compared as the "
        "request's host field",
    ),
)


@dataclass
class SuppressionLog:
    """Records every field a normalisation rule removed."""

    entries: list[tuple[str, str, str]] = field(default_factory=list)

    def record(self, host: str, header: str, reason: str) -> None:
        self.entries.append((host, header, reason))

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, header, _ in self.entries:
            counts[header] = counts.get(header, 0) + 1
        return counts


def normalise_headers(
    host: str, headers: dict[str, str], log: SuppressionLog | None = None
) -> dict[str, str]:
    """Drop volatile headers for `host`, recording each removal."""
    kept = {}
    for name, value in headers.items():
        lowered = name.lower()
        rule = next(
            (r for r in HEADER_RULES if r.header == lowered and r.applies_to(host)),
            None,
        )
        if rule is None:
            kept[lowered] = value
        elif log is not None:
            log.record(host, lowered, rule.reason)
    return kept
