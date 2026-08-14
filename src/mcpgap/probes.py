"""Generate tool arguments from a declared JSON Schema, tagged with nonces.

Every value we supply carries a nonce derived from `sha256(seed | tool | path)`.
That makes attribution a matter of exact matching rather than judgement: a
string in an outbound request either contains one of our nonces (it came from
us), or matches injected config (it came from the manifest), or it came from
somewhere we cannot account for. The third case is a fact worth reporting, and
it is reached without ever asking "does this look like an exfiltration address".

Nonces are derived from a fixed seed rather than randomly, because the two
versions under comparison must be driven with byte-identical inputs. If the
inputs differed, every field of every request would differ and the diff would
be meaningless.

Domains use `.invalid`, reserved by RFC 2606 and guaranteed never to resolve, so
a probe value cannot accidentally name a real host.
"""

from __future__ import annotations

import hashlib
from typing import Any

DEFAULT_SEED = "mcpgap-v1"
PROBE_DOMAIN = "example.invalid"

# Parameter names that need a syntactically valid value of a particular shape,
# matched case-insensitively as substrings. Kept small on purpose: this is a
# convenience for getting tools to run, never a signal used in a verdict.
_EMAIL_HINTS = ("email", "recipient", "sender", "to", "from", "cc", "bcc", "reply")
_URL_HINTS = ("url", "uri", "link", "endpoint", "webhook", "href")


def nonce(seed: str, tool: str, path: str) -> str:
    digest = hashlib.sha256(f"{seed}|{tool}|{path}".encode()).hexdigest()[:12]
    return f"probe{digest}"


def _looks_like(name: str, hints: tuple[str, ...]) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in hints)


def _string_for(seed: str, tool: str, path: str, name: str, schema: dict[str, Any]) -> str:
    token = nonce(seed, tool, path)
    fmt = str(schema.get("format", "")).lower()
    if fmt in {"email", "idn-email"} or _looks_like(name, _EMAIL_HINTS):
        return f"{token}@{PROBE_DOMAIN}"
    if fmt in {"uri", "url", "iri"} or _looks_like(name, _URL_HINTS):
        return f"https://{token}.{PROBE_DOMAIN}/probe"
    if enum := schema.get("enum"):
        return str(enum[0])
    return token


def value_for(
    schema: dict[str, Any],
    *,
    seed: str = DEFAULT_SEED,
    tool: str = "",
    path: str = "",
    name: str = "",
) -> Any:
    """Build one deterministic value for `schema`."""
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]

    declared = schema.get("type")
    if isinstance(declared, list):
        declared = next((t for t in declared if t != "null"), "string")
    # A schema with no `type` but with `properties` is an object in practice.
    if declared is None:
        declared = "object" if "properties" in schema else "string"

    if declared == "string":
        return _string_for(seed, tool, path, name or path, schema)
    if declared == "integer":
        return 1
    if declared == "number":
        return 1.0
    if declared == "boolean":
        return True
    if declared == "array":
        item = schema.get("items") or {"type": "string"}
        return [value_for(item, seed=seed, tool=tool, path=f"{path}[0]", name=name)]
    if declared == "object":
        properties = schema.get("properties") or {}
        return {
            key: value_for(sub, seed=seed, tool=tool, path=f"{path}.{key}", name=key)
            for key, sub in properties.items()
        }
    return _string_for(seed, tool, path, name or path, schema)


def arguments_for(
    tool: str,
    input_schema: dict[str, Any],
    *,
    seed: str = DEFAULT_SEED,
    required_only: bool = False,
) -> dict[str, Any]:
    """Build an argument object for one tool.

    `required_only` is the fallback used when a full call errors: some optional
    parameters change what the tool does (an attachment URL makes it fetch), and
    a tool that refuses the full set is still worth observing on its minimum.
    """
    properties = input_schema.get("properties") or {}
    required = set(input_schema.get("required") or [])
    chosen = required if required_only else set(properties)
    return {
        key: value_for(schema, seed=seed, tool=tool, path=key, name=key)
        for key, schema in properties.items()
        if key in chosen
    }


def nonces_in(value: Any) -> set[str]:
    """Every probe token appearing anywhere in a generated argument object."""
    found: set[str] = set()
    if isinstance(value, str):
        for chunk in value.replace("@", " ").replace("/", " ").replace(".", " ").split():
            if chunk.startswith("probe") and len(chunk) == 17:
                found.add(chunk)
    elif isinstance(value, dict):
        for item in value.values():
            found |= nonces_in(item)
    elif isinstance(value, list):
        for item in value:
            found |= nonces_in(item)
    return found
