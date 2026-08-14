"""Loader for the vendored malicious-package fixtures.

The archives in `fixtures/` contain real malware. This loader is the only
supported way to unpack them, and it is deliberately narrow:

* it extracts only into a caller-supplied directory, after checking that the
  directory is not inside the repository working tree;
* it rejects absolute paths, `..` traversal, symlinks and any non-regular
  member, rather than trusting the archive's own member names.

That is a smaller promise than "malware cannot escape", and SECURITY.md states
it as such.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "fixtures" / "postmark-mcp"
PASSWORD = b"infected"

# From fixtures/postmark-mcp/PROVENANCE.md. Asserted on every load: a fixture
# that does not hash correctly is not the artifact we vouched for.
EXPECTED_INDEX_SHA256 = {
    "1.0.15": "0007994c327f1cd3bfe99e8cc179000e063e25d77b6466f02e57e570857a3719",
    "1.0.16": "27214b8639d541c6c5671f53fd598c72d7b6531cd52dd828ecb5d1d42c6d663c",
}

# The change under test, quoted from the real v1.0.16 source.
ATTACKER_BCC = "phan@giftshop.club"


class FixtureError(RuntimeError):
    """Raised when a fixture is missing, unreadable, or fails verification.

    Distinct from any assertion failure in a test, so that "the gate did not
    detect the rug pull" can never be confused with "the fixture was not there".
    """


def archive_path(version: str) -> Path:
    return FIXTURE_DIR / f"postmark-mcp-{version}.zip"


def available(version: str) -> bool:
    return archive_path(version).is_file()


def _safe_members(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename
        if name.startswith("/") or Path(name).is_absolute() or ".." in Path(name).parts:
            raise FixtureError(f"unsafe member path in fixture archive: {name!r}")
        # Upper 4 bits of the high half of external_attr are the Unix file type;
        # 0xA is a symlink. Regular files are 0x8.
        mode_type = (info.external_attr >> 16) & 0xF000
        if mode_type not in (0, 0x8000):
            raise FixtureError(f"non-regular member in fixture archive: {name!r}")
        members.append(info)
    return members


def unpack(version: str, dest: Path) -> Path:
    """Extract fixture `version` into `dest`; return the package root.

    Raises FixtureError -- never an assertion -- for anything that is a problem
    with the fixture rather than a problem with the scanner.
    """
    src = archive_path(version)
    if not src.is_file():
        raise FixtureError(
            f"fixture archive missing: {src}. Run `python3 tools/build_fixtures.py` to rebuild it."
        )

    dest = dest.resolve()
    if dest == REPO_ROOT or REPO_ROOT in dest.parents:
        raise FixtureError(
            f"refusing to unpack live malware inside the repository working tree: {dest}"
        )
    dest.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(src) as zf:
            for info in _safe_members(zf):
                data = zf.read(info, pwd=PASSWORD)
                target = dest / info.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
    except (zipfile.BadZipFile, RuntimeError) as exc:
        raise FixtureError(f"could not read fixture {src}: {exc}") from exc

    root = dest / "package"
    index = root / "index.js"
    if not index.is_file():
        raise FixtureError(f"fixture {version} has no package/index.js")

    digest = hashlib.sha256(index.read_bytes()).hexdigest()
    expected = EXPECTED_INDEX_SHA256[version]
    if digest != expected:
        raise FixtureError(
            f"fixture {version} index.js sha256 {digest} != expected {expected}; "
            "the vendored artifact is not the one PROVENANCE.md describes"
        )
    return root


def read_index(version: str) -> str:
    """Read a fixture's index.js without unpacking it to disk."""
    src = archive_path(version)
    if not src.is_file():
        raise FixtureError(f"fixture archive missing: {src}")
    with zipfile.ZipFile(src) as zf:
        return zf.read("package/index.js", pwd=PASSWORD).decode("utf-8")
