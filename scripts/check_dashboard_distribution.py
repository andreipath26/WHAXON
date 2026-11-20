"""Fail Dashboard deployment if wheels/sdists omit any self-hosted UI asset."""
from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src/whaxon/interfaces/web/static"
MANIFEST = json.loads((STATIC / "dashboard-assets-manifest.json").read_text(encoding="utf-8"))
ASSET_FILES = [entry["file"] for entry in MANIFEST["files"]]
REQUIRED = [
    "dashboard-v2.css",
    "dashboard-fonts.css",
    "dashboard-assets-manifest.json",
    *[f"dashboard-fonts/{x}" if x.endswith(".woff2") else x for x in ASSET_FILES],
    "dashboard-licenses/Inter.txt",
    "dashboard-licenses/JetBrainsMono.txt",
    "dashboard-licenses/SpaceGrotesk.txt",
    "dashboard-licenses/MaterialSymbols.txt",
]


def verify_archive(label: str, names: list[str], read_bytes) -> None:
    for relative in REQUIRED:
        expected = "whaxon/interfaces/web/static/" + relative
        matches = [name for name in names if name.endswith(expected)]
        assert len(matches) == 1, f"{label}: missing or duplicated {expected}: {matches}"
        if relative.endswith((".woff2", ".jpg", ".png", ".webp")):
            source = next(
                item for item in MANIFEST["files"]
                if item["file"] == Path(relative).name
            )
            actual = hashlib.sha256(read_bytes(matches[0])).hexdigest()
            assert actual == source["sha256"], f"{label}: checksum mismatch for {relative}"
    assert len(ASSET_FILES) >= 6, "Dashboard font/image inventory suspiciously small"


def main() -> None:
    wheel = list((ROOT / "dist").glob("*.whl"))
    source = list((ROOT / "dist").glob("*.tar.gz"))
    assert len(wheel) == 1 and len(source) == 1, "Expected one wheel and one sdist"
    with ZipFile(wheel[0]) as archive:
        verify_archive("wheel", archive.namelist(), archive.read)
    with tarfile.open(source[0], "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers() if member.isfile()}
        def read_member(name: str) -> bytes:
            stream = archive.extractfile(members[name])
            assert stream is not None
            return stream.read()
        verify_archive("sdist", list(members), read_member)
    print("Dashboard wheel and source distribution: complete self-hosted assets, SHA-256 verified")


if __name__ == "__main__":
    main()
