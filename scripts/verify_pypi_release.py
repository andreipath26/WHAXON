"""Verify the exact distributions published for a WHAXON release."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def local_artifacts(dist_dir: Path) -> dict[str, str]:
    artifacts = sorted(
        item for item in dist_dir.iterdir()
        if item.is_file() and (item.name.endswith(".whl") or item.name.endswith(".tar.gz"))
    )
    if not artifacts:
        raise RuntimeError(f"No wheel or sdist found in {dist_dir}")
    return {
        item.name: hashlib.sha256(item.read_bytes()).hexdigest()
        for item in artifacts
    }


def published_artifacts(version: str, *, opener=urlopen) -> dict[str, str]:
    request = Request(
        f"https://pypi.org/pypi/whaxon/{version}/json",
        headers={"Accept": "application/json"},
    )
    with opener(request, timeout=20) as response:
        payload = json.load(response)
    if payload.get("info", {}).get("version") != version:
        raise RuntimeError(f"PyPI returned metadata for the wrong version: {version}")
    result = {}
    for item in payload.get("urls", []):
        filename = item.get("filename")
        digest = item.get("digests", {}).get("sha256")
        if filename and digest:
            result[filename] = digest
    return result


def verify_pypi_release(
    version: str,
    dist_dir: Path,
    *,
    opener=urlopen,
    sleeper=time.sleep,
    attempts: int = 30,
    interval_s: float = 20.0,
) -> None:
    expected = local_artifacts(dist_dir)
    last_error = "PyPI has not exposed the expected files yet"
    for attempt in range(attempts):
        try:
            published = published_artifacts(version, opener=opener)
        except HTTPError as exc:
            if exc.code != 404:
                raise
            published = {}
        missing = set(expected) - set(published)
        mismatched = {
            name for name, digest in expected.items()
            if name in published and published[name] != digest
        }
        if mismatched:
            raise RuntimeError(
                "PyPI SHA-256 does not match local build for: "
                + ", ".join(sorted(mismatched))
            )
        unexpected = set(published) - set(expected)
        if not missing and not unexpected:
            print(f"PyPI {version} files match the local wheel and sdist SHA-256 hashes.")
            return
        last_error = (
            f"PyPI files are incomplete or unexpected; missing={sorted(missing)}, "
            f"unexpected={sorted(unexpected)}"
        )
        if attempt + 1 < attempts:
            sleeper(interval_s)
    raise RuntimeError(f"PyPI release verification timed out: {last_error}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    args = parser.parse_args()
    verify_pypi_release(args.version, Path("dist"))


if __name__ == "__main__":
    main()
