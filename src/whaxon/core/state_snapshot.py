"""Offline, fail-closed Engine V2 operator state backup and restoration.

Both web and workflow-worker services MUST be stopped by the operator first.
This tool cannot prove service quiescence or provide an external trust anchor.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
from contextlib import closing
from pathlib import Path

_MANIFEST = "e5-snapshot-manifest.json"
_DB = "whaxon.db"
_SIDECARS = {"whaxon.db-wal", "whaxon.db-shm", "whaxon.db-journal"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inventory(root: Path) -> dict[str, Path]:
    result = {}
    for entry in sorted(root.rglob("*")):
        mode = entry.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ValueError(f"state contains symlink: {entry.relative_to(root)}")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode) or entry.stat().st_nlink != 1:
            raise ValueError(f"state contains unsupported file: {entry.relative_to(root)}")
        relative = entry.relative_to(root).as_posix()
        result[relative] = entry
    return result


def _validate_database(path: Path) -> None:
    if not path.is_file():
        raise ValueError("snapshot is missing the workflow SQLite database")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity check failed")
    finally:
        conn.close()


def verify_offline_snapshot(snapshot: Path, *, expected_manifest_sha256: str | None = None) -> dict:
    """Check every copied file against its manifest; not an external signature."""
    snapshot = Path(snapshot)
    files = _inventory(snapshot)
    manifest_path = files.pop(_MANIFEST, None)
    if manifest_path is None:
        raise ValueError("snapshot manifest missing")
    manifest_digest = _sha256(manifest_path)
    if expected_manifest_sha256 is not None:
        if (not isinstance(expected_manifest_sha256, str)
                or len(expected_manifest_sha256) != 64
                or any(c not in "0123456789abcdef" for c in expected_manifest_sha256)):
            raise ValueError("external manifest digest must be 64 lowercase hex characters")
        if manifest_digest != expected_manifest_sha256:
            raise ValueError("independently retained manifest digest mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "whaxon.e5.offline-snapshot.v1":
        raise ValueError("unknown snapshot schema")
    expected = manifest.get("sha256")
    if not isinstance(expected, dict) or set(expected) != set(files):
        raise ValueError("snapshot file inventory mismatch")
    for name, source in files.items():
        if not isinstance(expected[name], str) or _sha256(source) != expected[name]:
            raise ValueError(f"snapshot checksum mismatch: {name}")
    _validate_database(files[_DB] if _DB in files else snapshot / _DB)
    return {"file_count": len(files), "files_verified": True,
            "manifest_sha256": manifest_digest,
            "external_anchor_verified": expected_manifest_sha256 is not None}


def create_offline_snapshot(state_dir: Path, destination: Path) -> dict:
    """Snapshot an operator-stopped state directory, without trusting symlinks.

    This is OFFLINE-only. Stop both the web and workflow-worker services and
    independently preserve the returned manifest digest before use.
    """
    state_dir = Path(state_dir).resolve(strict=True)
    destination = Path(destination).resolve(strict=False)
    if not state_dir.is_dir() or not (state_dir / _DB).is_file():
        raise ValueError("state directory or workflow database missing")
    if destination.exists() or destination == state_dir or state_dir in destination.parents:
        raise ValueError("destination must be new and outside source state")
    source_files = _inventory(state_dir)
    if _MANIFEST in source_files:
        raise ValueError("source contains a reserved snapshot manifest name")
    if _DB not in source_files:
        raise ValueError("workflow database must be a regular file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".whaxon-e5-", dir=destination.parent))
    stage.chmod(0o700)
    try:
        for name, source in source_files.items():
            if name == _DB or name in _SIDECARS:
                continue
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            # Stream large evidence instead of loading it entirely into RAM.
            shutil.copyfile(source, target)
            target.chmod(0o600)
        with (
            closing(sqlite3.connect(f"file:{state_dir / _DB}?mode=ro", uri=True)) as db_source,
            closing(sqlite3.connect(stage / _DB)) as db_target,
        ):
            db_source.backup(db_target)
            db_target.commit()
        (stage / _DB).chmod(0o600)
        _validate_database(stage / _DB)
        copies = _inventory(stage)
        manifest = {
            "schema_version": "whaxon.e5.offline-snapshot.v1",
            "sha256": {name: _sha256(path) for name, path in copies.items()},
            "external_anchor_verified": False,
        }
        (stage / _MANIFEST).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (stage / _MANIFEST).chmod(0o600)
        verify_offline_snapshot(stage)
        os.replace(stage, destination)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return verify_offline_snapshot(destination)


def restore_offline_snapshot(snapshot: Path, destination: Path, *,
                             expected_manifest_sha256: str | None = None) -> dict:
    """Restore a verified snapshot into a new directory, never overwrite state."""
    snapshot = Path(snapshot)
    verified = verify_offline_snapshot(
        snapshot, expected_manifest_sha256=expected_manifest_sha256,
    )
    manifest_path = snapshot / _MANIFEST
    manifest_bytes = manifest_path.read_bytes()
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    if verified["manifest_sha256"] != manifest_digest:
        raise ValueError("snapshot manifest changed during verification")
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    expected_files = manifest["sha256"]

    snapshot = snapshot.resolve(strict=True)
    destination = Path(destination).resolve(strict=False)
    if destination.exists() or destination == snapshot or snapshot in destination.parents:
        raise ValueError("restore destination must be new and outside snapshot")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".whaxon-e5-restore-", dir=destination.parent))
    stage.chmod(0o700)
    try:
        entries = _inventory(snapshot)
        entries.pop(_MANIFEST, None)
        if set(entries) != set(expected_files):
            raise ValueError("snapshot file inventory mismatch")
        for name, source in entries.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            # Stream large evidence instead of loading it entirely into RAM.
            shutil.copyfile(source, target)
            target.chmod(0o600)
            if _sha256(target) != expected_files[name]:
                raise ValueError(f"snapshot checksum mismatch: {name}")
        _validate_database(stage / _DB)
        os.replace(stage, destination)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return verified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    for name in ("backup", "restore"):
        action = command.add_parser(name)
        action.add_argument("source", type=Path)
        action.add_argument("destination", type=Path)
    verify = command.add_parser("verify")
    verify.add_argument("source", type=Path)
    verify.add_argument("--expected-manifest-sha256")
    command.choices["restore"].add_argument("--expected-manifest-sha256")
    args = parser.parse_args()
    if args.command == "backup":
        result = create_offline_snapshot(args.source, args.destination)
    elif args.command == "restore":
        result = restore_offline_snapshot(
            args.source, args.destination,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
    else:
        result = verify_offline_snapshot(
            args.source, expected_manifest_sha256=args.expected_manifest_sha256,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
