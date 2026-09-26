"""Safe local Exploit-DB catalog import and manifest-based catalog updates."""
from __future__ import annotations
import csv, hashlib, json, os, tempfile, urllib.request, zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

MAX_CATALOG_BYTES = 100 * 1024 * 1024
REQUIRED_COLUMNS = {"id", "file", "description"}


def validate_csv(path: Path) -> tuple[int, str]:
    if not path.is_file() or path.stat().st_size == 0 or path.stat().st_size > MAX_CATALOG_BYTES:
        raise ValueError("Catalog file is empty or exceeds the 100 MiB limit.")
    digest = hashlib.sha256()
    with path.open("rb") as raw:
        for chunk in iter(lambda: raw.read(1024 * 1024), b""):
            digest.update(chunk)
    with path.open("r", encoding="utf-8-sig", errors="strict", newline="") as f:
        reader = csv.DictReader(f)
        columns = {str(x or "").strip().lower() for x in (reader.fieldnames or [])}
        if not REQUIRED_COLUMNS.issubset(columns):
            raise ValueError("CSV is not an Exploit-DB files_exploits.csv (missing required columns).")
        count = sum(1 for _ in reader)
    if count < 1:
        raise ValueError("Catalog contains no records.")
    return count, digest.hexdigest()


def _extract_catalog(source: Path, scratch: Path) -> Path:
    if source.suffix.lower() == ".csv":
        return source
    if source.suffix.lower() != ".zip":
        raise ValueError("Upload a CSV or ZIP containing files_exploits.csv.")
    with zipfile.ZipFile(source) as zf:
        candidates = [n for n in zf.namelist() if Path(n).name.lower() == "files_exploits.csv" and not n.endswith("/")]
        if not candidates:
            raise ValueError("ZIP does not contain files_exploits.csv.")
        info = zf.getinfo(candidates[0])
        if info.file_size > MAX_CATALOG_BYTES:
            raise ValueError("Catalog exceeds the 100 MiB limit.")
        target = scratch / "imported_files_exploits.csv"
        with zf.open(info) as src, target.open("wb") as dst:
            total = 0
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk: break
                total += len(chunk)
                if total > MAX_CATALOG_BYTES: raise ValueError("Catalog exceeds the 100 MiB limit.")
                dst.write(chunk)
        return target


def install_catalog(source: Path, catalog_dir: Path) -> dict:
    catalog_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="catalog-stage-") as tmp:
        staged = _extract_catalog(source, Path(tmp))
        count, digest = validate_csv(staged)
        dest = catalog_dir / "files_exploits.csv"
        temp_dest = catalog_dir / "files_exploits.csv.new"
        with staged.open("rb") as src, temp_dest.open("wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk: break
                dst.write(chunk)
            dst.flush(); os.fsync(dst.fileno())
        os.replace(temp_dest, dest)
    meta = {"records": count, "sha256": digest, "updated_utc": datetime.now(timezone.utc).isoformat(), "source": source.name}
    meta_path = catalog_dir / "catalog_metadata.json"
    meta_tmp = meta_path.with_suffix(".json.new")
    meta_tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    os.replace(meta_tmp, meta_path)
    return meta


def fetch_update_manifest(manifest_url: str) -> dict:
    p = urlparse(manifest_url)
    if p.scheme != "https" or not p.hostname or p.username or p.password:
        raise ValueError("Update manifest URL must be HTTPS and contain no embedded credentials.")
    req = urllib.request.Request(manifest_url, headers={"User-Agent": "SecureLab-Updater/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        payload = resp.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024: raise ValueError("Update manifest is larger than 1 MiB.")
    data = json.loads(payload.decode("utf-8"))
    if not isinstance(data, dict) or not data.get("latest_version"):
        raise ValueError("Manifest must be a JSON object with latest_version.")
    return data


def update_catalog_from_manifest(manifest: dict, catalog_dir: Path) -> dict:
    url = manifest.get("catalog_url")
    expected = str(manifest.get("catalog_sha256", "")).lower()
    p = urlparse(str(url or ""))
    if p.scheme != "https" or not p.hostname or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("Manifest must provide an HTTPS catalog_url and a valid catalog_sha256.")
    catalog_dir.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="catalog-download-", suffix=".csv", dir=catalog_dir)
    os.close(fd); tmp = Path(name)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecureLab-Updater/1.0"})
        total = 0
        with urllib.request.urlopen(req, timeout=60) as resp, tmp.open("wb") as out:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk: break
                total += len(chunk)
                if total > MAX_CATALOG_BYTES: raise ValueError("Downloaded catalog exceeds the 100 MiB limit.")
                out.write(chunk)
        count, actual = validate_csv(tmp)
        if actual != expected: raise ValueError("Catalog SHA-256 does not match the update manifest.")
        return install_catalog(tmp, catalog_dir)
    finally:
        tmp.unlink(missing_ok=True)
