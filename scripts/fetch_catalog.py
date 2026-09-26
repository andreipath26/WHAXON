#!/usr/bin/env python3
"""Fetch an Exploit-DB metadata CSV to data/files_exploits.csv for offline use.

Run only when online; later import/refresh works without internet.
"""
import hashlib, urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data" / "files_exploits.csv"
DEST.parent.mkdir(parents=True, exist_ok=True)
tmp = DEST.with_suffix(".csv.part")
req = urllib.request.Request(URL, headers={"User-Agent": "SecureLab-Catalog/1.0"})
with urllib.request.urlopen(req, timeout=45) as response, tmp.open("wb") as out:
    total = 0
    while True:
        chunk = response.read(1024 * 1024)
        if not chunk: break
        total += len(chunk)
        if total > 100 * 1024 * 1024: raise SystemExit("Catalog download exceeds 100 MiB")
        out.write(chunk)
with tmp.open("rb") as f:
    digest = hashlib.sha256()
    for chunk in iter(lambda: f.read(1024 * 1024), b""): digest.update(chunk)
if tmp.stat().st_size < 100 or b"id,file,description" not in tmp.read_bytes()[:4096]:
    tmp.unlink(missing_ok=True)
    raise SystemExit("Downloaded file does not look like an Exploit-DB catalog")
tmp.replace(DEST)
print(f"Saved {DEST} ({DEST.stat().st_size:,} bytes; SHA-256 {digest.hexdigest()})")
