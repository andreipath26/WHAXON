#!/usr/bin/env python3
"""Download sqlmap source archive into third_party/ for review/build staging."""
import urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DEST=ROOT/"third_party"/"sqlmap-master.zip"
DEST.parent.mkdir(parents=True, exist_ok=True)
req=urllib.request.Request("https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip", headers={"User-Agent":"SecureLab-Asset-Fetcher/1.0"})
with urllib.request.urlopen(req, timeout=60) as r, DEST.open("wb") as f:
    total=0
    while True:
        chunk=r.read(1024*1024)
        if not chunk: break
        total+=len(chunk)
        if total>100*1024*1024: raise SystemExit("sqlmap archive exceeds 100 MiB")
        f.write(chunk)
print(f"Downloaded {DEST} ({DEST.stat().st_size:,} bytes). Review the upstream license and provide corresponding source when redistributing.")
