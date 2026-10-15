"""whaxon vulndb — manage the local vulnerability database.

Subcommands:
  whaxon vulndb status                       show row counts and last updates
  whaxon vulndb lookup <cve-id>              print one record
  whaxon vulndb update [--years 2024,2025]   download NVD, EPSS, KEV

The database lives at $WHAXON_DATA/vulndb.db (default data/vulndb.db).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_FOUND = 3


def _data_dir() -> Path:
    return Path(os.environ.get("WHAXON_DATA", "data"))


def _usage() -> None:
    print("Usage: whaxon vulndb <status|lookup|update> [args]")
    print("  status                      show row counts and last updates")
    print("  lookup <cve-id>             print one record")
    print("  update [--years 2024,2025]  download NVD, EPSS, KEV")
    print("  update --all                download all NVD years (slow)")


def main(args: list[str]) -> None:
    if not args or args[0] in ("--help", "-h", "help"):
        _usage()
        sys.exit(EXIT_OK if args else EXIT_USAGE)

    sub = args[0]
    rest = args[1:]

    if sub == "status":
        _status()
    elif sub == "lookup":
        _lookup(rest)
    elif sub == "update":
        _update(rest)
    else:
        print(f"Unknown vulndb subcommand: {sub}")
        _usage()
        sys.exit(EXIT_USAGE)


def _status() -> None:
    from ...core.vulndb import VulnDB
    db = VulnDB(_data_dir() / "vulndb.db")
    s = db.status()
    print(f"database:  {s['path']}")
    print(f"rows:      {s['rows']}")
    print(f"with cvss: {s['with_cvss']}")
    print(f"with epss: {s['with_epss']}")
    print(f"with kev:  {s['with_kev']}")
    print(f"nvd update: {s['last_nvd_update']}")
    print(f"epss update: {s['last_epss_update']}")
    print(f"kev update:  {s['last_kev_update']}")


def _lookup(args: list[str]) -> None:
    from ...core.vulndb import VulnDB
    if not args:
        print("Usage: whaxon vulndb lookup <cve-id>")
        sys.exit(EXIT_USAGE)
    cve_id = args[0].strip().upper()
    db = VulnDB(_data_dir() / "vulndb.db")
    rec = db.lookup(cve_id)
    if not rec:
        print(f"{cve_id}: not found in the local database.")
        print("Run `whaxon vulndb update` to populate it.")
        sys.exit(EXIT_NOT_FOUND)
    print(f"cve:               {rec['cve_id']}")
    print(f"cvss v3:           {rec.get('cvss_v3_score')} ({rec.get('cvss_v3_severity')})")
    print(f"cvss v4:           {rec.get('cvss_v4_score')} ({rec.get('cvss_v4_severity')})")
    print(f"epss score:        {rec.get('epss_score')}")
    print(f"epss percentile:   {rec.get('epss_percentile')}")
    print(f"kev:               {'yes' if rec.get('kev') else 'no'}")
    if rec.get("kev_ransomware"):
        print("kev ransomware:    yes")
    print(f"published:         {rec.get('published')}")
    print(f"modified:          {rec.get('modified')}")
    desc = rec.get("description") or ""
    if desc:
        print(f"description:       {desc[:400]}")


def _update(args: list[str]) -> None:
    from ...core.vulndb import VulnDB, update_all
    years = None
    i = 0
    while i < len(args):
        if args[i] == "--years" and i + 1 < len(args):
            years = [int(y.strip()) for y in args[i + 1].split(",") if y.strip()]
            i += 2
        elif args[i] == "--all":
            years = None
            i += 1
        else:
            print(f"Unknown flag: {args[i]}")
            _usage()
            sys.exit(EXIT_USAGE)
    db = VulnDB(_data_dir() / "vulndb.db")
    print(f"database: {db.path}")
    print(f"years: {years if years else 'all (2002-2026)'}")
    print("this may take a while on first run.")
    print()
    result = update_all(db, years=years)
    print()
    print(f"nvd:  {result['nvd']} rows processed")
    print(f"epss: {result['epss']} rows processed")
    print(f"kev:  {result['kev']} rows processed")
    print(f"done. total rows: {db.count()}")
