"""whaxon lookup — exploit-db lookup via searchsploit.

Wraps `searchsploit --json` for offline exploit search. Also provides
`--id` to show details for one exploit and `--copy` / `--save` to read
the exploit source (does NOT execute it).

No new dependencies. searchsploit is the local Exploit-DB mirror that
ships with Kali's `exploitdb` package.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


EXIT_OK = 0
EXIT_NO_SEARCHSPLOIT = 1
EXIT_NO_RESULTS = 2
EXIT_ID_NOT_FOUND = 3
EXIT_USAGE = 64


def _usage() -> None:
    print("Usage:")
    print("  whaxon lookup <query>            # search (e.g. 'apache 2.4.7')")
    print("  whaxon lookup --cve CVE-2021-44228")
    print("  whaxon lookup --id <EDB-ID>      # details for one exploit")
    print("  whaxon lookup --id <EDB-ID> --copy")
    print("  whaxon lookup --id <EDB-ID> --save PATH")
    print()
    print("Options:")
    print("  --json          emit JSON instead of a table")
    print("  --copy          print the exploit source to stdout (read-only)")
    print("  --save PATH     copy the exploit source to PATH")
    print("  --limit N       max results to show (default 25)")


def _searchsploit(*args: str) -> tuple[bool, dict | str]:
    """Run searchsploit --json with args. Returns (ok, parsed_or_error)."""
    if shutil.which("searchsploit") is None:
        return False, "searchsploit not found on PATH (install the 'exploitdb' package)"
    try:
        r = subprocess.run(
            ["searchsploit", "--json", *args],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return False, "searchsploit timed out after 30s"
    except Exception as e:
        return False, f"searchsploit failed: {e!r}"

    # searchsploit writes a warning to stderr and prints JSON to stdout
    out = r.stdout.strip()
    if not out:
        return False, f"searchsploit returned no output (stderr: {r.stderr.strip()[:200]})"
    try:
        return True, json.loads(out)
    except json.JSONDecodeError as e:
        return False, f"searchsploit output is not valid JSON: {e}"


def _results(data: dict) -> list[dict]:
    """Flatten RESULTS_EXPLOIT + RESULTS_SHELLCODE into one list."""
    out = []
    for row in (data.get("RESULTS_EXPLOIT") or []):
        row["_kind"] = "exploit"
        out.append(row)
    for row in (data.get("RESULTS_SHELLCODE") or []):
        row["_kind"] = "shellcode"
        out.append(row)
    return out


def _cve_list(codes: str) -> list[str]:
    if not codes:
        return []
    return [c.strip() for c in codes.split(";") if c.strip().upper().startswith("CVE-")]


def _fmt_row(row: dict) -> str:
    eid = row.get("EDB-ID", "?")
    title = row.get("Title", "")[:70]
    platform = row.get("Platform", "")[:10]
    etype = row.get("Type", "")[:8]
    cves = ",".join(_cve_list(row.get("Codes", "")))
    verified = "*" if row.get("Verified") == "1" else " "
    return f"  {verified} {eid:>6s}  {platform:<10s}  {etype:<8s}  {title}  {cves}".rstrip()


def _print_table(rows: list[dict], limit: int) -> None:
    if not rows:
        print("  (no results)")
        return
    shown = rows[:limit]
    for row in shown:
        print(_fmt_row(row))
    if len(rows) > limit:
        print(f"  ... and {len(rows) - limit} more (use --limit to raise)")


def _resolve_path(row: dict) -> Path | None:
    p = row.get("Path")
    if not p:
        return None
    path = Path(p)
    return path if path.exists() else None


def _show_one(row: dict) -> None:
    print(f"  Title:    {row.get('Title', '')}")
    print(f"  EDB-ID:   {row.get('EDB-ID', '')}")
    print(f"  URL:      https://www.exploit-db.com/exploits/{row.get('EDB-ID', '')}")
    print(f"  Type:     {row.get('Type', '')}")
    print(f"  Platform: {row.get('Platform', '')}")
    print(f"  Port:     {row.get('Port', '') or '-'}")
    print(f"  Author:   {row.get('Author', '')}")
    print(f"  Added:    {row.get('Date_Added', '')}")
    print(f"  Verified: {'yes' if row.get('Verified') == '1' else 'no'}")
    cves = _cve_list(row.get("Codes", ""))
    if cves:
        print(f"  CVEs:     {', '.join(cves)}")
    p = _resolve_path(row)
    print(f"  Path:     {p if p else '(not present on disk)'}")
    if row.get("Source"):
        print(f"  Source:   {row['Source']}")


def _find_by_id(edb_id: str) -> dict | None:
    """Search for an exact EDB-ID. Searchsploit searches by text, so we
    search for the ID string and filter results for an exact match."""
    ok, data = _searchsploit(edb_id)
    if not ok or not isinstance(data, dict):
        return None
    for row in _results(data):
        if str(row.get("EDB-ID", "")) == str(edb_id):
            return row
    return None


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        _usage()
        return

    query: str | None = None
    cve: str | None = None
    edb_id: str | None = None
    as_json = False
    do_copy = False
    save_path: Path | None = None
    limit = 25

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--json":
            as_json = True; i += 1
        elif a == "--copy":
            do_copy = True; i += 1
        elif a == "--save" and i + 1 < len(args):
            save_path = Path(args[i + 1]); i += 2
        elif a == "--cve" and i + 1 < len(args):
            cve = args[i + 1]; i += 2
        elif a == "--id" and i + 1 < len(args):
            edb_id = args[i + 1]; i += 2
        elif a == "--limit" and i + 1 < len(args):
            try:
                limit = int(args[i + 1])
            except ValueError:
                print(f"error: --limit expects an integer, got {args[i+1]!r}", file=sys.stderr)
                sys.exit(EXIT_USAGE)
            i += 2
        elif a.startswith("--"):
            print(f"Unknown arg: {a}", file=sys.stderr)
            sys.exit(EXIT_USAGE)
        else:
            if query is not None:
                print(f"error: unexpected extra argument {a!r}", file=sys.stderr)
                sys.exit(EXIT_USAGE)
            query = a
            i += 1

    # ---- Mode: show one exploit by ID ----
    if edb_id is not None:
        row = _find_by_id(edb_id)
        if row is None:
            print(f"No exploit with EDB-ID {edb_id}", file=sys.stderr)
            sys.exit(EXIT_ID_NOT_FOUND)

        if as_json:
            print(json.dumps(row, indent=2))
            return

        # When --copy is set, print only the exploit source. Metadata
        # would pollute stdout if someone pipes it to a file.
        # When --save is set without --copy, show metadata first.
        if do_copy and save_path is None:
            p = _resolve_path(row)
            if p is None:
                print("error: exploit file not present on disk", file=sys.stderr)
                sys.exit(EXIT_NO_RESULTS)
            sys.stdout.write(p.read_text(errors="replace"))
            return

        _show_one(row)

        if do_copy or save_path is not None:
            p = _resolve_path(row)
            if p is None:
                print("error: exploit file not present on disk", file=sys.stderr)
                sys.exit(EXIT_NO_RESULTS)
            if do_copy:
                sys.stdout.write(p.read_text(errors="replace"))
            if save_path is not None:
                save_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, save_path)
                print(f"Saved {save_path} ({save_path.stat().st_size} bytes)")
        return

    # ---- Mode: search ----
    if cve is not None:
        ok, data = _searchsploit("--cve", cve)
        label = cve
    elif query is not None:
        ok, data = _searchsploit(query)
        label = query
    else:
        print("error: whaxon lookup requires a query, --cve, or --id", file=sys.stderr)
        _usage()
        sys.exit(EXIT_USAGE)

    if not ok:
        print(f"error: {data}", file=sys.stderr)
        sys.exit(EXIT_NO_SEARCHSPLOIT)

    rows = _results(data) if isinstance(data, dict) else []

    if as_json:
        print(json.dumps({"query": label, "results": rows}, indent=2, default=str))
        return

    print(f"Search: {label}")
    print(f"Results: {len(rows)}")
    print()
    _print_table(rows, limit)

    if rows:
        print()
        print(f"To view: whaxon lookup --id {rows[0].get('EDB-ID', '<id>')}")


if __name__ == "__main__":
    main()