"""whaxon findings — cross-job lookup of everything found against a target.

Usage:
    whaxon findings                        # summary: every target with counts
    whaxon findings <target>               # detailed view of one target
    whaxon findings <target> --severity high
    whaxon findings <target> --kind open_port
    whaxon findings <target> --source nmap
    whaxon findings --json                 # full store output as JSON

Reads from core.store.findings_by_target(), which dedupes findings by
(kind, signature) and tracks a per-signature count across jobs.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from whaxon.core import Core

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _usage() -> None:
    print("Usage: whaxon findings [<target>] [options]")
    print()
    print("  Without a target: summary of every target the store has seen.")
    print("  With a target:    detailed findings for that target.")
    print()
    print("Options:")
    print("  --severity SEV    filter by severity (critical|high|medium|low|info)")
    print("  --kind KIND       filter by finding kind (open_port, web_issue, ...)")
    print("  --source TOOL     filter by source tool (nmap, nikto, ...)")
    print("  --json            emit raw store output as JSON")
    print("  --limit N         max jobs to scan (default 2000)")
    print("  --data DIR        data directory (default ./data)")


def _fmt_line(f: dict) -> str:
    sev = (f.get("severity") or "info").lower()
    kind = f.get("kind") or "?"
    raw = (f.get("raw_line") or "").strip().replace("\n", " ")[:100]
    count = f.get("count", 1)
    suffix = f" (x{count})" if count > 1 else ""
    return f"  [{sev:8s}] {kind:24s} {raw}{suffix}"


def _matches(f: dict, sev_filter: str | None,
             kind_filter: str | None, source_filter: str | None) -> bool:
    if sev_filter:
        # Show this severity or higher
        try:
            order_idx = _SEVERITY_ORDER.index(sev_filter.lower())
        except ValueError:
            return False
        f_sev = (f.get("severity") or "info").lower()
        try:
            f_idx = _SEVERITY_ORDER.index(f_sev)
        except ValueError:
            return True
        if f_idx > order_idx:
            return False
    if kind_filter and f.get("kind") != kind_filter:
        return False
    if source_filter and f.get("source") != source_filter:
        return False
    return True


def _print_summary(entries: list[dict]) -> None:
    if not entries:
        print("(no targets found in the store)")
        return
    # Column widths
    tw = max(len(e["target"]) for e in entries)
    tw = max(tw, 6)  # header width
    print(f"{'TARGET'.ljust(tw)}  JOBS  FINDINGS")
    print(f"{'-' * tw}  ----  --------")
    for e in sorted(entries, key=lambda x: -x["finding_count"]):
        t = e["target"].ljust(tw)
        print(f"{t}  {e['job_count']:4d}  {e['finding_count']:8d}")


def _print_detail(entry: dict, sev_filter, kind_filter, source_filter) -> None:
    target = entry["target"]
    findings = [f for f in entry["findings"]
                if _matches(f, sev_filter, kind_filter, source_filter)]

    print(f"target: {target}")
    print(f"jobs: {entry['job_count']}  findings: {len(findings)}")
    print()

    if not findings:
        print("(no findings match the filter)")
        return

    # Group by severity, in canonical order
    by_sev: dict = {}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        by_sev.setdefault(s, []).append(f)

    for sev in _SEVERITY_ORDER:
        bucket = by_sev.get(sev) or []
        if not bucket:
            continue
        print(f"[{sev}] ({len(bucket)})")
        for f in bucket:
            print(_fmt_line(f))
        print()


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    if args and args[0] in ("-h", "--help"):
        _usage()
        return

    target = None
    sev_filter = None
    kind_filter = None
    source_filter = None
    as_json = False
    limit = 2000
    data_dir = Path("data")

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--severity" and i + 1 < len(args):
            sev_filter = args[i + 1]; i += 2
        elif a == "--kind" and i + 1 < len(args):
            kind_filter = args[i + 1]; i += 2
        elif a == "--source" and i + 1 < len(args):
            source_filter = args[i + 1]; i += 2
        elif a == "--json":
            as_json = True; i += 1
        elif a == "--limit" and i + 1 < len(args):
            try:
                limit = int(args[i + 1])
            except ValueError:
                print(f"error: --limit expects an integer, got {args[i+1]!r}",
                      file=sys.stderr)
                sys.exit(64)
            i += 2
        elif a == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif a.startswith("--"):
            print(f"Unknown arg: {a}", file=sys.stderr)
            sys.exit(64)
        else:
            if target is not None:
                print(f"error: unexpected extra argument {a!r}", file=sys.stderr)
                sys.exit(64)
            target = a
            i += 1

    core = Core(data_dir=data_dir)
    entries = core.store.findings_by_target(limit=limit)

    if as_json:
        print(json.dumps(entries, indent=2, default=str))
        return

    if target is None:
        _print_summary(entries)
        return

    # Find the target
    entry = next((e for e in entries if e["target"] == target), None)
    if entry is None:
        print(f"target not found in store: {target}", file=sys.stderr)
        print("  run: whaxon findings", file=sys.stderr)
        sys.exit(1)

    _print_detail(entry, sev_filter, kind_filter, source_filter)


if __name__ == "__main__":
    main()