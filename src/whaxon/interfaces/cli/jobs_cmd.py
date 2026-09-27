"""whaxon jobs <export|list> ..."""
from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

from whaxon.core import Core


def _export(job_id: str, fmt: str, out: Path | None, data_dir: Path) -> None:
    core = Core(data_dir=data_dir)
    job = core.store.get(job_id)
    if job is None:
        print(f"No job with id {job_id}")
        sys.exit(1)
    if fmt == "txt":
        body = "\n".join((l.get("text") or "") for l in (job.get("lines") or []))
        binary = body.encode("utf-8")
    elif fmt == "csv":
        findings = core.store.get_findings(job_id) or []
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["kind", "severity", "source", "cvss", "cwe", "raw_line"])
        for f in findings:
            w.writerow([f.get("kind", ""), f.get("severity", ""), f.get("source", ""),
                        f.get("cvss") or "", f.get("cwe", ""),
                        (f.get("raw_line") or "").replace("\n", " ")])
        binary = buf.getvalue().encode("utf-8")
    elif fmt == "json":
        findings = core.store.get_findings(job_id) or []
        binary = json.dumps(findings, indent=2).encode("utf-8")
    else:
        print(f"Unknown format: {fmt}")
        sys.exit(2)

    if out is None:
        out = Path(f"job-{job_id}.{fmt}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(binary)
    print(f"Wrote {out} ({len(binary)} bytes)")


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        print("Usage: whaxon jobs export <job_id> [--format txt|csv|json] [--out FILE] [--data DIR]")
        return
    if args[0] == "export":
        args = args[1:]
    if not args:
        print("Usage: whaxon jobs export <job_id> [--format txt|csv|json] [--out FILE]")
        return
    job_id = args[0]
    fmt = "txt"
    out: Path | None = None
    data_dir = Path("data")
    i = 1
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]; i += 2
        elif args[i] == "--out" and i + 1 < len(args):
            out = Path(args[i + 1]); i += 2
        elif args[i] == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        else:
            print(f"Unknown arg: {args[i]}"); sys.exit(2)
    _export(job_id, fmt, out, data_dir)


if __name__ == "__main__":
    main()
