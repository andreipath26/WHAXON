"""whaxon report <job_id> \u2014 render a job as a Markdown report."""
from __future__ import annotations

import sys
from pathlib import Path

from whaxon.core import Core
from whaxon.core.report import render_markdown, to_markdown, _load


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        print("Usage: whaxon report <job_id> [--out FILE] [--data DIR] [--format md|html]\n       whaxon report --jobs id1,id2,id3 [--out FILE]")
        return

    job_id = args[0] if args and not args[0].startswith("--") else None
    out_path: Path | None = None
    data_dir = Path("data")
    fmt = "md"
    jobs_filter: list[str] = []

    i = 0 if job_id is None else 1
    while i < len(args):
        if args[i] == "--out" and i + 1 < len(args):
            out_path = Path(args[i + 1]); i += 2
        elif args[i] == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]; i += 2
        elif args[i] == "--jobs" and i + 1 < len(args):
            jobs_filter = [j.strip() for j in args[i + 1].split(",") if j.strip()]; i += 2
        else:
            print(f"Unknown arg: {args[i]}"); sys.exit(2)

    core = Core(data_dir=data_dir)
    if jobs_filter:
        data = _load(core.store, "default")
        wanted = set(jobs_filter)
        data["jobs"] = [e for e in data["jobs"] if e["job"]["id"] in wanted]
        from whaxon.core.report import _SEV_ORDER, _LOOT_KINDS
        sev = {sx: 0 for sx in _SEV_ORDER}
        loot = []
        for entry in data["jobs"]:
            for f in entry["findings"]:
                sx = (f.get("severity") or "info").lower()
                if sx in sev:
                    sev[sx] += 1
                if f.get("kind") in _LOOT_KINDS:
                    loot.append({**f, "_job_id": entry["job"]["id"]})
        data["severity_counts"] = sev
        data["finding_count"] = sum(sev.values())
        data["job_count"] = len(data["jobs"])
        data["loot"] = loot
        md = to_markdown(data)
    else:
        job = core.store.get(job_id)
        if job is None:
            print(f"No job with id {job_id}"); sys.exit(1)
        findings = core.store.get_findings(job_id) or []
        if fmt == "html":
            from whaxon.core.report import render_html
            md = render_html(job, findings)
        else:
            md = render_markdown(job, findings)

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(md, encoding="utf-8")
        print(f"Wrote {out_path} ({len(md)} bytes)")
    else:
        sys.stdout.write(md)


if __name__ == "__main__":
    main()
