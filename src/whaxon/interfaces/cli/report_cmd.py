"""whaxon report <job_id> — render a job as a report (md|html|pdf|json|whaxon)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from whaxon.core import Core
from whaxon.core.report import render_markdown, to_markdown, _load

FORMATS = ("md", "html", "pdf", "json", "whaxon")
EXT = {"md": ".md", "html": ".html", "pdf": ".pdf", "json": ".json", "whaxon": ".whaxon"}


def _try_import(name):
    try:
        mod = __import__("whaxon.core.report", fromlist=[name])
        return getattr(mod, name)
    except AttributeError:
        return None


def _render_payload(fmt, job, findings):
    if fmt == "html":
        from whaxon.core.report import render_html
        return render_html(job, findings), False
    if fmt == "json":
        return json.dumps({"job": job, "findings": findings or []}, indent=2, default=str), False
    if fmt == "whaxon":
        import hashlib
        body = json.dumps({"job": job, "findings": findings or []}, sort_keys=True, default=str).encode("utf-8")
        return json.dumps({"version": 1, "alg": "sha256",
                           "sha256": hashlib.sha256(body).hexdigest(),
                           "payload": json.loads(body.decode("utf-8"))}, indent=2, default=str), False
    return render_markdown(job, findings), False


def main(args=None):
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        print("Usage: whaxon report <job_id> [--out FILE] [--data DIR] [--format md|html|pdf|json|whaxon]\n"
              "       whaxon report --jobs id1,id2,id3 [--out FILE] [--format md|json|whaxon]")
        return
    job_id = args[0] if args and not args[0].startswith("--") else None
    out_path = None
    data_dir = Path("data")
    fmt = "md"
    jobs_filter = []
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
    if fmt not in FORMATS:
        print("Unknown format: " + fmt + ". Choose from " + ", ".join(FORMATS)); sys.exit(2)
    core = Core(data_dir=data_dir)
    payload = None
    is_bytes = False
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
                if sx in sev: sev[sx] += 1
                if f.get("kind") in _LOOT_KINDS:
                    loot.append({**f, "_job_id": entry["job"]["id"]})
        data["severity_counts"] = sev
        data["finding_count"] = sum(sev.values())
        data["job_count"] = len(data["jobs"])
        data["loot"] = loot
        if fmt == "md":
            payload = to_markdown(data)
        elif fmt == "json":
            payload = json.dumps(data, indent=2, default=str)
        elif fmt == "whaxon":
            import hashlib
            body = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
            payload = json.dumps({"version": 1, "alg": "sha256",
                                  "sha256": hashlib.sha256(body).hexdigest(),
                                  "payload": data}, indent=2, default=str)
        else:
            print(f"format {fmt} not supported with --jobs"); sys.exit(2)
    else:
        job = core.store.get(job_id)
        if job is None:
            print(f"No job with id {job_id}"); sys.exit(1)
        findings = core.store.get_findings(job_id) or []
        if fmt == "pdf":
            from whaxon.core.report import render_pdf
            try:
                payload = render_pdf(job, findings)
            except Exception as e:
                print(f"pdf render failed: {e}"); sys.exit(1)
            is_bytes = True
        else:
            payload, is_bytes = _render_payload(fmt, job, findings)
    if out_path is None:
        if not jobs_filter and job_id:
            out_path = Path(f"{job_id}{EXT[fmt]}")
        else:
            out_path = Path(f"whaxon-report{EXT[fmt]}")
    elif out_path.suffix == "":
        out_path = out_path.with_suffix(EXT[fmt])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if is_bytes:
        out_path.write_bytes(payload)
        print(f"Wrote {out_path} ({len(payload)} bytes)")
    else:
        out_path.write_text(payload, encoding="utf-8")
        print(f"Wrote {out_path} ({len(payload)} bytes)")


if __name__ == "__main__":
    main()
