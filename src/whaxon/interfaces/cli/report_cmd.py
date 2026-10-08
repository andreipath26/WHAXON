"""whaxon report <job_id> — render a job as a report (md|html|pdf|json|whaxon).

Two modes:
  - Per-job:    whaxon report <job_id> --format md|html|pdf|json
  - Engagement: whaxon report --engagement NAME --format md|pdf|json|whaxon
                whaxon report --all --format md|pdf|json|whaxon

The whaxon format is engagement-wide and mirrors /api/report?format=whaxon.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from whaxon.core import Core
from whaxon.core.report import (
    _load,
    attach_chains,
    render_html,
    render_markdown,
    render_pdf,
    to_markdown,
    to_pdf_bytes,
)

FORMATS = ("md", "html", "pdf", "json", "whaxon")
EXT = {"md": ".md", "html": ".html", "pdf": ".pdf", "json": ".json", "whaxon": ".whaxon"}
ENGAGEMENT_FORMATS = ("md", "pdf", "json", "whaxon")
JOB_FORMATS = ("md", "html", "pdf", "json")


def _use_color(stream):
    return stream.isatty() and os.environ.get("NO_COLOR") is None


def _ok(s):
    return ("\033[32m" + s + "\033[0m") if _use_color(sys.stdout) else s


def _warn(s):
    return ("\033[33m" + s + "\033[0m") if _use_color(sys.stderr) else s


def _fail(s):
    return ("\033[31m" + s + "\033[0m") if _use_color(sys.stderr) else s


def _find_clipboard_tool():
    import shutil
    for name, cmd in [
        ("wl-copy", ["wl-copy"]),
        ("xclip", ["xclip", "-selection", "clipboard"]),
        ("xsel", ["xsel", "--clipboard", "--input"]),
    ]:
        if shutil.which(name):
            return cmd
    return None


def _copy_to_clipboard(text):
    cmd = _find_clipboard_tool()
    if cmd is None:
        return False, "no clipboard tool found (install wl-copy, xclip, or xsel)"
    import subprocess
    try:
        subprocess.run(cmd, input=text.encode("utf-8"), check=True)
        return True, cmd[0]
    except Exception as e:
        return False, cmd[0] + " failed: " + str(e)


def _open_file(path):
    import shutil
    import subprocess
    for name in ("xdg-open", "open", "start"):
        if shutil.which(name):
            try:
                subprocess.Popen([name, str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True, name
            except Exception as e:
                return False, name + " failed: " + str(e)
    return False, "no file opener found (install xdg-utils)"


def _render_job(fmt, job, findings):
    if fmt == "html":
        return render_html(job, findings), False
    if fmt == "pdf":
        return render_pdf(job, findings), True
    if fmt == "json":
        return json.dumps({"job": job, "findings": findings or []}, indent=2, default=str), False
    return render_markdown(job, findings), False


def _build_envelope(data, eng):
    from whaxon import __version__ as _v
    canonical = json.dumps(data, default=str, sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    envelope = {
        "format": "whaxon",
        "version": 1,
        "generated": data.get("generated"),
        "tool": "whaxon/" + _v,
        "engagement": eng,
        "integrity": "sha256:" + digest,
        "payload": data,
    }
    return json.dumps(envelope, default=str, indent=2)


def _build_aggregate(core, eng, jobs_filter):
    data = _load(core.store, eng)
    if jobs_filter:
        wanted = set(jobs_filter)
        data["jobs"] = [e for e in data["jobs"] if e["job"]["id"] in wanted]
        from whaxon.core.report import _LOOT_KINDS, _SEV_ORDER
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
    data["chains"] = attach_chains(core.store)
    return data


def _render_engagement(fmt, data, eng, all_findings=False):
    if fmt == "html":
        print(_warn("engagement-level html is not supported; use --format md or the web UI"), file=sys.stderr)
        sys.exit(2)
    if fmt == "json":
        return json.dumps(data, default=str, separators=(",", ":")) + "\n", False
    if fmt == "whaxon":
        return _build_envelope(data, eng), False
    md = to_markdown(data, chains=data.get("chains", []), all_findings=all_findings)
    if fmt == "pdf":
        try:
            return to_pdf_bytes(md), True
        except Exception as e:
            print(_fail("pdf render failed: " + str(e)), file=sys.stderr)
            sys.exit(1)
    return md, False


def main(args=None):
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        print("Usage:")
        print("  whaxon report <job_id> [--out FILE] [--data DIR] [--format md|html|pdf|json]")
        print("  whaxon report --engagement NAME [--out FILE] [--jobs id1,id2] [--format md|pdf|json|whaxon]")
        print("  whaxon report --all [--out FILE] [--jobs id1,id2] [--format md|pdf|json|whaxon]")
        print()
        print("  --engagement NAME  engagement name (default: default)")
        print("  --all              alias for --engagement default")
        print("  --jobs id1,id2     restrict to these job ids")
        print("  --format FORMAT    md | html | pdf | json | whaxon")
        print("  --out FILE         write to FILE (default: derived from job/format)")
        print("  --data DIR         data directory (default: ./data)")
        print("  --open             open the report in the default viewer")
        print("  --clipboard        copy the report text to the system clipboard")
        print("  --all-findings     show every finding, not just critical/high")
        return

    job_id = args[0] if args and not args[0].startswith("--") else None
    out_path = None
    data_dir = Path("data")
    fmt = "md"
    jobs_filter = []
    engagement = None
    open_after = False
    clipboard = False
    all_findings = False

    i = 0 if job_id is None else 1
    while i < len(args):
        a = args[i]
        if a == "--out" and i + 1 < len(args):
            out_path = Path(args[i + 1]); i += 2
        elif a == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif a == "--format" and i + 1 < len(args):
            fmt = args[i + 1]; i += 2
        elif a == "--jobs" and i + 1 < len(args):
            jobs_filter = [j.strip() for j in args[i + 1].split(",") if j.strip()]; i += 2
        elif a == "--engagement" and i + 1 < len(args):
            engagement = args[i + 1]; i += 2
        elif a == "--all":
            if engagement is None:
                engagement = "default"
            i += 1
        elif a == "--open":
            open_after = True; i += 1
        elif a == "--clipboard":
            clipboard = True; i += 1
        elif a == "--all-findings":
            all_findings = True; i += 1
        else:
            print(_fail("Unknown arg: " + a), file=sys.stderr)
            sys.exit(2)

    if fmt not in FORMATS:
        print(_fail("Unknown format: " + fmt + ". Choose from " + ", ".join(FORMATS)), file=sys.stderr)
        sys.exit(2)

    is_engagement_mode = engagement is not None or bool(jobs_filter)
    if is_engagement_mode and engagement is None:
        engagement = "default"

    if fmt == "whaxon" and engagement is None:
        print(_warn("whaxon format is engagement-wide; use --engagement NAME or --all"), file=sys.stderr)
        sys.exit(2)

    core = Core(data_dir=data_dir)

    if is_engagement_mode:
        if fmt not in ENGAGEMENT_FORMATS:
            print(_fail("format " + fmt + " not supported at engagement level; use --engagement with one of: " + ", ".join(ENGAGEMENT_FORMATS)), file=sys.stderr)
            sys.exit(2)
        data = _build_aggregate(core, engagement, jobs_filter)
        payload, is_bytes = _render_engagement(fmt, data, engagement, all_findings=all_findings)
        default_out = "whaxon-report" + EXT[fmt]
    else:
        if fmt not in JOB_FORMATS:
            print(_warn("format " + fmt + " requires an engagement; use --engagement NAME or --all"), file=sys.stderr)
            sys.exit(2)
        if not job_id:
            print(_fail("no job_id given and no --engagement specified"), file=sys.stderr)
            sys.exit(2)
        job = core.store.get(job_id)
        if job is None:
            print(_fail("No job with id " + job_id), file=sys.stderr)
            sys.exit(1)
        findings = core.store.get_findings(job_id) or []
        payload, is_bytes = _render_job(fmt, job, findings)
        default_out = job_id + EXT[fmt]

    if out_path is None:
        out_path = Path(default_out)
    elif out_path.suffix == "":
        out_path = out_path.with_suffix(EXT[fmt])

    # --open / --clipboard need a file. Force default path if stdout would be used.
    if (open_after or clipboard) and out_path is None:
        if is_engagement_mode:
            out_path = Path("whaxon-report" + EXT[fmt])
        else:
            out_path = Path(job_id + EXT[fmt])

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if is_bytes:
        out_path.write_bytes(payload)
    else:
        out_path.write_text(payload, encoding="utf-8")
    print(_ok("Wrote " + str(out_path) + " (" + str(len(payload)) + " bytes, " + fmt + ")"))

    # Post-processing: --open, --clipboard
    if open_after or clipboard:
        if is_bytes and clipboard:
            print(_warn("--clipboard is not supported for binary formats; skipping"), file=sys.stderr)
        elif clipboard and not is_bytes:
            ok, detail = _copy_to_clipboard(payload)
            if ok:
                print(_ok("Copied to clipboard (" + detail + ")"))
            else:
                print(_warn("clipboard: " + detail), file=sys.stderr)
        if open_after:
            ok, detail = _open_file(out_path)
            if ok:
                print(_ok("Opened with " + detail))
            else:
                print(_warn("open: " + detail), file=sys.stderr)


if __name__ == "__main__":
    main()
