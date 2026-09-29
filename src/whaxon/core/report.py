"""Engagement report generation.

Reads from the WHAXON store and produces a Markdown or JSON report
covering every job and finding in an engagement.
"""
from __future__ import annotations

import datetime as _dt
import json
from typing import Any

# Severities in report order.
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# Loot-kind findings get a dedicated section.
_SESSION_SOURCES = {"msf_sysinfo", "msf_getuid", "msf_hashdump"}

_LOOT_KINDS = {
    "env_var", "sysinfo", "platform", "ntlm_hash", "service",
    "msf_session", "network_iface", "system_section",
    "exploit_suggestion", "msf_loot", "msf_loot_file",
}


def _load(store, engagement: str | None, limit: int = 500) -> dict[str, Any]:
    """Collect all jobs + findings for an engagement into one dict."""
    jobs = store.history(limit=limit)
    entries = []
    sev_counts = {s: 0 for s in _SEV_ORDER}
    loot_items = []
    session_findings = []
    for j in jobs:
        findings = store.get_findings(j["id"]) or []
        entries.append({
            "job": j,
            "findings": findings,
        })
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            if f.get("kind") in _LOOT_KINDS:
                loot_items.append({**f, "_job_id": j["id"]})
            if f.get("source") in _SESSION_SOURCES:
                session_findings.append({**f, "_job_id": j["id"]})
    ai_runs = _load_ai_runs(store)
    return {
        "engagement": engagement or "default",
        "generated": _dt.datetime.now().isoformat(timespec="seconds"),
        "job_count": len(jobs),
        "finding_count": sum(sev_counts.values()),
        "severity_counts": sev_counts,
        "jobs": entries,
        "loot": loot_items,
        "session_findings": session_findings,
        "ai_runs": ai_runs,
    }


def _load_ai_runs(store, limit: int = 20) -> list[dict[str, Any]]:
    """Collect recent AI runs with their phase + phase_history."""
    try:
        summaries = store.list_ai_runs(limit=limit) or []
    except Exception:
        return []
    runs = []
    for summary in summaries:
        rid = summary.get("id")
        if not rid:
            continue
        try:
            full = store.get_ai_run(rid) or {}
        except Exception:
            full = {}
        runs.append({
            "id": rid,
            "goal": summary.get("goal", ""),
            "status": summary.get("status", ""),
            "phase": full.get("phase") or summary.get("phase") or "recon",
            "phase_history": full.get("phase_history") or "[]",
            "step_count": len(full.get("steps") or []),
        })
    return runs


def _md_ai_runs(md: list[str], runs: list[dict]) -> None:
    if not runs:
        return
    md.append("## AI Runs\n")
    md.append("| Run | Goal | Phase | Status | Steps |")
    md.append("|-----|------|-------|--------|-------|")
    for r in runs:
        goal = (r.get("goal") or "").replace("|", "/")[:60]
        rid = r["id"]
        phase = r["phase"]
        status = r["status"]
        steps = r["step_count"]
        md.append(f"| `{rid}` | {goal} | {phase} | {status} | {steps} |")
    md.append("")
    for r in runs:
        try:
            hist = json.loads(r.get("phase_history") or "[]")
        except Exception:
            hist = []
        if len(hist) > 1:
            path = " -> ".join(h.get("phase", "?") for h in hist)
            rid = r["id"]
            md.append(f"- `{rid}` phase history: {path}")
    md.append("")


def _md_session_findings(md: list[str], findings: list[dict]) -> None:
    if not findings:
        return
    md.append("## Session Findings")
    md.append("Findings collected by acting inside an established Metasploit session.")
    md.append("")
    md.append("| Source | Detail | Session | Job |")
    md.append("|--------|--------|---------|-----|")
    for f in findings:
        d = f.get("data") or {}
        kind = f.get("kind") or ""
        if kind == "sysinfo":
            detail = str(d.get("field", "")) + ": " + str(d.get("value", ""))
        elif kind == "ntlm_hash":
            detail = str(d.get("user", "")) + " NT=" + str(d.get("nt_hash", ""))
        else:
            detail = (f.get("raw_line") or "")[:120]
        src = f.get("source", "")
        sid = d.get("session_id", "")
        job = f.get("_job_id", "")
        md.append("| " + str(src) + " | " + detail + " | " + str(sid) + " | " + str(job) + " |")
    md.append("")


def _md_loot(md: list[str], loot: list[dict]) -> None:
    by_kind: dict[str, list[dict]] = {}
    for f in loot:
        by_kind.setdefault(f.get("kind", "loot"), []).append(f)
    if not by_kind:
        return
    md.append("## Loot Summary\n")
    for kind in sorted(by_kind):
        items = by_kind[kind]
        md.append(f"### {kind} ({len(items)})\n")
        md.append("| Detail | Job |")
        md.append("|--------|-----|")
        for f in items:
            d = f.get("data") or {}
            if kind == "env_var":
                detail = f"{d.get('name','')} = {d.get('value','')}"
            elif kind in ("sysinfo", "platform"):
                detail = f"{d.get('field','platform')}: {d.get('value') or d.get('platform','')}"
            elif kind == "ntlm_hash":
                detail = f"{d.get('user','')} NT={d.get('nt_hash','')}"
            elif kind == "service":
                detail = f"{d.get('port','')}/{d.get('proto','')} {d.get('state','')} {d.get('name','')}"
            elif kind == "msf_session":
                detail = f"session {d.get('session_id','')} on {d.get('host','')}"
            elif kind == "exploit_suggestion":
                detail = f"{d.get('module_type','')}/{d.get('module','')}"
            elif kind == "network_iface":
                detail = f"{d.get('ip','')}/{d.get('cidr','')}"
            else:
                detail = (f.get("raw_line") or json.dumps(d))[:200]
            # escape pipes
            detail = detail.replace("|", "\\|")
            md.append(f"| {detail} | {f.get('_job_id','')} |")
        md.append("")


def to_markdown(report: dict[str, Any], chains: list | None = None,
                all_findings: bool = False, lookup: bool = True) -> str:
    md: list[str] = []
    md.append("# WHAXON Engagement Report\n")
    md.append(f"Scope: **{report['engagement']}**  ")
    md.append(f"Generated: {report['generated']}  ")
    md.append(f"Jobs: {report['job_count']}  Findings: {report['finding_count']}\n")

    md.append("## Executive Summary\n")
    for sev in _SEV_ORDER:
        n = report["severity_counts"].get(sev, 0)
        if n:
            md.append(f"- **{sev.capitalize()}**: {n}")
    md.append("")

    # Critical + high in detail up top
    detail_sevs = list(_SEV_ORDER) if all_findings else ["critical", "high"]
    for sev in detail_sevs:
        bucket = []
        for entry in report["jobs"]:
            for f in entry["findings"]:
                if (f.get("severity") or "").lower() == sev:
                    bucket.append((entry["job"], f))
        if not bucket:
            continue
        md.append(f"## {sev.capitalize()} Findings\n")
        for job, f in bucket:
            raw = (f.get("raw_line") or "").strip().replace("\n", " ")[:200]
            md.append(f"- **[{sev}]** {raw}  _(job `{job['id']}` tool `{job['tool']}`)_")
        md.append("")

    _md_loot(md, report["loot"])

    _md_session_findings(md, report.get("session_findings") or [])

    if lookup:
        _md_lookup(md, report)

    _md_chains(md, chains or [])

    _md_ai_runs(md, report.get("ai_runs") or [])

    md.append("## Job History\n")
    md.append("| Job | Tool | Target | Status | Exit |")
    md.append("|-----|------|--------|--------|------|")
    for entry in report["jobs"]:
        j = entry["job"]
        md.append(f"| `{j['id']}` | {j.get('tool','')} | {j.get('target','')} | "
                  f"{j.get('status','')} | {j.get('exit_code','')} |")
    md.append("")
    return "\n".join(md)



# Cache searchsploit results within a single report render.
_LOOKUP_CACHE: dict = {}


def _searchsploit_json(hint, timeout=10.0):
    """Run searchsploit --json <hint>. Returns parsed dict or None."""
    if hint in _LOOKUP_CACHE:
        return _LOOKUP_CACHE[hint]
    import json as _json
    import shutil
    import subprocess
    if shutil.which("searchsploit") is None:
        _LOOKUP_CACHE[hint] = None
        return None
    try:
        r = subprocess.run(
            ["searchsploit", "--json", hint],
            capture_output=True, text=True, timeout=timeout,
        )
        if not r.stdout.strip():
            _LOOKUP_CACHE[hint] = None
            return None
        data = _json.loads(r.stdout)
        _LOOKUP_CACHE[hint] = data
        return data
    except Exception:
        _LOOKUP_CACHE[hint] = None
        return None


def _md_lookup(md, report, per_hint_limit=5):
    """Render a Known Vulnerabilities section for findings with hints."""
    hints = set()
    for entry in report.get("jobs") or []:
        for f in entry.get("findings") or []:
            h = (f.get("lookup_hint") or "").strip()
            if h:
                hints.add(h)
    if not hints:
        return

    md.append("## Known Vulnerabilities\n")
    md.append(
        "Service versions detected during the engagement, cross-referenced "
        "against the local Exploit-DB mirror. This is a starting point for "
        "manual review, not a definitive list.\n"
    )

    for hint in sorted(hints):
        data = _searchsploit_json(hint)
        md.append("### " + hint + "\n")
        if not data:
            md.append("_No local searchsploit results (mirror may be stale)._")
            md.append("")
            continue
        rows = data.get("RESULTS_EXPLOIT") or []
        if not rows:
            md.append("_No results._")
            md.append("")
            continue
        md.append("Matches: " + str(len(rows)))
        md.append("")
        md.append("| EDB-ID | Title | CVEs |")
        md.append("|--------|-------|------|")
        for row in rows[:per_hint_limit]:
            eid = row.get("EDB-ID", "?")
            title = (row.get("Title") or "")[:70].replace("|", "\\|")
            codes = row.get("Codes") or ""
            cves = ",".join(
                c.strip() for c in codes.split(";")
                if c.strip().upper().startswith("CVE-")
            )
            md.append("| " + eid + " | " + title + " | " + cves + " |")
        if len(rows) > per_hint_limit:
            md.append("")
            md.append("_" + str(len(rows) - per_hint_limit) + " more results not shown._")
        md.append("")


def _md_chains(md, chains):
    """Render the pivot chain tree into the report."""
    if not chains:
        return
    md.append("## Pivot Chains\n")
    for c in chains:
        root = c.get("root", {})
        md.append(f"- **{root.get('kind','?')} `{root.get('id','?')}`**"
                  + (f" — {root.get('evidence','')}" if root.get("evidence") else ""))
        for d in c.get("descendants", []):
            rel = d.get("relation", "?")
            arrow = "→" if rel == "from_exploit" else "↳"
            child = d.get("child", {})
            ev = d.get("evidence", "")
            line = f"  {arrow} {child.get('kind','?')} `{child.get('id','?')}`"
            if ev:
                line += f"  ({ev})"
            md.append(line)
    md.append("")

def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, default=str)



# ─── CLI entrypoints (per-job reports) ──────────────────────────────

def _md_next_steps(md: list, findings: list) -> None:
    """Render suggestion-kind findings as a Next steps section."""
    suggestions = [f for f in findings if f.get('kind') == 'suggestion']
    if not suggestions:
        return
    md.append('## Next steps\n')
    for f in suggestions:
        d = f.get('data') or {}
        label = d.get('label') or f.get('raw_line') or 'unspecified'
        tool = d.get('tool') or ''
        extra = d.get('extra_args') or ''
        line = '- ' + label
        if tool:
            line += '  (tool: `' + tool + '`'
            if extra:
                line += ', args: `' + extra + '`'
            line += ')'
        md.append(line)
    md.append('')


def render_markdown(job: dict, findings: list[dict]) -> str:
    """Render a single job + its findings as Markdown. Used by whaxon report."""
    md: list[str] = []
    md.append(f"# Job {job.get('id','')}\n")
    md.append(f"- **Tool**: {job.get('tool','')}")
    md.append(f"- **Target**: {job.get('target','')}")
    md.append(f"- **Status**: {job.get('status','')}  exit={job.get('exit_code','')}")
    md.append(f"- **Started**: {job.get('started_at','')}")
    md.append("")
    if findings:
        md.append(f"## Findings ({len(findings)})\n")
        for f in findings:
            sev = (f.get('severity') or 'info').upper()
            raw = (f.get('raw_line') or '').strip().replace('\n', ' ')
            raw = ' '.join(raw.split())[:500]
            md.append(f"- **[{sev}]** `{f.get('kind','')}` — {raw}")
        md.append("")
        _md_next_steps(md, findings)
    else:
        md.append("_No findings recorded._\n")
    return "\n".join(md)


def render_html(job: dict, findings: list[dict]) -> str:
    """Same as render_markdown but wrapped in a <pre> so a browser renders it.

    The markdown (including raw_line, which may contain attacker-controlled
    text from tool output) is HTML-escaped before wrapping. Without this,
    a raw_line containing "<script>" would be interpreted by the browser.
    """
    import html as _html
    md = render_markdown(job, findings)
    return (
        "<pre style=\"font-family:ui-monospace,monospace\">"
        + _html.escape(md)
        + "</pre>"
    )


def to_pdf_bytes(markdown_text: str) -> bytes:
    """Render markdown to PDF via pandoc (md->html) + weasyprint (html->pdf)."""
    import shutil, subprocess, tempfile
    from pathlib import Path

    pandoc = shutil.which("pandoc")
    weasy = shutil.which("weasyprint")
    if not pandoc or not weasy:
        raise RuntimeError(
            "PDF export requires pandoc and weasyprint on PATH "
            f"(pandoc={pandoc}, weasyprint={weasy})"
        )

    with tempfile.TemporaryDirectory() as td:
        md_path = Path(td) / "report.md"
        html_path = Path(td) / "report.html"
        pdf_path = Path(td) / "report.pdf"
        md_path.write_text(markdown_text, encoding="utf-8")
        css = ("body{font-family:sans-serif;max-width:800px;margin:2em auto;}"
               "pre{background:#f4f4f4;padding:1em;}"
               "table{border-collapse:collapse;}"
               "td,th{border:1px solid #ccc;padding:4px 8px;}")
        subprocess.run(
            [pandoc, str(md_path), "-o", str(html_path), "--standalone",
             "--metadata", "title=WHAXON Report",
             "--css", "data:text/css," + css],
            check=True, capture_output=True,
        )
        subprocess.run([weasy, str(html_path), str(pdf_path)],
                       check=True, capture_output=True)
        return pdf_path.read_bytes()


def render_pdf(job: dict, findings: list[dict]) -> bytes:
    return to_pdf_bytes(render_markdown(job, findings))


def attach_chains(store):
    """Collect pivot chains. Returns [] on any failure."""
    try:
        from whaxon.core import pivot as _pivot
        conn = store._conn()
        try:
            edges = _pivot.list_edges(conn)
        finally:
            try: conn.close()
            except Exception: pass
        sessions = sorted({e["child"]["id"] for e in edges
                           if e["child"]["kind"] == "session"
                           and e["relation"] == "from_exploit"})
        chains = []
        for sid in sessions:
            try:
                conn = store._conn()
                try:
                    chain = _pivot.chain_for_session(conn, sid)
                finally:
                    try: conn.close()
                    except Exception: pass
                for root in chain.get("root_exploits", []):
                    chains.append({
                        "root": root["parent"],
                        "descendants": chain.get("descendants", []),
                    })
            except Exception:
                pass
        return chains
    except Exception:
        return []
