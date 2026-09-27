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
    return {
        "engagement": engagement or "default",
        "generated": _dt.datetime.now().isoformat(timespec="seconds"),
        "job_count": len(jobs),
        "finding_count": sum(sev_counts.values()),
        "severity_counts": sev_counts,
        "jobs": entries,
        "loot": loot_items,
    }


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


def to_markdown(report: dict[str, Any]) -> str:
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
    for sev in ("critical", "high"):
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

    md.append("## Job History\n")
    md.append("| Job | Tool | Target | Status | Exit |")
    md.append("|-----|------|--------|--------|------|")
    for entry in report["jobs"]:
        j = entry["job"]
        md.append(f"| `{j['id']}` | {j.get('tool','')} | {j.get('target','')} | "
                  f"{j.get('status','')} | {j.get('exit_code','')} |")
    md.append("")
    return "\n".join(md)


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, default=str)
