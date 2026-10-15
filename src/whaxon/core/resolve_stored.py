"""Retroactive severity resolution for stored findings.

The severity resolver (core/severity.py) runs on findings as they are
produced, before they are written to the store. Findings written before
the resolver existed still carry their original adapter severity.

This module walks the store and re-resolves each finding in place, using
the local vulnerability database. Idempotent: a second run finds nothing
new to change.
"""
from __future__ import annotations

import json
from typing import Any

from .severity import resolve
from .severity_policy import apply_ceiling


def _finding_dict(row) -> dict[str, Any]:
    try:
        data = json.loads(row["data_json"] or "{}")
    except Exception:
        data = {}
    try:
        enrich = json.loads(row["enrichment_json"] or "{}")
    except Exception:
        enrich = {}
    return {
        "kind": row["kind"],
        "severity": row["severity"],
        "source": row["source"],
        "data": data,
        "raw_line": row["raw_line"],
        "enrichment": enrich,
        "references": enrich.get("references") or [],
    }


def resolve_stored(store, vulndb, target_filter: str | None = None, log=print) -> dict:
    """Walk every finding, re-resolve severity, update in place.

    Returns a summary: findings scanned, changed, unchanged, by source.
    """
    c = store._conn()
    job_rows = c.execute(
        "SELECT id, target FROM jobs" + (" WHERE target = ?" if target_filter else ""),
        (target_filter,) if target_filter else (),
    ).fetchall()

    scanned = 0
    changed = 0
    nvd_set = 0
    adapter_kept = 0

    for j in job_rows:
        job_id = j["id"]
        f_rows = c.execute(
            "SELECT seq, kind, severity, source, data_json, raw_line, enrichment_json "
            "FROM findings WHERE job_id=? ORDER BY seq",
            (job_id,),
        ).fetchall()
        for f in f_rows:
            scanned += 1
            original = _finding_dict(f)
            resolved = resolve(original, vulndb)
            resolved = apply_ceiling(resolved)
            old_sev = original["severity"]
            new_sev = resolved.get("severity", old_sev)
            new_source = resolved.get("severity_source", "adapter")
            if new_source == "nvd":
                nvd_set += 1
            else:
                adapter_kept += 1

            # Enrichment carries severity_source, cvss, epss, kev.
            # Only carry cvss when it came from NVD. An adapter-assigned
            # cvss is a guess, not a score, and must not be presented as one.
            enrich = json.loads(f["enrichment_json"] or "{}")
            enrich["severity_source"] = new_source
            if resolved.get("business_impact"):
                enrich["business_impact"] = resolved["business_impact"]
            if new_source == "nvd":
                for k in ("cvss", "epss", "epss_percentile", "cve", "kev", "kev_ransomware", "business_impact"):
                    if k in resolved:
                        enrich[k] = resolved[k]
            else:
                enrich.pop("cvss", None)
                if "cve" in resolved:
                    enrich["cve"] = resolved["cve"]

            if new_sev != old_sev:
                changed += 1
            if resolved.get("severity_policy_applied"):
                enrich["severity_policy_applied"] = True
                enrich["severity_policy_ceiling"] = resolved.get("severity_policy_ceiling")
            c.execute(
                "UPDATE findings SET severity=?, enrichment_json=? WHERE job_id=? AND seq=?",
                (new_sev, json.dumps(enrich), job_id, f["seq"]),
            )
    c.commit()

    summary = {
        "scanned": scanned,
        "changed": changed,
        "unchanged": scanned - changed,
        "severity_from_nvd": nvd_set,
        "severity_from_adapter": adapter_kept,
    }
    log(
        f"resolved {scanned} findings: {changed} changed, {scanned - changed} unchanged "
        f"({nvd_set} from nvd, {adapter_kept} from adapter)"
    )
    return summary
