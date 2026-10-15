"""Post-parse severity resolution.

The adapter proposes a severity. This module decides the final one.

When a finding carries a CVE identifier, the severity comes from the
CVSS base score in the local vulnerability database. When it does not,
or the CVE has no CVSS score on record, the adapter's severity stands.

Every finding is annotated with the source of its severity:

    severity_source = "nvd"      CVSS base score from the vulndb
    severity_source = "adapter"  the adapter's original assignment

EPSS score, EPSS percentile, and CISA KEV membership are also copied
onto the finding when the CVE is on record. They do not set severity.
They feed the priority computation (report redesign PR 3).

Design ref: docs/report-redesign.md section 1e.
"""
from __future__ import annotations

import re
from typing import Any

from .business_impact import base_band as _business_band

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _normalize(finding):
    """Accept either a Finding object or a dict. Return a dict."""
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return finding


def extract_cve(finding) -> str | None:
    """Return the first CVE identifier found on the finding, or None.

    Checks, in order: the enrichment references, the data dict (as
    'cve' key or anywhere in serialized form), and the raw_line.
    """
    finding = _normalize(finding)
    enrich = finding.get("enrichment") or {}
    refs = enrich.get("references") or finding.get("references") or []
    for ref in refs:
        m = CVE_RE.search(str(ref))
        if m:
            return m.group(0).upper()

    data = finding.get("data") or {}
    if isinstance(data, dict):
        cve_field = data.get("cve")
        if isinstance(cve_field, str):
            m = CVE_RE.search(cve_field)
            if m:
                return m.group(0).upper()
        blob = str(data)
        m = CVE_RE.search(blob)
        if m:
            return m.group(0).upper()

    raw = finding.get("raw_line") or ""
    m = CVE_RE.search(raw)
    if m:
        return m.group(0).upper()

    return None


def cvss_to_severity(score: float | None) -> str:
    """NVD qualitative severity bands."""
    if score is None or score == 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _annotate(out: dict[str, Any]) -> dict[str, Any]:
    """Attach the business-impact band to a resolved finding."""
    try:
        out["business_impact"] = _business_band(out)
    except Exception:
        out["business_impact"] = "low"
    return out


def resolve(finding, vulndb) -> dict[str, Any]:
    """Return a copy of the finding with severity resolved from CVSS when possible.

    Accepts either a Finding object or a dict. Returns a dict.
    """
    out = dict(_normalize(finding))
    out.setdefault("severity_source", "adapter")

    cve = extract_cve(finding)
    if not cve:
        return _annotate(out)

    record = vulndb.lookup(cve)
    if not record:
        out["cve"] = cve
        return _annotate(out)

    out["cve"] = cve
    score = record.get("cvss_v3_score")
    if score is None:
        score = record.get("cvss_v4_score")
    if score is not None:
        out["severity"] = cvss_to_severity(score)
        out["cvss"] = score
        out["severity_source"] = "nvd"

    if record.get("epss_score") is not None:
        out["epss"] = record["epss_score"]
    if record.get("epss_percentile") is not None:
        out["epss_percentile"] = record["epss_percentile"]
    if record.get("kev"):
        out["kev"] = True
        if record.get("kev_ransomware"):
            out["kev_ransomware"] = True

    return _annotate(out)


def priority(finding) -> str:
    """Compute a priority band from CVSS + EPSS + KEV.

    Accepts either a Finding object or a dict.
    HIGH    if KEV, or EPSS > 0.2, or CVSS >= 9.0
    MEDIUM  if EPSS > 0.05 or CVSS >= 7.0
    LOW     otherwise
    """
    finding = _normalize(finding)
    if finding.get("kev"):
        return "high"
    epss = finding.get("epss")
    cvss = finding.get("cvss")
    if epss is not None and epss > 0.2:
        return "high"
    if cvss is not None and cvss >= 9.0:
        return "high"
    if epss is not None and epss > 0.05:
        return "medium"
    if cvss is not None and cvss >= 7.0:
        return "medium"
    return "low"
