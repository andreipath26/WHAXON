"""Nuclei adapter — template-driven vulnerability findings with enrichment.

Nuclei output lines look like:
    [critical] [CVE-2021-44228] https://target/path
or with extra key=value metadata after the URL:
    [high] [tech-detect:nginx] https://target/ [nginx]
"""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register


_NUCLEI_RE = re.compile(
    r"^\[(?P<sev>info|low|medium|high|critical|unknown)\]\s*"
    r"\[(?P<id>[^\]]+)\]\s+"
    r"(?P<url>\S+)"
    r"(?:\s+\[(?P<extract>[^\]]+)\])?"
)


# CVSS 3.1 base scores by severity tier. Nuclei reports severity, not score.
_SEV_TO_CVSS = {
    "critical": 9.8,
    "high": 7.5,
    "medium": 5.3,
    "low": 3.7,
    "info": None,
    "unknown": None,
}

# CWE mapping for the most common template id families. Falls back to
# CWE-200 (information disclosure) when no specific mapping applies.
_CWE_BY_TEMPLATE_PREFIX = {
    "cve-": "CWE-1395",  # unclassified vulnerability in a dependency
    "sqli": "CWE-89",
    "sql-injection": "CWE-89",
    "xss": "CWE-79",
    "rce": "CWE-94",
    "lfi": "CWE-22",
    "rfi": "CWE-98",
    "ssrf": "CWE-918",
    "open-redirect": "CWE-601",
    "xxe": "CWE-611",
    "csrf": "CWE-352",
    "cors": "CWE-346",
    "takeover": "CWE-284",
    "expos": "CWE-200",
    "disclos": "CWE-200",
    "misconfig": "CWE-16",
    "default-login": "CWE-1392",
    "weak-": "CWE-326",
}


class NucleiAdapter(Adapter):
    tool_id = "nuclei"

    def _cwe(self, template_id: str) -> str:
        tid = template_id.lower()
        for prefix, cwe in _CWE_BY_TEMPLATE_PREFIX.items():
            if prefix in tid:
                return cwe
        return ""

    def parse(self, lines, ctx=None):
        findings = []
        for stream, text in lines:
            if stream != "stdout":
                continue
            m = _NUCLEI_RE.match(text.strip())
            if not m:
                continue
            sev = m.group("sev").lower()
            template_id = m.group("id")
            url = m.group("url")
            extract = m.group("extract") or ""

            cwe = self._cwe(template_id)
            is_cve = template_id.lower().startswith("cve-")
            remediation = (
                "Apply the vendor security patch for this CVE. Consult the "
                "vendor advisory for the specific version range affected and "
                "the fixed version."
                if is_cve else
                "Review the template's documentation at "
                "https://cloud.projectdiscovery.io/library for specific remediation "
                "steps. Templates often link to the relevant vendor advisory."
            )
            impact = (
                "Nuclei matched this target against a template that identifies "
                "a known vulnerability or misconfiguration. Severity is reported "
                "by the template author, not calculated per-target — validate "
                "the match manually before acting."
            )

            findings.append(Finding(
                kind="vulnerability",
                severity=sev,
                source="nuclei",
                data={
                    "template": template_id,
                    "url": url,
                    "extract": extract,
                },
                raw_line=text,
                remediation=remediation,
                impact=impact,
                cvss=_SEV_TO_CVSS.get(sev),
                cwe=cwe,
            ))
        return findings


register(NucleiAdapter())