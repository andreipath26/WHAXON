"""FFUF adapter — web fuzzing results with remediation knowledge."""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register


# Two shapes we handle:
#   "admin"                              — silent mode, no status
#   "admin  [Status: 200, Size: 1234]"   — default mode with status
_FFUF_RE = re.compile(
    r"^(?P<path>\S+?)"
    r"(?:\s+\[Status:\s*(?P<status>\d+)"
    r"(?:,\s*Size:\s*(?P<size>\d+))?.*?\])?\s*$"
)


STATUS_KNOWLEDGE = {
    200: {
        "severity": "low", "cwe": "CWE-200", "cvss": 3.7,
        "remediation": (
            "Review the discovered path. Remove debug, admin, and backup endpoints "
            "from production. If the path must be reachable, add authentication."
        ),
        "impact": (
            "Publicly reachable paths expand the attack surface and often disclose "
            "application internals or accept unauthenticated input."
        ),
    },
    301: {"severity": "info", "cwe": "", "cvss": None,
          "remediation": "Verify the redirect target.",
          "impact": "Redirects reveal URL structure."},
    302: {"severity": "info", "cwe": "", "cvss": None,
          "remediation": "Verify the redirect target.",
          "impact": "Redirects reveal URL structure."},
    401: {"severity": "info", "cwe": "", "cvss": None,
          "remediation": "Confirm the authentication scheme is appropriate.",
          "impact": "Protected paths are visible to unauthenticated users."},
    403: {"severity": "info", "cwe": "", "cvss": None,
          "remediation": "Confirm the response does not leak information.",
          "impact": "Path existence is disclosed."},
}


class FfufAdapter(Adapter):
    tool_id = "ffuf"

    def parse(self, lines, ctx=None):
        findings = []
        for stream, text in lines:
            if stream != "stdout":
                continue
            stripped = text.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = _FFUF_RE.match(stripped)
            if not m:
                continue
            path = m.group("path")
            if path.startswith("http"):
                # Strip scheme + host; keep only the path portion
                parts = path.split("/", 3)
                path = "/" + parts[-1] if len(parts) > 3 else "/"
            status = int(m.group("status")) if m.group("status") else 200
            if status == 404:
                continue
            knowledge = STATUS_KNOWLEDGE.get(status, {
                "severity": "info", "cwe": "", "cvss": None,
                "remediation": "", "impact": "",
            })
            findings.append(Finding(
                kind="found_path",
                severity=knowledge["severity"],
                source="ffuf",
                data={
                    "path": path,
                    "status": status,
                    "size": int(m.group("size")) if m.group("size") else None,
                },
                raw_line=text,
                remediation=knowledge.get("remediation", ""),
                impact=knowledge.get("impact", ""),
                cvss=knowledge.get("cvss"),
                cwe=knowledge.get("cwe", ""),
            ))
        return findings


register(FfufAdapter())