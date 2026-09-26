"""Tool output parsers that produce structured findings.

Each parser takes a list of (stream, text) tuples and returns a list of
Finding objects. Parsers are registered by tool_id in PARSERS.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    source: str
    data: dict
    raw_line: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "source": self.source,
            "data": self.data,
            "raw_line": self.raw_line,
        }


# ---------------------------------------------------------------------------
# nmap: "80/tcp   open  http"
# ---------------------------------------------------------------------------
_NMAP_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>open|filtered|closed)\s+(?P<service>\S+)?",
    re.IGNORECASE,
)


def parse_nmap(lines: list[tuple[str, str]]) -> list[Finding]:
    out: list[Finding] = []
    for stream, text in lines:
        if stream != "stdout":
            continue
        m = _NMAP_PORT_RE.match(text.strip())
        if not m:
            continue
        state = m.group("state").lower()
        if state != "open":
            continue
        port = int(m.group("port"))
        severity = "info"
        if port in (22, 23, 21, 445, 3389):
            severity = "medium"
        elif port in (3306, 5432, 6379, 27017, 9200):
            severity = "high"
        out.append(Finding(
            kind="open_port",
            severity=severity,
            source="nmap",
            data={
                "port": port,
                "protocol": m.group("proto"),
                "state": state,
                "service": (m.group("service") or "").strip(),
            },
            raw_line=text,
        ))
    return out


# ---------------------------------------------------------------------------
# nikto: "+ /admin/: Directory indexing found."
# ---------------------------------------------------------------------------
_NIKTO_LINE_RE = re.compile(r"^\+\s+(?P<body>.+)")


def parse_nikto(lines: list[tuple[str, str]]) -> list[Finding]:
    out: list[Finding] = []
    for stream, text in lines:
        if stream != "stdout":
            continue
        t = text.strip()
        # Skip noise lines
        if t.startswith("+ Target") or t.startswith("+ Server") or t.startswith("+ Start Time"):
            continue
        if t.startswith("+ End Time") or t.startswith("+ 0 host") or t.startswith("+ 1 host"):
            continue
        m = _NIKTO_LINE_RE.match(t)
        if not m:
            continue
        body = m.group("body")
        # Heuristic severity
        severity = "info"
        lower = body.lower()
        if any(k in lower for k in ("vulnerable", "rce", "sql", "command execution", "xss")):
            severity = "high"
        elif any(k in lower for k in ("disclosure", "backup", "config", "indexing")):
            severity = "medium"
        # Try to extract a path
        path = ""
        pm = re.search(r"(/[A-Za-z0-9_\-./]+)", body)
        if pm:
            path = pm.group(1)
        out.append(Finding(
            kind="web_issue",
            severity=severity,
            source="nikto",
            data={"path": path, "message": body},
            raw_line=text,
        ))
    return out


# ---------------------------------------------------------------------------
# gobuster: "/admin                (Status: 200) [Size: 1234]"
# ---------------------------------------------------------------------------
_GOBUSTER_RE = re.compile(
    r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d+)\)(?:\s+\[Size:\s*(?P<size>\d+)\])?"
)


def parse_gobuster(lines: list[tuple[str, str]]) -> list[Finding]:
    out: list[Finding] = []
    for stream, text in lines:
        if stream != "stdout":
            continue
        m = _GOBUSTER_RE.match(text.strip())
        if not m:
            continue
        status = int(m.group("status"))
        if status in (404, 400):
            continue
        severity = "info"
        if status == 200:
            severity = "low"
        if status in (401, 403):
            severity = "info"
        out.append(Finding(
            kind="found_path",
            severity=severity,
            source="gobuster",
            data={
                "path": m.group("path"),
                "status": status,
                "size": int(m.group("size")) if m.group("size") else None,
            },
            raw_line=text,
        ))
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
PARSERS: dict[str, Callable[[list[tuple[str, str]]], list[Finding]]] = {
    "nmap": parse_nmap,
    "nikto": parse_nikto,
    "gobuster": parse_gobuster,
}


def parse_findings(tool_id: str, lines: list[tuple[str, str]]) -> list[Finding]:
    parser = PARSERS.get(tool_id)
    if parser is None:
        return []
    try:
        return parser(lines)
    except Exception:
        return []
