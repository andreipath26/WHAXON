"""Tool output parsers that produce structured findings.

Each parser takes a list of (stream, text) tuples and returns a list of
Finding objects. Parsers are registered by tool_id in PARSERS.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    source: str
    data: dict
    raw_line: str = ""
    # Enriched fields — filled in by adapters where possible
    remediation: str = ""
    impact: str = ""
    cvss: float | None = None
    cwe: str = ""
    references: tuple[str, ...] = ()
    # Optional: a search hint for exploit/cve lookup (e.g. "apache 2.4.7").
    # Rendered as a lookup section by to_markdown when non-empty.
    lookup_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "source": self.source,
            "data": self.data,
            "raw_line": self.raw_line,
            "remediation": self.remediation,
            "impact": self.impact,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "references": list(self.references),
            "lookup_hint": self.lookup_hint,
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
        # High-risk data services
        if port in (3306, 5432, 6379, 27017, 9200, 11211, 1433, 5984):
            severity = "high"
        # Remotely-accessible admin / legacy services
        elif port in (22, 23, 21, 445, 3389, 512, 513, 514):
            severity = "medium"
        # Common dev / debug / misc services
        elif port in (3000, 5000, 8000, 8080, 8888, 9000, 9090):
            severity = "low"
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




# ---------------------------------------------------------------------------
# sqlmap: "[INFO] GET parameter id appears to be injectable"
#         "Parameter: id (GET)"
# ---------------------------------------------------------------------------
_SQLMAP_INJECTABLE_RE = re.compile(r"parameter '?(?P<name>[\w\[\]]+)'? .*appears to be (?P<kind>injectable|vulnerable)", re.IGNORECASE)
_SQLMAP_PARAM_RE = re.compile(r"^Parameter:\s*(?P<name>\S+)\s*\((?P<where>[^)]+)\)")


def parse_sqlmap(lines):
    out = []
    seen = set()
    for stream, text in lines:
        if stream != "stdout":
            continue
        t = text.strip()
        m = _SQLMAP_INJECTABLE_RE.search(t)
        if m:
            key = (m.group("name"), m.group("kind"))
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                kind="sqli",
                severity="critical",
                source="sqlmap",
                data={"parameter": m.group("name"), "type": m.group("kind")},
                raw_line=text,
            ))
            continue
        m = _SQLMAP_PARAM_RE.match(t)
        if m:
            key = (m.group("name"), "param")
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                kind="sqli_param",
                severity="high",
                source="sqlmap",
                data={"parameter": m.group("name"), "where": m.group("where").strip()},
                raw_line=text,
            ))
    return out


# ---------------------------------------------------------------------------
# whois: domain expiry, registrar, name servers
# ---------------------------------------------------------------------------
_WHOIS_EXPIRY_RE = re.compile(r"^(?:Registry Expiry Date|Expiry Date|paid-till):\s*(?P<date>.+)$", re.IGNORECASE)
_WHOIS_REGISTRAR_RE = re.compile(r"^Registrar:\s*(?P<name>.+)$", re.IGNORECASE)
_WHOIS_NS_RE = re.compile(r"^Name Server:\s*(?P<ns>\S+)", re.IGNORECASE)


def parse_whois(lines):
    out = []
    seen = set()
    for stream, text in lines:
        t = text.strip()
        m = _WHOIS_EXPIRY_RE.match(t)
        if m and "expiry" not in seen:
            seen.add("expiry")
            out.append(Finding(kind="domain_expiry", severity="info", source="whois",
                data={"expiry": m.group("date").strip()}, raw_line=text))
            continue
        m = _WHOIS_REGISTRAR_RE.match(t)
        if m and "registrar" not in seen:
            seen.add("registrar")
            out.append(Finding(kind="registrar", severity="info", source="whois",
                data={"registrar": m.group("name").strip()}, raw_line=text))
            continue
        m = _WHOIS_NS_RE.match(t)
        if m:
            key = ("ns", m.group("ns"))
            if key not in seen:
                seen.add(key)
                out.append(Finding(kind="nameserver", severity="info", source="whois",
                    data={"ns": m.group("ns")}, raw_line=text))
    return out


# ---------------------------------------------------------------------------
# dig: parse A/AAAA/MX/NS records from +short output
# ---------------------------------------------------------------------------
_MX_PRIORITY_RE = re.compile(r"^(?P<priority>\d+)\s+(?P<host>\S+\.)$")
def parse_dig(lines):
    out = []
    ips = 0
    for stream, text in lines:
        if stream != "stdout":
            continue
        t = text.strip()
        if not t:
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", t):
            out.append(Finding(kind="a_record", severity="info", source="dig",
                data={"ip": t}, raw_line=text)); ips += 1
            continue
        if ":" in t and re.match(r"^[0-9a-fA-F:]+$", t):
            out.append(Finding(kind="aaaa_record", severity="info", source="dig",
                data={"ip": t}, raw_line=text)); continue
        m = _MX_PRIORITY_RE.match(t)
        if m:
            out.append(Finding(kind="mx_record", severity="info", source="dig",
                data={"mx": m.group("host"), "priority": int(m.group("priority"))},
                raw_line=text)); continue
        if "@" in t:
            out.append(Finding(kind="mx_record", severity="info", source="dig",
                data={"mx": t}, raw_line=text)); continue
        if t.endswith("."):
            out.append(Finding(kind="ns_record", severity="info", source="dig",
                data={"ns": t}, raw_line=text)); continue
    return out


# ---------------------------------------------------------------------------
# nuclei: "[critical] [CVE-2021-1234] https://target/..."
# ---------------------------------------------------------------------------
_NUCLEI_RE = re.compile(r"^\[(?P<sev>info|low|medium|high|critical)\]\s*\[(?P<id>[^\]]+)\]\s*(?P<url>\S+)")


def parse_nuclei(lines):
    out = []
    for stream, text in lines:
        if stream != "stdout":
            continue
        m = _NUCLEI_RE.match(text.strip())
        if m:
            out.append(Finding(
                kind="vulnerability",
                severity=m.group("sev").lower(),
                source="nuclei",
                data={"template": m.group("id"), "url": m.group("url")},
                raw_line=text,
            ))
    return out


# ---------------------------------------------------------------------------
# ffuf: parse "-s" (silent) output lines like "admin" or "admin  [Status: 200, ...]"
# ---------------------------------------------------------------------------
_FFUF_RE = re.compile(r"^(?P<path>\S+?)(?:\s+\[Status:\s*(?P<status>\d+).*?\])?\s*$")


def parse_ffuf(lines):
    out = []
    for stream, text in lines:
        if stream != "stdout":
            continue
        t = text.strip()
        if not t or t.startswith("#"):
            continue
        m = _FFUF_RE.match(t)
        if not m:
            continue
        path = m.group("path")
        if path.startswith("http"):
            path = "/" + path.split("/", 3)[-1]
        status = int(m.group("status")) if m.group("status") else 200
        out.append(Finding(
            kind="found_path",
            severity="low" if status == 200 else "info",
            source="ffuf",
            data={"path": path, "status": status},
            raw_line=text,
        ))
    return out


# ---------------------------------------------------------------------------
# wpscan: "[+] WordPress version 5.8 identified" / "[!] Title: ..."
# ---------------------------------------------------------------------------
_WPSCAN_VERSION_RE = re.compile(r"^\[\+\] WordPress version (?P<v>[\d.]+)")
_WPSCAN_VULN_RE = re.compile(r"^\[!\] Title:\s*(?P<title>.+)")


def parse_wpscan(lines):
    out = []
    for stream, text in lines:
        t = text.strip()
        m = _WPSCAN_VERSION_RE.match(t)
        if m:
            out.append(Finding(kind="wp_version", severity="info", source="wpscan",
                data={"version": m.group("v")}, raw_line=text)); continue
        m = _WPSCAN_VULN_RE.match(t)
        if m:
            out.append(Finding(kind="wp_vulnerability", severity="high", source="wpscan",
                data={"title": m.group("title").strip()}, raw_line=text))
    return out


PARSERS.update({
    "sqlmap": parse_sqlmap,
    "whois": parse_whois,
    "dig": parse_dig,
    "nuclei": parse_nuclei,
    "ffuf": parse_ffuf,
    "wpscan": parse_wpscan,
})


def parse_findings(tool_id: str, lines: list[tuple[str, str]]) -> list[Finding]:
    parser = PARSERS.get(tool_id)
    if parser is None:
        return []
    try:
        return parser(lines)
    except Exception:
        return []
