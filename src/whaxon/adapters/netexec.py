"""NetExec (nxc) adapter — SMB/LDAP/SSH/WMI/RDP/WinRM/MSSQL etc."""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register


# NetExec prints lines like:
#   SMB         10.0.0.5       445    HOSTNAME   [*] Windows 10 (name:X) (domain:Y)
#   SMB         10.0.0.5       445    HOSTNAME   [+] DOMAIN\user:pass (Pwn3d!)
#   SMB         10.0.0.5       445    HOSTNAME   [-] DOMAIN\user:pass STATUS_LOGON_FAILURE
#   LDAP        10.0.0.5       389    HOSTNAME   [*] domain.local\\DC01
_LINE_RX = re.compile(
    r"^(?P<proto>[A-Z][A-Z0-9_]+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<port>\d+)\s+"
    r"(?P<name>\S+)\s+"
    r"\[(?P<marker>[+*\-!])\]\s+"
    r"(?P<msg>.+)$"
)


_SUCCESS_RX = re.compile(
    r"^\[\+\]\s+(?:(?P<domain>[^\\\s]+)\\)?"
    r"(?P<user>[^:\s]+):(?P<password>\S*)\s*(?P<tail>\(.*\))?$"
)
_FAIL_RX = re.compile(
    r"^\[-\]\s+(?:(?P<domain>[^\\\s]+)\\)?"
    r"(?P<user>[^:\s]+):(?P<password>\S*)\s+(?P<status>STATUS_\S+)"
)


def _parse_line(line: str) -> list[dict]:
    out: list[dict] = []
    m = _LINE_RX.match(line)
    if not m:
        return out
    g = m.groupdict()
    marker = g["marker"]
    msg = g["msg"]
    base = {"protocol": g["proto"], "host": g["host"],
            "port": int(g["port"]), "name": g["name"]}
    if marker == "+":
        sm = _SUCCESS_RX.match("[+] " + msg)
        cred_data = dict(base)
        if sm:
            sd = sm.groupdict()
            cred_data["domain"] = sd.get("domain") or ""
            cred_data["user"] = sd.get("user")
            cred_data["password"] = sd.get("password") or ""
            tail = sd.get("tail") or ""
            cred_data["pwned"] = "Pwn3d" in tail
        else:
            cred_data["message"] = msg[:200]
        out.append({"kind": "nxc_credential", "data": cred_data,
                    "raw": line[:200]})
    elif marker == "-":
        fm = _FAIL_RX.match("[-] " + msg)
        if fm:
            fd = fm.groupdict()
            bad = dict(base)
            bad["domain"] = fd.get("domain") or ""
            bad["user"] = fd.get("user")
            bad["status"] = fd.get("status")
            out.append({"kind": "nxc_auth_fail", "data": bad,
                        "raw": line[:200]})
    elif marker == "*":
        info = dict(base)
        info["message"] = msg[:200]
        out.append({"kind": "nxc_info", "data": info,
                    "raw": line[:200]})
    return out


class NetexecAdapter(Adapter):
    tool_id = "netexec"

    def parse(self, lines, ctx=None):
        if isinstance(lines, list):
            text = "\n".join(
                str(item[1]) if isinstance(item, tuple) and len(item) == 2 else str(item)
                for item in lines
            )
        else:
            text = lines or ""
        findings: list[Finding] = []
        for line in text.splitlines():
            for r in _parse_line(line.strip()):
                data = dict(r["data"])
                kind = r["kind"]
                if kind == "nxc_credential":
                    sev = "critical" if data.get("pwned") else "high"
                    findings.append(Finding(
                        kind=kind, severity=sev, source="netexec",
                        data=data, raw_line=r["raw"][:200],
                        remediation="Rotate the credential and audit its usage.",
                        impact="Valid credentials discovered via NetExec.",
                        cvss=9.0 if data.get("pwned") else 7.5,
                        cwe="CWE-521",
                    ))
                elif kind == "nxc_auth_fail":
                    findings.append(Finding(
                        kind=kind, severity="info", source="netexec",
                        data=data, raw_line=r["raw"][:200],
                    ))
                else:
                    findings.append(Finding(
                        kind=kind, severity="info", source="netexec",
                        data=data, raw_line=r["raw"][:200],
                    ))
        return findings


register(NetexecAdapter())
