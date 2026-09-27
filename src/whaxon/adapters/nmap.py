"""Nmap adapter — structured port/service parsing with remediation knowledge."""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register


# "22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu"
_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
    r"(?P<state>open|filtered|closed)\s+"
    r"(?P<service>\S+)?"
    r"(?:\s+(?P<version>.+))?$",
    re.IGNORECASE,
)


# Service -> (severity, cwe, cvss, remediation, impact)
# Keys are lowercase, matched against the service name from nmap.
SERVICE_KNOWLEDGE: dict[str, dict] = {
    "ssh": {
        "severity": "medium",
        "cwe": "CWE-287",
        "cvss": 5.3,
        "remediation": (
            "Restrict SSH access to trusted networks via firewall rules or a bastion host. "
            "Disable password authentication in favour of key-based auth. Enforce MFA where possible. "
            "Keep OpenSSH patched and review `sshd_config` against CIS benchmarks."
        ),
        "impact": (
            "Exposed SSH increases the attack surface for credential-stuffing, "
            "brute-force, and unpatched OpenSSH vulnerabilities."
        ),
    },
    "telnet": {
        "severity": "high",
        "cwe": "CWE-319",
        "cvss": 7.4,
        "remediation": (
            "Replace Telnet with SSH immediately. Telnet transmits credentials and session "
            "data in plaintext. If legacy devices require Telnet, isolate them on a separate "
            "management VLAN with strict ACLs."
        ),
        "impact": (
            "Telnet credentials can be captured by any attacker on the network path. "
            "Full remote access is typically achievable."
        ),
    },
    "ftp": {
        "severity": "high",
        "cwe": "CWE-319",
        "cvss": 7.4,
        "remediation": (
            "Replace FTP with SFTP or FTPS. If FTP is required, disable anonymous access "
            "and restrict allowed source networks."
        ),
        "impact": (
            "FTP transmits credentials and data in plaintext. Anonymous access, if enabled, "
            "permits unauthenticated data retrieval."
        ),
    },
    "smtp": {
        "severity": "medium",
        "cwe": "CWE-16",
        "cvss": 5.3,
        "remediation": (
            "Restrict SMTP to trusted relay networks. Verify the server is not an open relay "
            "by testing with an external RCPT TO. Enable STARTTLS."
        ),
        "impact": (
            "An exposed mail server can be abused for spam relay or user enumeration."
        ),
    },
    "http": {
        "severity": "info",
        "cwe": "",
        "cvss": None,
        "remediation": (
            "Redirect HTTP to HTTPS. Ensure security headers are set "
            "(HSTS, X-Content-Type-Options, Content-Security-Policy)."
        ),
        "impact": "Unencrypted HTTP exposes session tokens and credentials to network attackers.",
    },
    "https": {
        "severity": "info",
        "remediation": (
            "Verify the TLS configuration against a modern profile (Mozilla intermediate or "
            "strict). Disable TLS <1.2. Ensure the certificate chain is complete."
        ),
        "impact": "Correctly configured HTTPS protects session confidentiality.",
    },
    "mysql": {
        "severity": "high",
        "cwe": "CWE-284",
        "cvss": 8.1,
        "remediation": (
            "Bind MySQL to localhost or a private interface. Never expose 3306 to the internet. "
            "Use strong passwords for all accounts. Disable remote root login."
        ),
        "impact": (
            "Exposed database port permits direct credential attacks and, if successful, "
            "complete data compromise."
        ),
    },
    "postgresql": {
        "severity": "high",
        "cwe": "CWE-284",
        "cvss": 8.1,
        "remediation": (
            "Restrict Postgres to the application network. Use pg_hba.conf to enforce host-based "
            "auth. Never expose 5432 publicly."
        ),
        "impact": "Exposed Postgres permits direct credential attacks and data exfiltration.",
    },
    "redis": {
        "severity": "critical",
        "cwe": "CWE-306",
        "cvss": 9.8,
        "remediation": (
            "Redis has no authentication by default and, if exposed, permits arbitrary key "
            "manipulation and often RCE via module loading. Bind to localhost, set a strong "
            "password with `requirepass`, and never expose 6379 publicly."
        ),
        "impact": (
            "Exposed Redis is widely exploited for full server compromise via Lua scripting "
            "or SSH key injection."
        ),
    },
    "mongodb": {
        "severity": "critical",
        "cwe": "CWE-306",
        "cvss": 9.8,
        "remediation": (
            "Enable MongoDB authentication. Bind to localhost or a private interface. "
            "Never expose 27017 publicly."
        ),
        "impact": (
            "Unauthenticated MongoDB has historically been exploited at scale for mass data theft."
        ),
    },
    "elasticsearch": {
        "severity": "high",
        "cwe": "CWE-306",
        "cvss": 8.6,
        "remediation": (
            "Enable Elasticsearch security features. Bind to a private interface. "
            "Never expose 9200 publicly."
        ),
        "impact": "Exposed Elasticsearch permits index browsing, deletion, and often RCE.",
    },
    "rdp": {
        "severity": "high",
        "cwe": "CWE-287",
        "cvss": 7.5,
        "remediation": (
            "Restrict RDP to VPN or bastion hosts. Enable Network Level Authentication. "
            "Enforce MFA. Patch BlueKeep and related CVEs."
        ),
        "impact": (
            "Exposed RDP is a primary initial-access vector for ransomware operators."
        ),
    },
    "smb": {
        "severity": "high",
        "cwe": "CWE-284",
        "cvss": 8.1,
        "remediation": (
            "Disable SMBv1. Block SMB (445) at network boundaries. Enforce SMB signing. "
            "Review shares for anonymous access."
        ),
        "impact": (
            "Exposed SMB permits share enumeration, credential relay, and exploitation "
            "of EternalBlue-class vulnerabilities."
        ),
    },
    "vnc": {
        "severity": "high",
        "cwe": "CWE-521",
        "cvss": 7.5,
        "remediation": (
            "VNC often runs with weak or no authentication. Tunnel through SSH or a VPN. "
            "Set a strong password and disable shared sessions where possible."
        ),
        "impact": "Exposed VNC grants interactive desktop access with weak protection.",
    },
}


class NmapAdapter(Adapter):
    tool_id = "nmap"

    def parse(self, lines, ctx=None):
        findings = []
        for stream, text in lines:
            if stream != "stdout":
                continue
            m = _PORT_RE.match(text.strip())
            if not m:
                continue
            state = m.group("state").lower()
            if state != "open":
                continue

            port = int(m.group("port"))
            service = (m.group("service") or "").lower()
            version = (m.group("version") or "").strip()

            knowledge = SERVICE_KNOWLEDGE.get(service, {})
            severity = knowledge.get("severity", "info")

            # Unknown ports on the "high" range default to medium
            if not knowledge and 1024 < port < 49152:
                severity = "medium"

            data = {
                "port": port,
                "protocol": m.group("proto"),
                "state": state,
                "service": service,
                "version": version,
            }

            findings.append(Finding(
                kind="open_port",
                severity=severity,
                source="nmap",
                data=data,
                raw_line=text,
                remediation=knowledge.get("remediation", ""),
                impact=knowledge.get("impact", ""),
                cvss=knowledge.get("cvss"),
                cwe=knowledge.get("cwe", ""),
                references=knowledge.get("references", ()),
            ))
        return findings


register(NmapAdapter())
