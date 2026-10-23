"""Individual recon checks. Each is a plain function returning list[Finding].

Checks must be independent, must not require ScopeManager access (the runner
gates the target before calling them), and must return findings even on
partial failure — the runner wraps exceptions into recon_error findings.

Adding a Phase 2 check: write a function here, add one register() line in
Core.__init__. The ReconRunner never changes.
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.request
from urllib.parse import urlparse

from .findings import Finding

# ---------------------------------------------------------------------------
# Enrichment tables — mirrors the nmap.py SERVICE_KNOWLEDGE pattern.
# ---------------------------------------------------------------------------

_MISSING_HEADER_KNOWLEDGE: dict[str, dict] = {
    "strict-transport-security": {
        "severity": "low",
        "cwe": "CWE-319",
        "cvss": 4.3,
        "remediation": (
            "Send Strict-Transport-Security with max-age of at least 6 months "
            "and includeSubDomains: 'Strict-Transport-Security: max-age=15768000; includeSubDomains'."
        ),
        "impact": (
            "Without HSTS, users are vulnerable to SSL-stripping attacks on first visit."
        ),
    },
    "content-security-policy": {
        "severity": "medium",
        "cwe": "CWE-693",
        "cvss": 5.0,
        "remediation": (
            "Define a Content-Security-Policy that restricts script-src and "
            "object-src to trusted origins. Start in report-only mode, then enforce."
        ),
        "impact": (
            "Missing CSP leaves the application without a defence-in-depth "
            "layer against XSS and data injection."
        ),
    },
    "x-frame-options": {
        "severity": "low",
        "cwe": "CWE-1021",
        "cvss": 4.3,
        "remediation": (
            "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'. The modern equivalent "
            "is Content-Security-Policy frame-ancestors."
        ),
        "impact": "Missing frame protections allow clickjacking.",
    },
    "x-content-type-options": {
        "severity": "low",
        "cwe": "CWE-16",
        "cvss": 3.7,
        "remediation": "Send 'X-Content-Type-Options: nosniff' on every response.",
        "impact": (
            "MIME sniffing can cause browsers to interpret content as a different "
            "type than intended, sometimes leading to script execution."
        ),
    },
    "referrer-policy": {
        "severity": "info",
        "cwe": "CWE-200",
        "cvss": None,
        "remediation": "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
        "impact": (
            "Without a Referrer-Policy, sensitive URL fragments may leak to "
            "third-party origins via the Referer header."
        ),
    },
    "permissions-policy": {
        "severity": "info",
        "cwe": "",
        "cvss": None,
        "remediation": (
            "Send Permissions-Policy to disable powerful browser features "
            "(camera, microphone, geolocation) unless explicitly required."
        ),
        "impact": (
            "Unrestricted browser features expand the attack surface for "
            "malicious third-party scripts."
        ),
    },
}

_TECH_MARKERS = (
    ("nginx", "nginx"),
    ("apache", "apache"),
    ("iis", "iis"),
    ("cloudflare", "cloudflare"),
    ("express", "express"),
    ("php", "php"),
    ("asp.net", "aspnet"),
)

_DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA")


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_dns(target: str) -> list[Finding]:
    """Query A/AAAA/MX/NS/TXT/SOA. Emit one finding per record, plus any error."""
    import dns.exception
    import dns.resolver

    host = _as_host(target)
    out: list[Finding] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    for rtype in _DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(host, rtype, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.resolver.NoAnswer):
            continue
        except Exception as exc:
            out.append(Finding(
                kind="recon_error",
                severity="info",
                source="recon:dns",
                data={"target": host, "record_type": rtype, "error": str(exc)},
                raw_line=f"dns {rtype} {host} failed: {exc}",
            ))
            continue
        if answers.rrset is None:
            continue
        for rr in answers:
            value = rr.to_text()
            out.append(Finding(
                kind="dns_record",
                severity="info",
                source="recon:dns",
                data={"record_type": rtype, "value": value, "host": host},
                raw_line=f"{host} {rtype} {value}",
            ))
    return out


def check_ssl(target: str) -> list[Finding]:
    """Inspect the TLS certificate. Emit cert details + SAN host discoveries."""
    host = _as_host(target)
    out: list[Finding] = []
    cert: dict | None = None
    verified = False

    try:
        # Verification-on path first.
        verified_ctx = ssl.create_default_context()
        with (
            socket.create_connection((host, 443), timeout=5) as s,
            verified_ctx.wrap_socket(s, server_hostname=host) as t,
        ):
            cert = t.getpeercert()
            verified = True
    except ssl.SSLCertVerificationError as exc:
        out.append(Finding(
            kind="ssl_cert_invalid",
            severity="medium",
            source="recon:ssl",
            data={"host": host, "error": str(exc)},
            raw_line=f"cert verification failed for {host}: {exc}",
            remediation="Use a certificate from a trusted CA and ensure the hostname matches.",
            impact="Certificate verification failure permits MITM if users ignore the warning.",
            cwe="CWE-295",
            cvss=5.9,
        ))
        # Best-effort: try again without verification to still surface SANs/issuer.
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with (
                socket.create_connection((host, 443), timeout=5) as s,
                ctx.wrap_socket(s, server_hostname=host) as t,
            ):
                # getpeercert() with CERT_NONE returns {} on some Pythons.
                raw = t.getpeercert() or {}
                cert = raw if raw else None
        except Exception:
            pass
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        out.append(Finding(
            kind="recon_error",
            severity="info",
            source="recon:ssl",
            data={"target": host, "error": str(exc)},
            raw_line=f"ssl {host} failed: {exc}",
        ))
        return out

    if cert:
        out.append(Finding(
            kind="ssl_cert",
            severity="info",
            source="recon:ssl",
            data={
                "host": host,
                "subject": _cert_field(cert, "subject"),
                "issuer": _cert_field(cert, "issuer"),
                "notBefore": cert.get("notBefore", ""),
                "notAfter": cert.get("notAfter", ""),
                "verified": verified,
            },
            raw_line=f"TLS cert for {host}: issuer={_cert_field(cert, 'issuer')}",
        ))
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type != "DNS" or san_value == host:
                continue
            out.append(Finding(
                kind="recon_discovered_host",
                severity="info",
                source="recon:ssl",
                data={"host": san_value, "relation": "san", "from": host},
                raw_line=f"SAN on {host}: {san_value}",
                remediation=(
                    "Review whether this host should be in scope. Add via the override "
                    "log if authorised; do not auto-scan."
                ),
                impact="Additional hostname associated with the target via certificate SANs.",
            ))
    return out


def check_headers(target: str) -> list[Finding]:
    """Fetch the target over HTTPS and report missing security headers."""
    url = _as_url(target)
    out: list[Finding] = []
    try:
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "WHAXON-recon/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:
        out.append(Finding(
            kind="recon_error",
            severity="info",
            source="recon:headers",
            data={"target": target, "error": str(exc)},
            raw_line=f"headers {url} failed: {exc}",
        ))
        return out

    for header, info in _MISSING_HEADER_KNOWLEDGE.items():
        if header in headers:
            continue
        out.append(Finding(
            kind="http_header_missing",
            severity=info["severity"],
            source="recon:headers",
            data={"header": header, "url": url},
            raw_line=f"{url}: missing {header}",
            remediation=info["remediation"],
            impact=info["impact"],
            cwe=info["cwe"],
            cvss=info["cvss"],
        ))
    return out


def check_tech(target: str) -> list[Finding]:
    """Detect server framework / CMS. Emits tech_detected (human) + open_port
    (correlator-shaped) when a version is known, so rule_vulnerable_service fires."""
    url = _as_url(target)
    out: list[Finding] = []
    try:
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "WHAXON-recon/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
    except Exception as exc:
        out.append(Finding(
            kind="recon_error", severity="info", source="recon:tech",
            data={"target": target, "error": str(exc)},
            raw_line=f"tech {url} failed: {exc}",
        ))
        return out

    for raw in (server, powered):
        if not raw:
            continue
        raw_l = raw.lower()
        for marker, canonical in _TECH_MARKERS:
            if marker not in raw_l:
                continue
            version = _version_from(raw_l, marker)
            out.append(Finding(
                kind="tech_detected", severity="info", source="recon:tech",
                data={"product": canonical, "banner": raw, "url": url,
                      "version": version},
                raw_line=f"{url}: {raw}",
                lookup_hint=f"{canonical} {version}".strip(),
            ))
            if version:
                out.append(Finding(
                    kind="open_port", severity="info", source="recon:tech",
                    data={"port": 443, "protocol": "tcp", "state": "open",
                          "service": canonical, "version": raw},
                    raw_line=f"443/tcp open  https   {raw}",
                ))
            break
    return out

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_host(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/", 1)[0].split(":", 1)[0]


def _as_url(target: str) -> str:
    if "://" in target:
        return target
    return f"https://{_as_host(target)}/"


def _cert_field(cert: dict, field: str) -> str:
    parts = cert.get(field, ())
    bits = []
    for group in parts:
        for k, v in group:
            bits.append(f"{k}={v}")
    return ", ".join(bits)


def _version_from(banner_l: str, marker: str) -> str:
    m = re.search(rf"{re.escape(marker)}[/ ]+([0-9][0-9a-z.\-]*)", banner_l)
    return m.group(1) if m else ""
