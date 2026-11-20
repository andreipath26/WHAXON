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
from typing import TypedDict
from urllib.parse import urlparse

from .findings import Finding


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not let passive recon follow a redirect beyond its checked target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _open_no_redirect(request, timeout: float):
    return _NO_REDIRECT_OPENER.open(request, timeout=timeout)

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
    """Fetch the target (HTTPS first, HTTP fallback) and report missing
    security headers."""
    out: list[Finding] = []
    try:
        url, resp = _http_get(target, timeout=5.0)
        with resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:
        out.append(Finding(
            kind="recon_error",
            severity="info",
            source="recon:headers",
            data={"target": target, "error": str(exc)},
            raw_line=f"headers {target} failed: {exc}",
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
    out: list[Finding] = []
    try:
        url, resp = _http_get(target, timeout=5.0)
        with resp:
            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
    except Exception as exc:
        out.append(Finding(
            kind="recon_error", severity="info", source="recon:tech",
            data={"target": target, "error": str(exc)},
            raw_line=f"tech {target} failed: {exc}",
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
    """Build an HTTPS URL from a bare host. If the caller passed an explicit
    scheme (http:// or https://), respect it. Otherwise default to HTTPS —
    but HTTP-only checks should call _as_url_http_fallback when HTTPS fails."""
    if "://" in target:
        return target
    return f"https://{_as_host(target)}/"


def _try_urls(target: str) -> list[str]:
    """Return candidate URLs to try in order. If the target has an explicit
    scheme, only that scheme is tried. Otherwise HTTPS first, then HTTP."""
    if "://" in target:
        return [target]
    host = _as_host(target)
    return [f"https://{host}/", f"http://{host}/"]


def _http_get(target: str, timeout: float = 5.0):
    """Try _try_urls(target) in order. Returns (final_url, response) on the
    first success; raises the last exception if all fail. Caller owns the
    response and must close it (use as context manager)."""
    last_exc = None
    for url in _try_urls(target):
        try:
            req = urllib.request.Request(
                url, method="GET",
                headers={"User-Agent": "WHAXON-recon/1.0"},
            )
            resp = _open_no_redirect(req, timeout=timeout)
            return url, resp
        except Exception as exc:
            last_exc = exc
            continue
    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"no candidate URLs for {target}")


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


def check_robots(target: str) -> list[Finding]:
    """Fetch robots.txt + sitemap.xml. Emit findings for disallowed paths
    and sitemap URLs. Redirects are followed (matching browser behaviour);
    the final URL is recorded so the trail is visible."""
    base = _as_url(target).rstrip("/")
    out: list[Finding] = []

    robots_url = f"{base}/robots.txt"
    robots_body = ""
    robots_final = ""
    try:
        req = urllib.request.Request(
            robots_url, method="GET",
            headers={"User-Agent": "WHAXON-recon/1.0"},
        )
        with _open_no_redirect(req, timeout=5) as resp:
            robots_body = resp.read(65536).decode("utf-8", errors="replace")
            robots_final = getattr(resp, "geturl", lambda: robots_url)() or robots_url
    except Exception as exc:
        out.append(Finding(
            kind="recon_error", severity="info", source="recon:robots",
            data={"target": target, "url": robots_url, "error": str(exc)},
            raw_line=f"robots.txt fetch failed for {robots_url}: {exc}",
        ))

    if robots_body:
        for line in robots_body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if low.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    out.append(Finding(
                        kind="robots_disallow", severity="info",
                        source="recon:robots",
                        data={"url": robots_final, "path": path},
                        raw_line=f"{robots_final}: Disallow {path}",
                        remediation=(
                            "Review the disallowed path. Robots.txt is advisory, "
                            "not access control; confirm the path is not sensitive."
                        ),
                        impact=(
                            "Disallowed paths often reveal administrative interfaces, "
                            "backup directories, or internal endpoints the operator "
                            "wanted hidden from crawlers."
                        ),
                    ))
            elif low.startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                if sm:
                    out.append(Finding(
                        kind="robots_sitemap_ref", severity="info",
                        source="recon:robots",
                        data={"url": robots_final, "sitemap": sm},
                        raw_line=f"{robots_final}: Sitemap {sm}",
                    ))

    sitemap_url = f"{base}/sitemap.xml"
    try:
        req = urllib.request.Request(
            sitemap_url, method="GET",
            headers={"User-Agent": "WHAXON-recon/1.0"},
        )
        with _open_no_redirect(req, timeout=5) as resp:
            xml = resp.read(65536).decode("utf-8", errors="replace")
    except Exception:
        return out

    if xml:
        locs = re.findall(r"<loc>([^<]+)</loc>", xml)
        for loc in locs[:100]:
            out.append(Finding(
                kind="sitemap_url", severity="info", source="recon:robots",
                data={"sitemap": sitemap_url, "url": loc},
                raw_line=f"{sitemap_url}: {loc}",
            ))
    return out


_SECURITY_TXT_FIELDS = (
    "Contact", "Expires", "Encryption", "Acknowledgments",
    "Preferred-Languages", "Canonical", "Policy", "Hiring",
)


def check_security_txt(target: str) -> list[Finding]:
    """Fetch /.well-known/security.txt (RFC 9116). Emit the declared fields
    as findings, or a single informational 'missing' finding."""
    out: list[Finding] = []
    body = ""
    final_url = ""
    sec_url = ""
    last_exc: Exception | None = None
    for base in _try_urls(target):
        sec_url = base.rstrip("/") + "/.well-known/security.txt"
        try:
            sec_req = urllib.request.Request(
                sec_url, method="GET",
                headers={"User-Agent": "WHAXON-recon/1.0"},
            )
            with _open_no_redirect(sec_req, timeout=5) as resp:
                body = resp.read(65536).decode("utf-8", errors="replace")
                final_url = getattr(resp, "geturl", lambda u=sec_url: u)() or sec_url
            last_exc = None
            break
        except Exception as exc:
            last_exc = exc
            continue

    if last_exc is not None and not body:
        out.append(Finding(
            kind="security_txt_missing", severity="info",
            source="recon:security_txt",
            data={"url": sec_url, "error": str(last_exc)},
            raw_line=f"security.txt not reachable at {sec_url}: {last_exc}",
            remediation=(
                "Publish a security.txt at /.well-known/security.txt (RFC 9116) "
                "with a Contact field so researchers can report vulnerabilities."
            ),
            impact=(
                "Without security.txt, security researchers have no documented "
                "channel for disclosing findings, increasing the risk of public "
                "disclosure or missed reports."
            ),
        ))
        return out

    # Parse RFC 9116 fields. Line format: "Field: value" — case-insensitive key.
    seen: dict[str, list[str]] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key_norm = key.strip()
        # Match known fields case-insensitively; store under canonical form.
        for canonical in _SECURITY_TXT_FIELDS:
            if key_norm.lower() == canonical.lower():
                seen.setdefault(canonical, []).append(value.strip())
                break

    if not seen:
        out.append(Finding(
            kind="security_txt_missing", severity="info",
            source="recon:security_txt",
            data={"url": final_url, "body_present": True, "fields_found": []},
            raw_line=f"security.txt at {final_url} contains no recognised RFC 9116 fields",
            remediation=(
                "security.txt is present but contains no recognised fields. "
                "Add at least a Contact field per RFC 9116."
            ),
            impact=(
                "A security.txt without a Contact field gives researchers no "
                "usable reporting channel."
            ),
        ))
        return out

    for field, values in seen.items():
        for value in values:
            out.append(Finding(
                kind="security_txt", severity="info",
                source="recon:security_txt",
                data={"url": final_url, "field": field, "value": value},
                raw_line=f"{final_url}: {field}: {value}",
            ))
    return out


class _CookieFlagKnowledge(TypedDict):
    severity: str
    cwe: str
    cvss: float | None
    remediation: str
    impact: str


_COOKIE_FLAG_KNOWLEDGE: dict[str, _CookieFlagKnowledge] = {
    "secure": {
        "severity": "low", "cwe": "CWE-614", "cvss": 3.7,
        "remediation": (
            "Set the Secure flag on every cookie. Cookies without Secure are "
            "sent over plain HTTP, exposing session tokens to network attackers."
        ),
        "impact": (
            "Without Secure, a downgrade to HTTP leaks the cookie to any "
            "attacker on the network path."
        ),
    },
    "httponly": {
        "severity": "low", "cwe": "CWE-1004", "cvss": 3.5,
        "remediation": (
            "Set HttpOnly on session cookies. Without it, document.cookie "
            "reads them, so any XSS becomes session theft."
        ),
        "impact": (
            "Without HttpOnly, a successful XSS can read and exfiltrate "
            "the session cookie."
        ),
    },
    "samesite": {
        "severity": "info", "cwe": "CWE-1275", "cvss": None,
        "remediation": (
            "Set SameSite=Lax (default in modern browsers) or Strict. "
            "SameSite=None requires Secure and should only be used where "
            "cross-site cookies are required."
        ),
        "impact": (
            "Without a SameSite attribute, the cookie may be sent on "
            "cross-site requests, expanding CSRF surface."
        ),
    },
}


def check_cookies(target: str) -> list[Finding]:
    """Fetch the target, parse Set-Cookie headers, report missing
    Secure / HttpOnly / SameSite flags."""
    out: list[Finding] = []
    try:
        url, resp = _http_get(target, timeout=5.0)
        with resp:
            raw_headers = resp.headers.get_all("Set-Cookie") or []
    except Exception as exc:
        out.append(Finding(
            kind="recon_error", severity="info", source="recon:cookies",
            data={"target": target, "error": str(exc)},
            raw_line=f"cookies {target} failed: {exc}",
        ))
        return out

    for raw in raw_headers:
        # "name=value; Flag; Flag=value" — split on ';', first token is name=value
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs = {p.split("=", 1)[0].strip().lower(): p for p in parts[1:]}
        for flag, knowledge in _COOKIE_FLAG_KNOWLEDGE.items():
            if flag in attrs:
                continue
            out.append(Finding(
                kind="cookie_insecure",
                severity=knowledge["severity"],
                source="recon:cookies",
                data={"url": url, "cookie": name, "missing": flag,
                      "raw": raw[:500]},
                raw_line=f"{url}: cookie '{name}' missing {flag}",
                remediation=knowledge["remediation"],
                impact=knowledge["impact"],
                cwe=knowledge["cwe"],
                cvss=knowledge["cvss"],
            ))
    return out


def check_redirects(target: str) -> list[Finding]:
    """Walk the redirect chain from the target and report HTTPS->HTTP
    downgrades and cross-origin hops. Redirects are followed manually so
    each hop is visible."""
    candidates = _try_urls(target)
    start = candidates[0]
    out: list[Finding] = []

    opener = _NO_REDIRECT_OPENER
    chain: list[str] = [start]
    current = start
    seen: set[str] = {current}
    max_hops = 10

    for _ in range(max_hops):
        try:
            req = urllib.request.Request(
                current, method="GET",
                headers={"User-Agent": "WHAXON-recon/1.0"},
            )
            opener.open(req, timeout=10)
            break
        except urllib.error.HTTPError as exc:
            if exc.code not in (301, 302, 303, 307, 308):
                break
            location = exc.headers.get("Location", "")
            if not location:
                break
            # Resolve relative redirects
            nxt = urllib.parse.urljoin(current, location)
            if nxt in seen:
                break
            seen.add(nxt)
            chain.append(nxt)
            # HTTPS -> HTTP downgrade?
            if current.startswith("https://") and nxt.startswith("http://"):
                out.append(Finding(
                    kind="redirect_downgrade", severity="medium",
                    source="recon:redirects",
                    data={"from": current, "to": nxt, "chain": list(chain)},
                    raw_line=f"{current} -> {nxt} (HTTPS to HTTP downgrade)",
                    remediation=(
                        "Remove the redirect to plain HTTP. Serve all content "
                        "over HTTPS and use HSTS to prevent downgrade attacks."
                    ),
                    impact=(
                        "An HTTPS-to-HTTP redirect allows a network attacker "
                        "to intercept or modify the subsequent request."
                    ),
                    cwe="CWE-319",
                    cvss=5.9,
                ))
            # Cross-origin hop?
            cur_origin = _origin(current)
            nxt_origin = _origin(nxt)
            if cur_origin and nxt_origin and cur_origin != nxt_origin:
                out.append(Finding(
                    kind="redirect_cross_origin", severity="info",
                    source="recon:redirects",
                    data={"from": current, "to": nxt,
                          "from_origin": cur_origin, "to_origin": nxt_origin},
                    raw_line=f"{current} -> {nxt} (cross-origin redirect)",
                ))
                # Report the hop but never contact the new origin: it has not
                # independently passed scope authorization.
                break
            current = nxt
        except Exception as exc:
            out.append(Finding(
                kind="recon_error", severity="info", source="recon:redirects",
                data={"target": target, "at": current, "error": str(exc)},
                raw_line=f"redirects {current} failed: {exc}",
            ))
            return out

    if len(chain) > 2:
        out.append(Finding(
            kind="redirect_chain", severity="info", source="recon:redirects",
            data={"start": start, "chain": list(chain)},
            raw_line=f"{start} -> " + " -> ".join(chain[1:]),
        ))
    return out


def _origin(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass
    return ""


_WAF_FINGERPRINTS: tuple[tuple[str, list[tuple[str, str]], list[str]], ...] = (
    # (name, header_rules, cookie_substrings)
    # header_rules: list of (header_name_lower, value_substring_lower).
    #   A rule matches when the header is present AND its value contains
    #   the substring. An empty value_substring means "any value matches".
    ("cloudflare",
     [("server", "cloudflare"), ("cf-ray", ""), ("cf-cache-status", "")],
     ["__cf_bm", "cf_clearance", "__cflb"]),
    ("akamai",
     [("server", "akamai"), ("x-akamai-transformed", "")],
     []),
    ("aws-cloudfront",
     [("server", "cloudfront"), ("x-amz-cf-id", ""), ("x-cache", "cloudfront")],
     []),
    ("aws-waf",
     [("x-amzn-waf-action", "")],
     []),
    ("imperva-incapsula",
     [("x-iinfo", ""), ("x-cdn", "incapsula"), ("server", "incapsula")],
     ["visid_incap", "incap_ses"]),
    ("sucuri",
     [("server", "sucuri"), ("x-sucuri-id", "")],
     ["sucuri_cloudproxy"]),
    ("f5-bigip",
     [("server", "big-ip"), ("server", "bigip"), ("x-wa-info", "")],
     ["bigipserver", "f5"]),
    ("fastly",
     [("server", "fastly"), ("x-served-by", "fastly"),
      ("x-fastly-request-id", "")],
     []),
    ("azure-front-door",
     [("server", "azurefd"), ("x-azure-ref", "")],
     []),
    ("barracuda",
     [("server", "barracuda")],
     ["barra_counter_session"]),
)


def check_waf(target: str) -> list[Finding]:
    """Fingerprint WAF / CDN from headers and cookies. Emits one
    waf_detected finding per match. Informational - changes testing strategy."""
    out: list[Finding] = []
    try:
        url, resp = _http_get(target, timeout=5.0)
        with resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            raw_cookies = resp.headers.get_all("Set-Cookie") or []
    except Exception as exc:
        out.append(Finding(
            kind="recon_error", severity="info", source="recon:waf",
            data={"target": target, "error": str(exc)},
            raw_line=f"waf {target} failed: {exc}",
        ))
        return out

    cookie_blob = " ".join(raw_cookies).lower()

    for name, header_rules, cookie_subs in _WAF_FINGERPRINTS:
        evidence: list[str] = []
        for header_key, value_sub in header_rules:
            if header_key not in headers:
                continue
            if value_sub == "":
                evidence.append(f"header {header_key}")
            else:
                if value_sub in str(headers[header_key]).lower():
                    evidence.append(f"header {header_key}~{value_sub}")
        for cs in cookie_subs:
            if cs in cookie_blob:
                evidence.append(f"cookie {cs}")
        if not evidence:
            continue
        out.append(Finding(
            kind="waf_detected", severity="info", source="recon:waf",
            data={"url": url, "waf": name, "evidence": evidence},
            raw_line=f"{url}: WAF/CDN detected -> {name} ({', '.join(evidence)})",
            remediation=(
                "No action required. Presence of a WAF changes testing strategy - "
                "some payloads may be blocked. Record the WAF type for the "
                "engagement so bypass research is scoped appropriately."
            ),
            impact=(
                "A WAF may block or filter active testing. Knowing its type "
                "lets the tester choose appropriate payloads and rate limits."
            ),
        ))
    return out




def check_dns_full(target: str) -> list[Finding]:
    """Query CAA, DMARC, and SPF. These control certificate issuance and
    email spoofing policy. Distinct from check_dns (which does A/AAAA/MX/
    NS/TXT/SOA) because the reasoning and findings differ."""
    import dns.exception
    import dns.resolver

    host = _as_host(target)
    out: list[Finding] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    # --- CAA: which CAs may issue certs for this host ---
    try:
        answers = resolver.resolve(host, "CAA", raise_on_no_answer=False)
        if answers.rrset is not None:
            for rr in answers:
                out.append(Finding(
                    kind="dns_caa", severity="info", source="recon:dns_full",
                    data={"host": host, "value": rr.to_text()},
                    raw_line=f"{host} CAA {rr.to_text()}",
                ))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.NoAnswer):
        out.append(Finding(
            kind="dns_caa_missing", severity="info", source="recon:dns_full",
            data={"host": host},
            raw_line=f"{host}: no CAA record",
            remediation=(
                "Publish a CAA record naming the CAs authorised to issue "
                "certificates for this domain (e.g. '0 issue \"letsencrypt.org\"')."
            ),
            impact=(
                "Without CAA, any CA can issue a certificate for this domain, "
                "widening the misissuance surface."
            ),
            cwe="CWE-295",
        ))

    # --- DMARC: email spoofing policy on _dmarc.<host> ---
    dmarc_name = f"_dmarc.{host}"
    try:
        answers = resolver.resolve(dmarc_name, "TXT", raise_on_no_answer=False)
        if answers.rrset is None:
            raise dns.resolver.NoAnswer
        for rr in answers:
            value = rr.to_text().strip('"')
            if not value.lower().startswith("v=dmarc1"):
                continue
            policy = "none"
            for part in value.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    policy = part.split("=", 1)[1].strip().lower()
                    break
            if policy == "none":
                out.append(Finding(
                    kind="dns_dmarc_permissive", severity="medium",
                    source="recon:dns_full",
                    data={"host": host, "record": value, "policy": policy},
                    raw_line=f"{dmarc_name}: DMARC p=none ({value})",
                    remediation=(
                        "Move DMARC from p=none to p=quarantine, then p=reject "
                        "once alignment is verified."
                    ),
                    impact=(
                        "DMARC p=none means a spoofed email fails the policy "
                        "check but is still delivered - no protection against "
                        "sender forgery."
                    ),
                    cwe="CWE-290",
                    cvss=5.3,
                ))
            else:
                out.append(Finding(
                    kind="dns_dmarc", severity="info", source="recon:dns_full",
                    data={"host": host, "record": value, "policy": policy},
                    raw_line=f"{dmarc_name}: DMARC p={policy}",
                ))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.NoAnswer):
        out.append(Finding(
            kind="dns_dmarc_missing", severity="medium", source="recon:dns_full",
            data={"host": host},
            raw_line=f"{dmarc_name}: no DMARC record",
            remediation=(
                "Publish a DMARC record at _dmarc.<domain> with at least "
                "v=DMARC1; p=quarantine."
            ),
            impact=(
                "Without DMARC, email from this domain can be forged without "
                "any policy check, enabling phishing from the legitimate domain."
            ),
            cwe="CWE-290",
            cvss=5.3,
        ))

    # --- SPF: parse TXT records on the host itself ---
    try:
        answers = resolver.resolve(host, "TXT", raise_on_no_answer=False)
        spf_found = None
        if answers.rrset is not None:
            for rr in answers:
                value = rr.to_text().strip('"')
                if value.lower().startswith("v=spf1"):
                    spf_found = value
                    break
        if spf_found is None:
            raise dns.resolver.NoAnswer
        if "-all" in spf_found or "~all" in spf_found:
            severity = "info"
        elif "?all" in spf_found or "+all" in spf_found:
            severity = "medium"
        else:
            severity = "low"
        out.append(Finding(
            kind="dns_spf", severity=severity, source="recon:dns_full",
            data={"host": host, "record": spf_found},
            raw_line=f"{host} SPF {spf_found}",
            remediation=(
                "Use '-all' (hard fail) once all legitimate senders are "
                "enumerated. '+all' or '?all' are permissive and allow spoofing."
            ) if severity == "medium" else "",
            impact=(
                "A permissive SPF qualifier allows unauthorised senders to "
                "send mail as this domain."
            ) if severity == "medium" else "",
            cwe="CWE-290" if severity == "medium" else "",
            cvss=5.3 if severity == "medium" else None,
        ))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.NoAnswer):
        out.append(Finding(
            kind="dns_spf_missing", severity="medium", source="recon:dns_full",
            data={"host": host},
            raw_line=f"{host}: no SPF record",
            remediation=(
                "Publish an SPF record (v=spf1 ... -all) naming the authorised "
                "senders for this domain."
            ),
            impact=(
                "Without SPF, any host can send email claiming to be from this "
                "domain, enabling phishing and BEC."
            ),
            cwe="CWE-290",
            cvss=5.3,
        ))

    return out
