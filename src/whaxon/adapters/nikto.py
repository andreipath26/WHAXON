"""Nikto adapter — issue-based parsing with remediation knowledge."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..core.findings import Finding
from .base import Adapter
from .registry import register

# "+ /admin/: Directory indexing found."
_ISSUE_RE = re.compile(r"^\+\s+(?P<body>.+)$")

# Lines that are scan metadata, not issues
_NOISE_PREFIXES = (
    "+ Target IP:",
    "+ Target Hostname:",
    "+ Target Port:",
    "+ Start Time:",
    "+ End Time:",
    "+ Server:",
    "+ 0 host",
    "+ 1 host",
    "+ No web server found",
)

# Path extraction: "+ /path: message" or "+ OSVDB-1234: /path: message"
_PATH_RE = re.compile(r"(?P<path>/(?:[A-Za-z0-9_\-./]*[A-Za-z0-9_\-/])?)")
_OSVDB_RE = re.compile(r"OSVDB-(\d+)")
_NIKTO_ID_RE = re.compile(r"^\[(?P<id>\d+)\]\s*")
_SEE_RE = re.compile(r"\s+See:\s*<?(?P<url>https?://[^\s)>]+)>?\s*$", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s)>]+", re.IGNORECASE)


# (pattern, severity, cwe, cvss, remediation, impact)
# Patterns are matched (case-insensitive) against the issue body.
ISSUE_PATTERNS: list[tuple[str, str, str, float | None, str, str]] = [
    (
        r"spring boot actuator|actuator endpoint",
        "high", "CWE-200", 7.5,
        "Disable unused Spring Boot Actuator endpoints. Expose only the minimum required endpoints, "
        "bind management endpoints to an internal interface, and require strong authentication "
        "and network-level access controls. Rotate any secrets disclosed by the endpoint.",
        "Exposed Actuator endpoints can disclose environment variables, configuration, mappings, "
        "beans, and operational details; some enabled endpoints may permit sensitive state changes.",
    ),
    (
        r"directory indexing|directory listing|directory is browsable|browsable directory",
        "medium", "CWE-548", 5.3,
        "Disable directory listing in the web server configuration. "
        "For Apache, set `Options -Indexes` in the affected directory or globally. "
        "For nginx, remove `autoindex on`. For IIS, disable Directory Browsing.",
        "Directory listings disclose file names and structure, aiding reconnaissance "
        "and exposing files not intended for public access.",
    ),
    (
        r"database backup file|backup\.sql|\.sql file|db backup",
        "high", "CWE-530", 7.5,
        "Remove backup files from the web root immediately. If they must be stored, "
        "place them outside the document root and restrict access. Add a rule to your "
        "deployment pipeline that prevents committing or uploading backup files.",
        "Database dumps often contain credentials, personal data, and full schema "
        "information. Exposure typically leads to full application compromise.",
    ),
    (
        r"phpinfo|php configuration",
        "high", "CWE-200", 7.5,
        "Remove phpinfo() calls from production code. Restrict access to any "
        "legitimate diagnostic pages by IP or via HTTP authentication.",
        "phpinfo pages disclose PHP configuration, environment variables, module "
        "versions, and often filesystem paths — valuable for targeted exploitation.",
    ),
    (
        r"server-status|server-info",
        "medium", "CWE-200", 5.3,
        "Restrict /server-status and /server-info to localhost or an internal "
        "monitoring network via the web server configuration.",
        "The Apache status page reveals active requests, client IPs, and internal "
        "URLs — useful for mapping the application.",
    ),
    (
        r"\.git|git repository|git config",
        "high", "CWE-538", 7.5,
        "Block access to .git, .svn, and .hg directories at the web server level. "
        "Ensure deployment scripts do not copy VCS metadata into the web root.",
        "Exposed Git metadata permits source code reconstruction, sometimes including "
        "hardcoded credentials and full application logic.",
    ),
    (
        r"\.env|environment file|dotenv",
        "critical", "CWE-538", 9.1,
        "Never deploy .env files to the web root. Add them to .gitignore and to "
        "your deployment exclusion list. Rotate any credentials that were exposed.",
        "Environment files commonly contain database credentials, API keys, and "
        "application secrets — direct path to full compromise.",
    ),
    (
        r"admin panel|admin login|/admin/|administrator",
        "info", "CWE-284", None,
        "Ensure administrative interfaces require strong authentication (MFA where "
        "possible) and are restricted by IP or VPN when feasible.",
        "Exposed admin panels expand the attack surface for credential attacks.",
    ),
    (
        r"x-frame-options|clickjacking",
        "low", "CWE-1021", 4.3,
        "Set the X-Frame-Options header to DENY or SAMEORIGIN. Modern alternative: "
        "use the Content-Security-Policy `frame-ancestors` directive.",
        "Missing frame protections allow the application to be embedded in attacker-"
        "controlled pages, enabling clickjacking.",
    ),
    (
        r"strict-transport-security|hsts",
        "low", "CWE-319", 4.3,
        "Enable HSTS with a max-age of at least 6 months: "
        "`Strict-Transport-Security: max-age=15768000; includeSubDomains`.",
        "Without HSTS, users are vulnerable to SSL-stripping attacks on first visit.",
    ),
    (
        r"x-content-type-options|mime sniffing",
        "low", "CWE-16", 3.7,
        "Send `X-Content-Type-Options: nosniff` on every response. This is a "
        "one-line change in most web server configurations.",
        "MIME sniffing can cause browsers to interpret content as a different type "
        "than intended, sometimes leading to script execution.",
    ),
    (
        r"allowed http methods|put method|delete method|trace method",
        "medium", "CWE-650", 5.3,
        "Restrict HTTP methods at the web server or application layer. Allow only "
        "the verbs your application uses (typically GET, POST, HEAD). Disable TRACE.",
        "Unnecessary HTTP methods increase the attack surface and can permit file "
        "upload (PUT) or deletion (DELETE) if authorization is weak.",
    ),
    (
        r"cgi-bin|shellshock|cgi script",
        "high", "CWE-78", 8.1,
        "Remove unused CGI scripts. If CGI is required, isolate it from the main "
        "site and patch the interpreter. Shellshock-class vulnerabilities remain "
        "exploitable on unpatched systems.",
        "Legacy CGI scripts frequently contain command-injection and known CVEs.",
    ),
    (
        r"robots\.txt|sitemap",
        "info", "", None,
        "Review robots.txt for paths you did not intend to advertise — it often "
        "reveals administrative or staging URLs.",
        "robots.txt is a reconnaissance aid; it disallows nothing for malicious clients.",
    ),
    (
        r"\bvulnerable to\b|remote code execution|command injection|\brce\b",
        "critical", "", 9.0,
        "Investigate the referenced CVE immediately. Confirm the affected version, "
        "apply the vendor patch, and treat the affected host as compromised until "
        "proven otherwise.",
        "Reported as a known vulnerability or RCE-class issue — direct path to "
        "system compromise if confirmed.",
    ),
]


class NiktoAdapter(Adapter):
    tool_id = "nikto"

    def parse(self, lines, ctx=None):
        findings = []
        seen_keys = set()

        for stream, text in lines:
            if stream != "stdout":
                continue
            stripped = text.strip()

            # Skip metadata lines
            if any(stripped.startswith(p) for p in _NOISE_PREFIXES):
                continue

            m = _ISSUE_RE.match(stripped)
            if not m:
                continue
            body = m.group("body").strip()
            if not body:
                continue

            id_match = _NIKTO_ID_RE.match(body)
            nikto_id = id_match.group("id") if id_match else ""
            if id_match:
                body = body[id_match.end():].strip()

            see_match = _SEE_RE.search(body)
            see_url = see_match.group("url").rstrip(".,;") if see_match else ""
            if see_match:
                body = body[:see_match.start()].rstrip()

            # Prefer a complete URL's parsed path. A generic slash regex sees
            # the // in http:// and can otherwise report the authority as a path.
            url_match = _URL_RE.search(body)
            if url_match:
                try:
                    url_text = url_match.group(0).rstrip(".,;:")
                    path = urlsplit(url_text).path or "/"
                except ValueError:
                    path = ""
            else:
                path_match = _PATH_RE.search(body)
                path = path_match.group("path") if path_match else ""

            osvdb_match = _OSVDB_RE.search(body)
            osvdb = f"OSVDB-{osvdb_match.group(1)}" if osvdb_match else ""

            # Dedup: same plugin/path/message is one finding.
            key = (nikto_id, path, body.lower())
            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Match against knowledge table
            severity, cwe, cvss, remediation, impact = "info", "", None, "", ""
            body_lower = body.lower()
            for pattern, sev, c, score, rem, imp in ISSUE_PATTERNS:
                if re.search(pattern, body_lower):
                    severity, cwe, cvss = sev, c, score
                    remediation, impact = rem, imp
                    break

            refs = []
            if osvdb:
                refs.append(osvdb)
            if nikto_id:
                refs.append(f"Nikto-{nikto_id}")
            if see_url:
                refs.append(see_url)

            finding_data = {"path": path, "message": body}
            if url_match:
                finding_data["url"] = url_text
            if nikto_id:
                finding_data["nikto_id"] = nikto_id
            if see_url:
                finding_data["see"] = see_url

            findings.append(Finding(
                kind="web_issue",
                severity=severity,
                source="nikto",
                data=finding_data,
                raw_line=stripped,
                remediation=remediation,
                impact=impact,
                cvss=cvss,
                cwe=cwe,
                references=tuple(refs),
            ))

        return findings


register(NiktoAdapter())
