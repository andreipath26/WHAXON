"""WhatWeb adapter — web technology fingerprinting.

Prefers JSON output (via --log-json=FILE in extra_args). Falls back
to the text line format when JSON isn't available.

Text format (one line per target):
    http://target/ [200 OK] Apache[2.4.7], Country[RESERVED][ZZ], IP[1.2.3.4], Title[...]

JSON format (array of target objects):
    [{"target": "http://...", "http_status": 200, "plugins": {...}}, ...]

Enrichment focuses on technologies where the version matters for
known-vulnerability correlation: web server, PHP, WordPress, jQuery.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..core.findings import Finding
from .base import Adapter
from .registry import register


_TEXT_RE = re.compile(r"^(?P<url>https?://\S+)\s+\[(?P<status>\d+)[^\]]*\]\s*(?P<plugins>.+)$")
_TEXT_PLUGIN_RE = re.compile(r"(?P<name>[A-Za-z][A-Za-z0-9_\-\.]+)(?:\[(?P<val>[^\]]*)\])?")
_LOG_JSON_RE = re.compile(r"--log-json=(\S+)")


# Enrichment per detected technology. Matched case-insensitively against
# the plugin name. Version-specific info stays in the finding data; the
# enrichment here is generic per-technology.
_TECH_KNOWLEDGE = {
    "wordpress": {
        "cwe": "CWE-1104",
        "remediation": (
            "Keep WordPress core, plugins, and themes up to date. Remove unused "
            "plugins and themes. Use a security plugin to restrict login attempts "
            "and enable two-factor authentication."
        ),
        "impact": (
            "WordPress is a high-value target: plugin vulnerabilities, weak "
            "credentials, and misconfigurations are common. Version disclosure "
            "narrows the exploit search."
        ),
    },
    "php": {
        "cwe": "CWE-1104",
        "remediation": "Keep PHP patched. Remove or disable unused modules.",
        "impact": "PHP version disclosure helps identify known CVEs.",
    },
    "jquery": {
        "cwe": "CWE-1104",
        "remediation": (
            "Update jQuery to the latest release. Older versions have known XSS "
            "issues. Consider migrating away from jQuery to modern browser APIs."
        ),
        "impact": (
            "Older jQuery versions have published XSS vulnerabilities, "
            "particularly in the AJAX handling and DOM manipulation APIs."
        ),
    },
    "apache": {
        "cwe": "",
        "remediation": "Keep Apache patched. Review ServerTokens / ServerSignature settings.",
        "impact": "Version disclosure helps match against Apache CVEs and known misconfigs.",
    },
    "nginx": {
        "cwe": "",
        "remediation": "Keep nginx patched. Set server_tokens off to suppress version.",
        "impact": "Version disclosure helps match against nginx CVEs.",
    },
    "openssl": {
        "cwe": "CWE-1104",
        "remediation": "Update OpenSSL to the latest stable release.",
        "impact": "Old OpenSSL versions carry known CVEs, including Heartbleed-class issues.",
    },
}


def _mk_finding(plugin_name, raw_line, data, severity="info"):
    kn = _TECH_KNOWLEDGE.get(plugin_name.lower(), {})
    return Finding(
        kind="tech_detected",
        severity=severity,
        source="whatweb",
        data=data,
        raw_line=raw_line,
        remediation=kn.get("remediation", ""),
        impact=kn.get("impact", ""),
        cwe=kn.get("cwe", ""),
    )


class WhatwebAdapter(Adapter):
    tool_id = "whatweb"

    # ---- JSON path ----

    def _parse_json_file(self, path: str) -> list[Finding]:
        p = Path(path)
        if not p.exists():
            return []
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return []
        if not isinstance(data, list):
            return []

        findings = []
        for entry in data:
            target = entry.get("target", "")
            status = entry.get("http_status")
            plugins = entry.get("plugins") or {}
            for plugin_name, plugin_data in plugins.items():
                # Extract a "version" field if present, else the whole plugin dict
                version = ""
                if isinstance(plugin_data, dict):
                    v = plugin_data.get("version")
                    if isinstance(v, list) and v:
                        version = str(v[0])
                    elif isinstance(v, str):
                        version = v
                findings.append(_mk_finding(
                    plugin_name,
                    raw_line=f"{target} {plugin_name}[{version}]",
                    data={
                        "target": target,
                        "status": status,
                        "plugin": plugin_name,
                        "version": version,
                    },
                ))
        return findings

    # ---- text path ----

    def _parse_text(self, lines) -> list[Finding]:
        findings = []
        for stream, text in lines:
            if stream != "stdout":
                continue
            m = _TEXT_RE.match(text.strip())
            if not m:
                continue
            target = m.group("url")
            status = int(m.group("status"))
            plugins_blob = m.group("plugins")

            for pm in _TEXT_PLUGIN_RE.finditer(plugins_blob):
                name = pm.group("name")
                val = pm.group("val") or ""
                # First bracket group is usually the version
                version = val.split("][")[0] if val else ""
                findings.append(_mk_finding(
                    name,
                    raw_line=text,
                    data={
                        "target": target,
                        "status": status,
                        "plugin": name,
                        "version": version,
                    },
                ))
        return findings

    # ---- dispatch ----

    def parse(self, lines, ctx=None):
        ctx = ctx or {}
        extra = ctx.get("extra_args") or ""
        m = _LOG_JSON_RE.search(extra)
        if m:
            json_findings = self._parse_json_file(m.group(1))
            if json_findings:
                return json_findings
            # fall through to text if the JSON file was missing/empty
        return self._parse_text(lines)


register(WhatwebAdapter())