"""WPScan adapter — WordPress version and vulnerability findings.

WPScan output lines we care about:
    [+] WordPress version 5.8 identified (Insecure, released on 2021-05-13)
    [+] WordPress version 5.8 identified
    [!] Title: WordPress 3.7-5.8.1 - SQL Injection
    [i] Plugin name: wp-discuz (v1.0.0)
"""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register

_VERSION_RE = re.compile(
    r"^\[\+\]\s+WordPress version (?P<v>[\d.]+)\s+identified"
    r"(?P<flag>\s+\((?:Insecure|Latest|Outdated)[^)]*\))?"
)
_VULN_RE = re.compile(r"^\[!\]\s+Title:\s*(?P<title>.+)")
_PLUGIN_RE = re.compile(r"^\[i\]\s+Plugin name:\s*(?P<name>\S+)\s*(?:\(v(?P<v>[^)]+)\))?")
_THEME_RE = re.compile(r"^\[i\]\s+Theme name:\s*(?P<name>\S+)\s*(?:\(v(?P<v>[^)]+)\))?")


# Known vulnerable WordPress version ranges. Kept small — anything not in
# here falls through to "info" severity. This is a starting point, not
# a vulnerability database.
_KNOWN_BAD_VERSIONS = {
    # (max_insecure_version): (severity, cwe, cvss, remediation, impact)
}


class WpscanAdapter(Adapter):
    tool_id = "wpscan"

    def parse(self, lines, ctx=None):
        findings = []
        for stream, text in lines:
            if stream != "stdout":
                continue
            stripped = text.strip()

            # Vulnerability title — highest signal
            m = _VULN_RE.match(stripped)
            if m:
                title = m.group("title").strip()
                findings.append(Finding(
                    kind="wp_vulnerability",
                    severity="high",
                    source="wpscan",
                    data={"title": title},
                    raw_line=text,
                    remediation=(
                        "Apply the WordPress security update that fixes this issue. "
                        "Check the plugin/theme release notes for the fixed version "
                        "range and update to at least that version."
                    ),
                    impact=(
                        "WPScan matched this WordPress installation against a known "
                        "vulnerability. The impact depends on the specific issue — "
                        "consult the WPScan advisory for the affected component and "
                        "attack vector."
                    ),
                    cvss=7.5,
                    cwe="CWE-1395",
                ))
                continue

            # WordPress core version
            m = _VERSION_RE.match(stripped)
            if m:
                version = m.group("v")
                flag = (m.group("flag") or "").lower()
                severity = "medium" if "insecure" in flag else "info"
                findings.append(Finding(
                    kind="wp_version",
                    severity=severity,
                    source="wpscan",
                    data={"version": version, "flag": flag.strip("() ")},
                    raw_line=text,
                    remediation=(
                        "Update WordPress core to the latest stable release. "
                        "Enable automatic minor updates if the environment allows it."
                    ),
                    impact=(
                        "Known WordPress versions narrow the attack surface a "
                        "scanner has to enumerate. Outdated versions often have "
                        "public exploits available."
                    ),
                    cvss=5.3 if severity == "medium" else None,
                    cwe="CWE-1104",
                ))
                continue

            # Plugins (informational)
            m = _PLUGIN_RE.match(stripped)
            if m:
                findings.append(Finding(
                    kind="wp_plugin",
                    severity="info",
                    source="wpscan",
                    data={"name": m.group("name"), "version": m.group("v") or ""},
                    raw_line=text,
                ))
                continue

            # Themes (informational)
            m = _THEME_RE.match(stripped)
            if m:
                findings.append(Finding(
                    kind="wp_theme",
                    severity="info",
                    source="wpscan",
                    data={"name": m.group("name"), "version": m.group("v") or ""},
                    raw_line=text,
                ))
        return findings


register(WpscanAdapter())