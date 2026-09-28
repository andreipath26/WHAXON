"""Tests for the four adapters added in session 4.

Each adapter wraps a parser that already existed in core/findings.py,
but adds CVE/CWE/remediation/impact metadata at parse time. The tests
feed small, realistic samples and assert on the enriched output.
"""
from __future__ import annotations

from whaxon.adapters.ffuf import FfufAdapter
from whaxon.adapters.gobuster import GobusterAdapter
from whaxon.adapters.nuclei import NucleiAdapter
from whaxon.adapters.wpscan import WpscanAdapter


def _stdout(lines):
    return [("stdout", l) for l in lines]


# ---------------------------------------------------------------- gobuster

def test_gobuster_parses_200_with_enrichment():
    lines = _stdout([
        "===============================================================",
        "Gobuster v3.8.2",
        "/admin                (Status: 200) [Size: 1234]",
        "/login                (Status: 200) [Size: 4096]",
        "/notfound             (Status: 404) [Size: 0]",
        "/api                  (Status: 403) [Size: 512]",
    ])
    findings = GobusterAdapter().parse(lines)
    assert len(findings) == 3  # 404 filtered out
    by_path = {f.data["path"]: f for f in findings}
    assert "/admin" in by_path
    assert by_path["/admin"].severity == "low"
    assert by_path["/admin"].cvss == 3.7
    assert by_path["/admin"].cwe == "CWE-200"
    assert by_path["/admin"].remediation  # non-empty
    assert by_path["/admin"].data["status"] == 200
    assert by_path["/api"].severity == "info"


def test_gobuster_ignores_stderr_and_non_matching():
    lines = [
        ("stderr", "/admin (Status: 200) [Size: 100]"),
        ("stdout", "Starting gobuster in directory mode"),
        ("stdout", "Progress: 100/5000"),
    ]
    assert GobusterAdapter().parse(lines) == []


# ---------------------------------------------------------------- ffuf

def test_ffuf_parses_status_lines():
    lines = _stdout([
        "admin                  [Status: 200, Size: 1234]",
        "login                  [Status: 200, Size: 2048]",
        "secret                 [Status: 403, Size: 512]",
        "missing                [Status: 404, Size: 0]",
    ])
    findings = FfufAdapter().parse(lines)
    assert len(findings) == 3  # 404 filtered
    paths = {f.data["path"] for f in findings}
    assert paths == {"admin", "login", "secret"}
    admin = next(f for f in findings if f.data["path"] == "admin")
    assert admin.severity == "low"
    assert admin.cvss == 3.7


def test_ffuf_handles_silent_mode_without_status():
    lines = _stdout(["admin", "login", "index.html"])
    findings = FfufAdapter().parse(lines)
    # No status given, defaults to 200, kept
    assert len(findings) == 3
    assert all(f.data["status"] == 200 for f in findings)


# ---------------------------------------------------------------- nuclei

def test_nuclei_parses_cve_finding():
    lines = _stdout([
        "[critical] [CVE-2021-44228] https://target.example.com/api",
        "[high] [CVE-2021-41773] https://target.example.com/cgi-bin/",
    ])
    findings = NucleiAdapter().parse(lines)
    assert len(findings) == 2
    log4shell = findings[0]
    assert log4shell.severity == "critical"
    assert log4shell.data["template"] == "CVE-2021-44228"
    assert log4shell.cvss == 9.8
    assert log4shell.cwe == "CWE-1395"  # CVE- prefix maps to unclassified
    assert log4shell.remediation  # non-empty


def test_nuclei_parses_misconfig_template():
    lines = _stdout([
        "[medium] [exposed-git-config] https://target.example.com/.git/config",
        "[info] [tech-detect:nginx] https://target.example.com/ [nginx]",
    ])
    findings = NucleiAdapter().parse(lines)
    git = findings[0]
    assert git.severity == "medium"
    assert git.cvss == 5.3
    assert git.cwe == "CWE-200"  # "exposure"/"disclosure" family


def test_nuclei_skips_non_matching():
    lines = _stdout([
        "Running nuclei v3.0",
        "Templates loaded: 5432",
    ])
    assert NucleiAdapter().parse(lines) == []


# ---------------------------------------------------------------- wpscan

def test_wpscan_parses_version_and_vuln():
    lines = _stdout([
        "[+] WordPress version 5.8 identified (Insecure, released on 2021-05-13)",
        "[!] Title: WordPress 3.7-5.8.1 - SQL Injection",
        "[i] Plugin name: wp-discuz (v1.0.0)",
    ])
    findings = WpscanAdapter().parse(lines)
    assert len(findings) == 3

    version = next(f for f in findings if f.kind == "wp_version")
    assert version.severity == "medium"  # flagged Insecure
    assert version.data["version"] == "5.8"

    vuln = next(f for f in findings if f.kind == "wp_vulnerability")
    assert vuln.severity == "high"
    assert vuln.cvss == 7.5
    assert "SQL Injection" in vuln.data["title"]
    assert vuln.remediation  # non-empty

    plugin = next(f for f in findings if f.kind == "wp_plugin")
    assert plugin.severity == "info"
    assert plugin.data["name"] == "wp-discuz"


def test_wpscan_parses_current_version():
    lines = _stdout([
        "[+] WordPress version 6.4.3 identified",
    ])
    findings = WpscanAdapter().parse(lines)
    assert len(findings) == 1
    assert findings[0].severity == "info"  # no Insecure flag