"""Severity classification regression tests.

A finding's severity must reflect what the finding IS, not what appears in
its raw line. A CVE identifier in a reference URL is a reference, not a
claim of exploitability. These tests lock that in for the adapters whose
severity comes from pattern matching or keyword heuristics.

Each adapter that classifies by pattern gets two corpora:
- SAFE_LINES: raw lines that must NOT be elevated above their semantic
  severity. These are the regression cases for the nikto CVE-URL bug.
- MUST_FIRE: raw lines that genuinely describe a critical-class issue and
  must classify as critical.
"""
from __future__ import annotations

from whaxon.adapters.nikto import NiktoAdapter


def _classify_nikto(raw_line: str) -> str:
    adapter = NiktoAdapter()
    findings = adapter.parse([("stdout", raw_line)])
    if not findings:
        return "none"
    return findings[0].severity


NIKTO_SAFE_LINES = [
    (
        "+ [001213] /doc/: The /doc/ directory is browsable. See: https://nvd.nist.gov/vuln/detail/CVE-1999-0678",
        "medium",
    ),
    (
        "+ [999984] /phpMyAdmin/ChangeLog: Server may leak inodes via ETags, header found with file /phpMyAdmin/ChangeLog. See: https://nvd.nist.gov/vuln/detail/CVE-1999-0678",
        "info",
    ),
    (
        "+ [002989] /phpinfo.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.",
        "high",
    ),
    (
        "+ [007224] /.gitignore: .gitignore file found. It is possible to grasp the directory structure.",
        "high",
    ),
]


NIKTO_MUST_FIRE = [
    (
        "+ [005678] /api/: The application is vulnerable to command injection.",
        "critical",
    ),
    (
        "+ [009999] /login: Command injection in the username parameter.",
        "critical",
    ),
]


def test_nikto_safe_lines_are_not_critical():
    for raw_line, expected in NIKTO_SAFE_LINES:
        got = _classify_nikto(raw_line)
        assert got != "critical", f"safe line classified as critical: {raw_line[:80]}"
        assert got == expected, f"expected {expected}, got {got} for: {raw_line[:80]}"


def test_nikto_critical_lines_fire():
    for raw_line, expected in NIKTO_MUST_FIRE:
        got = _classify_nikto(raw_line)
        assert got == expected, f"expected {expected}, got {got} for: {raw_line[:80]}"


def test_nikto_cve_url_alone_is_not_critical():
    raw_line = "+ [000000] /whatever: Something benign. See: https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
    got = _classify_nikto(raw_line)
    assert got != "critical", f"CVE URL alone promoted to {got}"
