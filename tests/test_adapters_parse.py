"""Tests for the adapters parse() methods that lacked coverage.

Covers nmap, nikto, sqlmap, burp, and hashcat parse paths. Each test
feeds a small sample of realistic tool output and asserts on the
resulting Finding objects.
"""
from __future__ import annotations

from pathlib import Path

from whaxon.adapters.burp import BurpAdapter
from whaxon.adapters.hashcat import _find_hashes
from whaxon.adapters.nikto import NiktoAdapter
from whaxon.adapters.nmap import NmapAdapter
from whaxon.adapters.sqlmap import SqlmapAdapter
from whaxon.core.store import JobStore


def _stdout(lines):
    return [("stdout", l) for l in lines]


# ---------- nmap ----------


def test_nmap_parses_open_ports_with_severity():
    lines = _stdout([
        "22/tcp   open  ssh     OpenSSH 8.2p1",
        "3306/tcp open  mysql   MySQL 5.7.30",
        "12345/tcp open unknown",
        "54321/tcp open unknown",
    ])
    findings = NmapAdapter().parse(lines)
    assert len(findings) == 4
    by_port = {f.data["port"]: f for f in findings}
    assert by_port[22].severity == "medium"
    assert by_port[3306].severity == "high"
    assert by_port[12345].severity == "medium"
    assert by_port[54321].severity == "info"
    assert all(f.kind == "open_port" for f in findings)


def test_nmap_ignores_stderr_and_non_matching_lines():
    lines = [
        ("stderr", "22/tcp open ssh"),
        ("stdout", "Starting Nmap 7.80"),
        ("stdout", "Host is up"),
    ]
    assert NmapAdapter().parse(lines) == []


# ---------- nikto ----------


def test_nikto_parses_issues():
    lines = _stdout([
        "+ Target IP: 10.0.0.5",
        "+ /admin/: Directory indexing found.",
        "+ /backup.zip: Backup file found.",
        "+ End Time: 2026-09-28",
    ])
    findings = NiktoAdapter().parse(lines)
    assert len(findings) == 2
    assert all(f.kind == "web_issue" for f in findings)
    paths = {f.data["path"] for f in findings}
    assert "/admin/" in paths
    assert "/backup.zip" in paths


def test_nikto_dedups_same_issue_on_same_path():
    lines = _stdout([
        "+ /admin/: Directory indexing found.",
        "+ /admin/: Directory indexing found.",
    ])
    findings = NiktoAdapter().parse(lines)
    assert len(findings) == 1


# ---------- sqlmap ----------


def test_sqlmap_parses_injectable_parameter():
    lines = _stdout([
        "Parameter: id (GET)",
        "    Type: boolean-based blind",
        "    Title: AND boolean-based blind",
        "    Payload: id=1 AND 1234=1234",
    ])
    findings = SqlmapAdapter().parse(lines)
    assert len(findings) >= 1
    sqli = [f for f in findings if f.kind == "sqli"]
    assert len(sqli) == 1
    assert sqli[0].data["parameter"] == "id"
    assert sqli[0].severity == "critical"


def test_sqlmap_parses_current_database_info():
    lines = _stdout(["current database: 'dvwa'"])
    findings = SqlmapAdapter().parse(lines)
    assert len(findings) == 1
    assert findings[0].kind == "sqli_info"
    assert findings[0].data["value"] == "dvwa"


# ---------- burp ----------


BURP_XML = (
    "<issues>"
    "<issue>"
    "<name>SQL injection</name>"
    "<severity>High</severity>"
    "<confidence>Certain</confidence>"
    "<host>example.com</host>"
    "<path>/login</path>"
    "<location>https://example.com/login</location>"
    "</issue>"
    "<issue>"
    "<name>Cookie without HttpOnly</name>"
    "<severity>Low</severity>"
    "<host>example.com</host>"
    "<path>/</path>"
    "</issue>"
    "</issues>"
)


def test_burp_parses_xml_file(tmp_path):
    xml_file = tmp_path / "burp.xml"
    xml_file.write_text(BURP_XML)
    findings = BurpAdapter().parse_file(xml_file)
    assert len(findings) == 2
    assert all(f.kind == "web_issue" for f in findings)
    sevs = {f.data["name"]: f.severity for f in findings}
    assert sevs["SQL injection"] == "high"
    assert sevs["Cookie without HttpOnly"] == "low"


def test_burp_returns_empty_on_missing_file():
    findings = BurpAdapter().parse_file(Path("/tmp/does-not-exist-burp.xml"))
    assert findings == []


# ---------- hashcat ----------


def test_hashcat_find_hashes_reads_ntlm_from_store(tmp_path):
    store = JobStore(tmp_path / "h.db")
    store.create("j1")
    store.set_started("j1", "impacket", "10.0.0.5")
    store.append_finding("j1", {
        "kind": "ntlm_hash", "severity": "critical", "source": "impacket",
        "data": {"user": "alice", "nt_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
        "raw_line": "alice",
    }, 0)
    store.set_finished("j1", 0, 0.1)
    hashes = _find_hashes(store)
    assert len(hashes) == 1
    assert hashes[0]["user"] == "alice"
    assert hashes[0]["nt_hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
