"""Report renders a Session Findings section (step 7 of session-execution)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from whaxon.core import report as _report
from whaxon.core.store import JobStore


@pytest.fixture
def store(tmp_path: Path) -> JobStore:
    return JobStore(tmp_path / "db.sqlite")


def _seed_session_finding(store: JobStore, job_id: str = "j1") -> None:
    store.create(job_id)
    store.set_started(job_id, "msf_sysinfo", "session:3")
    store.append_finding(job_id, {
        "kind": "sysinfo",
        "severity": "info",
        "source": "msf_sysinfo",
        "data": {"field": "current_user", "value": "root", "session_id": "3"},
        "raw_line": "current_user: root",
    }, 0)
    store.set_finished(job_id, 0, 0.1)


def test_load_collects_session_findings(store: JobStore) -> None:
    _seed_session_finding(store)
    data = _report._load(store, "default")
    assert "session_findings" in data
    assert len(data["session_findings"]) == 1
    f = data["session_findings"][0]
    assert f["source"] == "msf_sysinfo"
    assert f["data"]["session_id"] == "3"
    assert f["_job_id"] == "j1"


def test_load_ignores_non_session_findings(store: JobStore) -> None:
    store.create("j2")
    store.set_started("j2", "nmap", "10.0.0.5")
    store.append_finding("j2", {
        "kind": "open_port", "severity": "info", "source": "nmap",
        "data": {"port": 80}, "raw_line": "80/tcp open",
    }, 0)
    store.set_finished("j2", 0, 0.1)
    data = _report._load(store, "default")
    assert data["session_findings"] == []


def test_md_session_findings_renders_section() -> None:
    md: list[str] = []
    findings = [{
        "source": "msf_sysinfo",
        "kind": "sysinfo",
        "data": {"field": "current_user", "value": "root", "session_id": "3"},
        "raw_line": "current_user: root",
        "_job_id": "j1",
    }]
    _report._md_session_findings(md, findings)
    text = "\n".join(md)
    assert "## Session Findings" in text
    assert "msf_sysinfo" in text
    assert "current_user" in text
    assert "root" in text
    assert "| 3 |" in text or "| 3 " in text


def test_md_session_findings_renders_ntlm_hash() -> None:
    md: list[str] = []
    findings = [{
        "source": "msf_hashdump",
        "kind": "ntlm_hash",
        "data": {"user": "Administrator",
                 "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
                 "session_id": "3"},
        "raw_line": "Administrator:500:...",
        "_job_id": "j1",
    }]
    _report._md_session_findings(md, findings)
    text = "\n".join(md)
    assert "Administrator" in text
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" in text


def test_md_session_findings_omitted_when_empty() -> None:
    md: list[str] = []
    _report._md_session_findings(md, [])
    assert md == []


def test_to_markdown_includes_session_findings_section(store: JobStore) -> None:
    _seed_session_finding(store)
    data = _report._load(store, "default")
    md = _report.to_markdown(data, chains=[], lookup=False)
    assert "## Session Findings" in md
    assert "msf_sysinfo" in md


def test_to_markdown_omits_section_when_no_session_findings(store: JobStore) -> None:
    data = _report._load(store, "default")
    md = _report.to_markdown(data, chains=[], lookup=False)
    assert "## Session Findings" not in md