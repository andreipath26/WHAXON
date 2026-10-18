"""findings_by_target groups by host, not raw target string.

172.17.0.3 (nmap, gobuster, ffuf) and 172.17.0.3:80 (nikto) are the
same target to a pentester. Before this fix they were two groups, and
`whaxon findings <host>` saw only the exact string it was given.
"""
from __future__ import annotations

from pathlib import Path

from whaxon.core.store import JobStore


def _store(tmp_path: Path) -> JobStore:
    return JobStore(tmp_path / "db.sqlite")


def test_host_and_host_port_merge_into_one_group(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.create("j1"); s.set_started("j1", "nmap", "172.17.0.3")
    s.append_finding("j1", {"kind": "open_port", "severity": "info",
                            "source": "nmap", "raw_line": "80/tcp open http",
                            "data": {"port": 80}}, 0)
    s.create("j2"); s.set_started("j2", "nikto", "172.17.0.3:80")
    s.append_finding("j2", {"kind": "web_issue", "severity": "medium",
                            "source": "nikto", "raw_line": "/config/ indexing",
                            "data": {}}, 0)
    groups = s.findings_by_target()
    assert len(groups) == 1, [g["target"] for g in groups]
    assert groups[0]["job_count"] == 2
    assert groups[0]["finding_count"] == 2


def test_url_target_normalizes_to_host(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.create("j1"); s.set_started("j1", "ffuf", "http://172.17.0.3")
    s.append_finding("j1", {"kind": "found_path", "severity": "low",
                            "source": "ffuf", "raw_line": "admin", "data": {}}, 0)
    s.create("j2"); s.set_started("j2", "nikto", "172.17.0.3:80")
    s.append_finding("j2", {"kind": "web_issue", "severity": "medium",
                            "source": "nikto", "raw_line": "x", "data": {}}, 0)
    groups = s.findings_by_target()
    assert len(groups) == 1, [g["target"] for g in groups]


def test_distinct_hosts_stay_separate(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.create("j1"); s.set_started("j1", "nmap", "172.17.0.3")
    s.append_finding("j1", {"kind": "open_port", "severity": "info",
                            "source": "nmap", "raw_line": "x", "data": {}}, 0)
    s.create("j2"); s.set_started("j2", "nmap", "172.28.0.10")
    s.append_finding("j2", {"kind": "open_port", "severity": "info",
                            "source": "nmap", "raw_line": "y", "data": {}}, 0)
    assert len(s.findings_by_target()) == 2
