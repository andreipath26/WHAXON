"""Tests for whaxon.interfaces.cli.findings_cmd."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from whaxon.core import Core
from whaxon.interfaces.cli import findings_cmd


def _seed(tmp_path: Path) -> None:
    """Copy data/tools.json so Core can load a catalog."""
    repo_data = Path(__file__).resolve().parents[1] / "data"
    if (repo_data / "tools.json").exists():
        shutil.copy(repo_data / "tools.json", tmp_path / "tools.json")


def _add_job_with_findings(core: Core, job_id: str, target: str,
                           findings: list[dict]) -> None:
    store = core.store
    store.create(job_id)
    store.set_started(job_id, "nmap", target)
    for i, f in enumerate(findings):
        store.append_finding(job_id, f, i)
    store.set_finished(job_id, 0, 0.1)


# ---------------------------------------------------------------- validation

def test_help_prints_usage(capsys):
    findings_cmd.main(["--help"])
    out = capsys.readouterr().out
    assert "Usage: whaxon findings" in out


def test_summary_with_empty_store(tmp_path, capsys):
    _seed(tmp_path)
    findings_cmd.main(["--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "no targets found" in out


def test_unknown_flag_exits_64(tmp_path, capsys):
    _seed(tmp_path)
    with pytest.raises(SystemExit) as ei:
        findings_cmd.main(["--bogus", "--data", str(tmp_path)])
    assert ei.value.code == 64


def test_bad_limit_exits_64(tmp_path, capsys):
    _seed(tmp_path)
    with pytest.raises(SystemExit) as ei:
        findings_cmd.main(["--limit", "notanumber", "--data", str(tmp_path)])
    assert ei.value.code == 64


def test_target_not_found_exits_1(tmp_path, capsys):
    _seed(tmp_path)
    with pytest.raises(SystemExit) as ei:
        findings_cmd.main(["10.0.0.99", "--data", str(tmp_path)])
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "not found" in err


# ---------------------------------------------------------------- happy path

def test_summary_shows_targets(tmp_path, capsys):
    _seed(tmp_path)
    core = Core(data_dir=tmp_path)
    _add_job_with_findings(core, "j1", "10.0.0.5", [
        {"kind": "open_port", "severity": "high", "source": "nmap",
         "data": {"port": 22}, "raw_line": "22/tcp open ssh"},
    ])
    _add_job_with_findings(core, "j2", "10.0.0.6", [
        {"kind": "open_port", "severity": "low", "source": "nmap",
         "data": {"port": 8080}, "raw_line": "8080/tcp open http"},
    ])
    findings_cmd.main(["--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "10.0.0.5" in out
    assert "10.0.0.6" in out
    assert "TARGET" in out
    assert "FINDINGS" in out


def test_detail_for_target(tmp_path, capsys):
    _seed(tmp_path)
    core = Core(data_dir=tmp_path)
    _add_job_with_findings(core, "j1", "10.0.0.5", [
        {"kind": "open_port", "severity": "high", "source": "nmap",
         "data": {"port": 22}, "raw_line": "22/tcp open ssh"},
        {"kind": "web_issue", "severity": "medium", "source": "nikto",
         "data": {"path": "/admin"}, "raw_line": "/admin/: indexing"},
    ])
    findings_cmd.main(["10.0.0.5", "--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "target: 10.0.0.5" in out
    assert "[high]" in out
    assert "[medium]" in out
    assert "22/tcp open ssh" in out


def test_severity_filter(tmp_path, capsys):
    _seed(tmp_path)
    core = Core(data_dir=tmp_path)
    _add_job_with_findings(core, "j1", "10.0.0.5", [
        {"kind": "open_port", "severity": "high", "source": "nmap",
         "data": {"port": 22}, "raw_line": "22/tcp open ssh"},
        {"kind": "open_port", "severity": "low", "source": "nmap",
         "data": {"port": 8080}, "raw_line": "8080/tcp open http"},
    ])
    findings_cmd.main(["10.0.0.5", "--severity", "high",
                       "--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "22/tcp open ssh" in out
    assert "8080/tcp open http" not in out


def test_kind_filter(tmp_path, capsys):
    _seed(tmp_path)
    core = Core(data_dir=tmp_path)
    _add_job_with_findings(core, "j1", "10.0.0.5", [
        {"kind": "open_port", "severity": "high", "source": "nmap",
         "data": {"port": 22}, "raw_line": "22/tcp open ssh"},
        {"kind": "web_issue", "severity": "medium", "source": "nikto",
         "data": {"path": "/admin"}, "raw_line": "/admin/: indexing"},
    ])
    findings_cmd.main(["10.0.0.5", "--kind", "web_issue",
                       "--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "/admin/: indexing" in out
    assert "22/tcp open ssh" not in out


def test_json_output(tmp_path, capsys):
    _seed(tmp_path)
    core = Core(data_dir=tmp_path)
    _add_job_with_findings(core, "j1", "10.0.0.5", [
        {"kind": "open_port", "severity": "high", "source": "nmap",
         "data": {"port": 22}, "raw_line": "22/tcp open ssh"},
    ])
    findings_cmd.main(["--json", "--data", str(tmp_path)])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["target"] == "10.0.0.5"
    assert data[0]["finding_count"] == 1