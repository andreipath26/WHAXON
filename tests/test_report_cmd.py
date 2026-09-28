"""Tests for the whaxon report CLI — engagement mode and whaxon envelope."""
from __future__ import annotations

import hashlib
import json

import pytest

from whaxon.core import Core
from whaxon.interfaces.cli import report_cmd


def _seed_job(data_dir, job_id="j1"):
    core = Core(data_dir=data_dir)
    store = core.store
    store.create(job_id)
    store.set_started(job_id, "nmap", "10.0.0.5")
    store.append_finding(job_id, {
        "kind": "open_port", "severity": "high", "source": "nmap",
        "data": {"port": 22}, "raw_line": "22/tcp open ssh",
    }, 0)
    store.set_finished(job_id, 0, 0.1)
    return job_id


def test_help_exits_zero(capsys):
    report_cmd.main(["--help"])
    out = capsys.readouterr().out
    assert "Usage:" in out
    assert "--engagement" in out


def test_unknown_format_exits_two(tmp_path, capsys):
    _seed_job(tmp_path)
    with pytest.raises(SystemExit) as ei:
        report_cmd.main(["j1", "--data", str(tmp_path), "--format", "nope"])
    assert ei.value.code == 2
    assert "Unknown format" in capsys.readouterr().err


def test_whaxon_without_engagement_exits_two(tmp_path, capsys):
    _seed_job(tmp_path)
    with pytest.raises(SystemExit) as ei:
        report_cmd.main(["j1", "--data", str(tmp_path), "--format", "whaxon"])
    assert ei.value.code == 2
    assert "engagement-wide" in capsys.readouterr().err


def test_single_job_md_writes_header(tmp_path):
    _seed_job(tmp_path)
    out = tmp_path / "job.md"
    report_cmd.main(["j1", "--data", str(tmp_path), "--format", "md", "--out", str(out)])
    text = out.read_text()
    assert text.startswith("# Job j1")
    assert "[HIGH]" in text


def test_single_job_json_has_job_key(tmp_path):
    _seed_job(tmp_path)
    out = tmp_path / "job.json"
    report_cmd.main(["j1", "--data", str(tmp_path), "--format", "json", "--out", str(out)])
    data = json.loads(out.read_text())
    assert data["job"]["id"] == "j1"
    assert isinstance(data["findings"], list)


def test_engagement_json_is_compact(tmp_path):
    _seed_job(tmp_path)
    out = tmp_path / "eng.json"
    report_cmd.main(["--engagement", "default", "--data", str(tmp_path),
                     "--format", "json", "--out", str(out)])
    text = out.read_text()
    assert text.endswith(chr(10))
    assert text.count(": ") == 0
    data = json.loads(text)
    assert data["job_count"] == 1
    assert "chains" in data


def test_engagement_all_is_alias_for_default(tmp_path):
    _seed_job(tmp_path)
    out = tmp_path / "eng.json"
    report_cmd.main(["--all", "--data", str(tmp_path),
                     "--format", "json", "--out", str(out)])
    data = json.loads(out.read_text())
    assert data["engagement"] == "default"


def test_whaxon_envelope_shape(tmp_path):
    _seed_job(tmp_path)
    out = tmp_path / "eng.whaxon"
    report_cmd.main(["--engagement", "default", "--data", str(tmp_path),
                     "--format", "whaxon", "--out", str(out)])
    env = json.loads(out.read_text())
    for key in ("format", "version", "generated", "tool", "engagement",
                "integrity", "payload"):
        assert key in env
    assert env["format"] == "whaxon"
    assert env["version"] == 1
    assert env["tool"].startswith("whaxon/")
    assert env["engagement"] == "default"
    assert env["integrity"].startswith("sha256:")


def test_whaxon_envelope_integrity_matches_payload(tmp_path):
    _seed_job(tmp_path)
    out = tmp_path / "eng.whaxon"
    report_cmd.main(["--engagement", "default", "--data", str(tmp_path),
                     "--format", "whaxon", "--out", str(out)])
    env = json.loads(out.read_text())
    canonical = json.dumps(env["payload"], default=str, sort_keys=True)
    expected = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert env["integrity"] == expected


def test_jobs_filter_restricts_output(tmp_path):
    _seed_job(tmp_path, "j1")
    _seed_job(tmp_path, "j2")
    out = tmp_path / "eng.json"
    report_cmd.main(["--engagement", "default", "--data", str(tmp_path),
                     "--jobs", "j1", "--format", "json", "--out", str(out)])
    data = json.loads(out.read_text())
    assert data["job_count"] == 1
    assert data["jobs"][0]["job"]["id"] == "j1"
