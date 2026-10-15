"""whaxon vulndb CLI tests.

The CLI is a thin wrapper over VulnDB. These tests exercise the three
subcommands against a temp database. No network calls.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from whaxon.interfaces.cli import vulndb_cmd


@pytest.fixture
def temp_data(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    return tmp_path


def test_help_prints_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        vulndb_cmd.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "whaxon vulndb" in out
    assert "status" in out
    assert "lookup" in out
    assert "update" in out


def test_no_args_exits_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        vulndb_cmd.main([])
    assert exc.value.code == 2


def test_unknown_subcommand_exits_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        vulndb_cmd.main(["bogus"])
    assert exc.value.code == 2


def test_status_on_empty_db(temp_data, capsys):
    vulndb_cmd.main(["status"])
    out = capsys.readouterr().out
    assert "rows:" in out
    assert "never" in out


def test_lookup_missing_arg_exits_usage(temp_data, capsys):
    with pytest.raises(SystemExit) as exc:
        vulndb_cmd.main(["lookup"])
    assert exc.value.code == 2


def test_lookup_unknown_cve_exits_not_found(temp_data, capsys):
    with pytest.raises(SystemExit) as exc:
        vulndb_cmd.main(["lookup", "CVE-2099-99999"])
    assert exc.value.code == 3
    out = capsys.readouterr().out
    assert "not found" in out.lower()


def test_lookup_known_cve(temp_data, capsys):
    from whaxon.core.vulndb import VulnDB
    db = VulnDB(temp_data / "vulndb.db")
    c = db._c()
    c.execute(
        "INSERT INTO cve (cve_id, cvss_v3_score, cvss_v3_severity, epss_score, kev) "
        "VALUES (?, ?, ?, ?, ?)",
        ("CVE-2021-44228", 10.0, "CRITICAL", 0.97, 1),
    )
    c.commit()
    vulndb_cmd.main(["lookup", "cve-2021-44228"])
    out = capsys.readouterr().out
    assert "CVE-2021-44228" in out
    assert "10.0" in out
    assert "0.97" in out
    assert "kev" in out.lower()


def test_update_unknown_flag_exits_usage(temp_data, capsys):
    with pytest.raises(SystemExit) as exc:
        vulndb_cmd.main(["update", "--bogus"])
    assert exc.value.code == 2
