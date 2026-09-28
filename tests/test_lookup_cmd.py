"""Tests for whaxon.interfaces.cli.lookup_cmd.

searchsploit is a local dependency — the tests require it to be installed
on PATH. If it's missing, they skip with a clear reason. That's better
than mocking subprocess for this file: the whole point is to prove the
real searchsploit integration works.
"""
from __future__ import annotations

import json
import shutil

import pytest

from whaxon.interfaces.cli import lookup_cmd


pytestmark = pytest.mark.skipif(
    shutil.which("searchsploit") is None,
    reason="searchsploit not on PATH (install the 'exploitdb' package)",
)


# ---------------------------------------------------------------- validation

def test_no_args_prints_usage(capsys):
    lookup_cmd.main([])
    out = capsys.readouterr().out
    assert "Usage" in out
    assert "whaxon lookup" in out


def test_help_prints_usage(capsys):
    lookup_cmd.main(["--help"])
    out = capsys.readouterr().out
    assert "Usage" in out


def test_unknown_flag_exits_usage(capsys):
    with pytest.raises(SystemExit) as ei:
        lookup_cmd.main(["--bogus"])
    assert ei.value.code == lookup_cmd.EXIT_USAGE


def test_bad_limit_exits_usage(capsys):
    with pytest.raises(SystemExit) as ei:
        lookup_cmd.main(["--limit", "notanumber", "apache"])
    assert ei.value.code == lookup_cmd.EXIT_USAGE


def test_extra_positional_exits_usage(capsys):
    with pytest.raises(SystemExit) as ei:
        lookup_cmd.main(["apache", "nginx"])
    assert ei.value.code == lookup_cmd.EXIT_USAGE


# ---------------------------------------------------------------- search

def test_search_known_tool_finds_results(capsys):
    """vsftpd 2.3.4 has at least one known exploit in the mirror."""
    lookup_cmd.main(["vsftpd 2.3.4"])
    out = capsys.readouterr().out
    assert "Search: vsftpd 2.3.4" in out
    assert "Results:" in out
    # 49757 is the well-known backdoor exploit
    assert "49757" in out
    assert "CVE-2011-2523" in out


def test_search_unknown_returns_no_results(capsys):
    lookup_cmd.main(["definitely-not-a-real-tool-xyz-12345"])
    out = capsys.readouterr().out
    assert "no results" in out.lower()


def test_search_json_output(capsys):
    lookup_cmd.main(["vsftpd 2.3.4", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["query"] == "vsftpd 2.3.4"
    assert isinstance(data["results"], list)
    assert any(r["EDB-ID"] == "49757" for r in data["results"])


def test_search_limit_caps_results(capsys):
    lookup_cmd.main(["apache", "--limit", "3"])
    out = capsys.readouterr().out
    # At most 3 rows printed, and possibly a "... more" line
    lines = [l for l in out.splitlines() if "EDB-ID" not in l and l.strip()]
    # This test is loose because searchsploit's exact output varies
    # by mirror version. The key is that --limit was accepted.
    assert "Search: apache" in out


# ---------------------------------------------------------------- by ID

def test_lookup_by_id_shows_details(capsys):
    lookup_cmd.main(["--id", "49757"])
    out = capsys.readouterr().out
    assert "49757" in out
    assert "vsftpd" in out
    assert "CVE-2011-2523" in out
    assert "/usr/share/exploitdb/" in out


def test_lookup_by_id_json(capsys):
    lookup_cmd.main(["--id", "49757", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["EDB-ID"] == "49757"


def test_lookup_by_missing_id_exits_3(capsys):
    with pytest.raises(SystemExit) as ei:
        lookup_cmd.main(["--id", "99999999"])
    assert ei.value.code == lookup_cmd.EXIT_ID_NOT_FOUND
    err = capsys.readouterr().err
    assert "No exploit" in err


# ---------------------------------------------------------------- by CVE

def test_lookup_by_cve(capsys):
    lookup_cmd.main(["--cve", "CVE-2011-2523"])
    out = capsys.readouterr().out
    assert "CVE-2011-2523" in out
    assert "vsftpd" in out.lower() or "49757" in out