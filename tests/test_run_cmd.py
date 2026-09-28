"""Tests for whaxon.interfaces.cli.run_cmd.

Runs the CLI entry point directly against a temp data dir. Uses the
`echo` catalog tool as the "real run" case — it always exists if
`data/tools.json` is loaded and produces predictable output.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from whaxon.interfaces.cli import run_cmd


def _seed_data_dir(tmp_path: Path) -> Path:
    """Copy data/tools.json into tmp_path so the catalog has tools."""
    repo_data = Path(__file__).resolve().parents[1] / "data"
    if (repo_data / "tools.json").exists():
        shutil.copy(repo_data / "tools.json", tmp_path / "tools.json")
    return tmp_path


# ---------------------------------------------------------------- validation

def test_no_args_prints_usage(capsys):
    run_cmd.main([])
    out = capsys.readouterr().out
    assert "Usage: whaxon run" in out


def test_help_prints_usage(capsys):
    run_cmd.main(["--help"])
    out = capsys.readouterr().out
    assert "Usage: whaxon run" in out


def test_missing_target_exits_usage(tmp_path, capsys):
    _seed_data_dir(tmp_path)
    with pytest.raises(SystemExit) as ei:
        run_cmd.main(["echo", "--data", str(tmp_path)])
    assert ei.value.code == run_cmd.EXIT_USAGE


def test_unknown_tool_exits_3(tmp_path, capsys):
    _seed_data_dir(tmp_path)
    with pytest.raises(SystemExit) as ei:
        run_cmd.main(["definitely-not-a-tool", "127.0.0.1",
                      "--data", str(tmp_path)])
    assert ei.value.code == run_cmd.EXIT_UNKNOWN_TOOL
    err = capsys.readouterr().err
    assert "unknown tool" in err
    assert "available:" in err


def test_unknown_flag_exits_usage(tmp_path, capsys):
    _seed_data_dir(tmp_path)
    with pytest.raises(SystemExit) as ei:
        run_cmd.main(["echo", "127.0.0.1", "--bogus-flag",
                      "--data", str(tmp_path)])
    assert ei.value.code == run_cmd.EXIT_USAGE


def test_bad_timeout_value_exits_usage(tmp_path, capsys):
    _seed_data_dir(tmp_path)
    with pytest.raises(SystemExit) as ei:
        run_cmd.main(["echo", "127.0.0.1", "--timeout", "not-a-number",
                      "--data", str(tmp_path)])
    assert ei.value.code == run_cmd.EXIT_USAGE


# ---------------------------------------------------------------- happy path

def test_echo_run_succeeds(tmp_path, capsys):
    """Run the echo tool against 127.0.0.1. Should exit 0, print a job id."""
    _seed_data_dir(tmp_path)
    run_cmd.main(["echo", "127.0.0.1", "--quiet",
                  "--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "job:" in out
    assert "report: whaxon report" in out


def test_echo_run_json_output(tmp_path, capsys):
    """--json emits findings as a JSON array (empty for echo)."""
    _seed_data_dir(tmp_path)
    run_cmd.main(["echo", "127.0.0.1", "--quiet", "--json",
                  "--data", str(tmp_path)])
    out = capsys.readouterr().out
    # JSON array — either "[]" or a list with items
    assert out.strip().startswith("[")


def test_echo_run_creates_job_in_store(tmp_path):
    """After a run, the job exists in the store with the correct tool."""
    _seed_data_dir(tmp_path)
    run_cmd.main(["echo", "127.0.0.1", "--quiet", "--data", str(tmp_path)])
    # Reopen the store and find the most recent job
    from whaxon.core import Core
    core = Core(data_dir=tmp_path)
    history = core.store.history(limit=5)
    assert history, "no jobs in history after a run"
    latest = history[0]
    assert latest["tool"] == "echo"
    assert latest["target"] == "127.0.0.1"