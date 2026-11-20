"""Tests for whaxon.interfaces.cli.run_cmd.

Runs the CLI entry point directly against a temp data dir. Uses the
`echo` catalog tool as the "real run" case. The packaged catalog
provides it and produces predictable output.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from whaxon.interfaces.cli import run_cmd


def _seed_data_dir(tmp_path: Path) -> Path:
    """Copy the packaged tools.json into tmp_path so the catalog has tools."""
    repo_data = Path(__file__).resolve().parents[1] / "src" / "whaxon" / "data"
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
    run_cmd.main(["echo", "127.0.0.1", "--legacy", "--quiet",
                  "--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "job:" in out
    assert "report: whaxon report" in out


def test_echo_run_json_output(tmp_path, capsys):
    """--json emits findings as a JSON array (empty for echo)."""
    _seed_data_dir(tmp_path)
    run_cmd.main(["echo", "127.0.0.1", "--legacy", "--quiet", "--json",
                  "--data", str(tmp_path)])
    out = capsys.readouterr().out
    # JSON array — either "[]" or a list with items
    assert out.strip().startswith("[")


def test_echo_run_creates_job_in_store(tmp_path):
    """After a run, the job exists in the store with the correct tool."""
    _seed_data_dir(tmp_path)
    run_cmd.main(["echo", "127.0.0.1", "--legacy", "--quiet", "--data", str(tmp_path)])
    # Reopen the store and find the most recent job
    from whaxon.core import Core
    core = Core(data_dir=tmp_path)
    history = core.store.history(limit=5)
    assert history, "no jobs in history after a run"
    latest = history[0]
    assert latest["tool"] == "echo"
    assert latest["target"] == "127.0.0.1"

def test_run_automatically_drains_jobs_queued_by_automator(tmp_path, monkeypatch, capsys):
    """A single CLI run executes durable follow-ups queued by its findings."""
    import asyncio

    from whaxon.core.automation import Automator
    from whaxon.core.events import EventBus, JobFindings, JobFinished, JobStarted
    from whaxon.core.store import JobStore

    class FakeCatalog:
        def get(self, tool_id):
            return object() if tool_id in {"nmap", "nikto"} else None

    class FakeRunner:
        def __init__(self, bus, store):
            self.bus = bus
            self.store = store
            self.executed = []

        def has_tool(self, tool_id):
            return tool_id == "nikto"

        async def run_tool(self, tool_id, target, job_id=None, **kwargs):
            job_id = job_id or "initial-nmap-job"
            self.executed.append((tool_id, target, job_id))
            self.bus.publish(JobStarted(job_id=job_id, tool_id=tool_id, target=target))
            if tool_id == "nmap":
                self.bus.publish(JobFindings(job_id=job_id, findings=({
                    "kind": "open_port",
                    "severity": "info",
                    "source": "nmap",
                    "data": {"port": 80, "service": "http"},
                    "raw_line": "80/tcp open http",
                },)))
                # Simulate another producer queueing work between the primary
                # run and this invocation's causal follow-up drain.
                self.store.create_pending(
                    "late-unrelated-job", "echo", "unrelated.example.com",
                )
            self.bus.publish(JobFinished(job_id=job_id, exit_code=0, duration_s=0.01))
            return job_id

    class FakeCore:
        def __init__(self, data_dir):
            self.bus = EventBus()
            self.store = JobStore(Path(data_dir) / "whaxon.db")
            # A one-shot run must not silently drain work left by an older run.
            self.store.create_pending("older-pending-job", "nikto", "older.example.com:443")
            self.catalog = FakeCatalog()
            self.scope = None
            self.runner = FakeRunner(self.bus, self.store)
            self.bus.subscribe(JobStarted, lambda e: (
                self.store.create(e.job_id),
                self.store.set_started(e.job_id, e.tool_id, e.target),
            ))
            self.bus.subscribe(JobFinished, lambda e: self.store.set_finished(
                e.job_id, e.exit_code, e.duration_s
            ))
            self.bus.subscribe(JobFindings, lambda e: [
                self.store.append_finding(e.job_id, finding, i)
                for i, finding in enumerate(e.findings)
            ])
            self.automator = Automator(self.bus, self.store, self.runner)
            self.automator.attach()

        async def initialize(self, drain=False):
            self.bus.bind_loop(asyncio.get_running_loop())

    cores = []
    def make_core(data_dir):
        core = FakeCore(data_dir)
        cores.append(core)
        return core

    monkeypatch.setattr(run_cmd, "Core", make_core)
    run_cmd.main(["nmap", "burpbountylab.com", "--legacy", "--extra", "-sV -p 80,443",
                  "--quiet", "--data", str(tmp_path)])

    core = cores[0]
    history = core.store.history(limit=10)
    by_target = {job["target"]: job for job in history}
    assert by_target["burpbountylab.com"]["tool"] == "nmap"
    assert by_target["burpbountylab.com"]["status"] == "finished"
    assert by_target["burpbountylab.com:80"]["tool"] == "nikto"
    assert by_target["burpbountylab.com:80"]["status"] == "finished"
    assert core.store.get("older-pending-job")["status"] == "pending"
    assert core.store.get("late-unrelated-job")["status"] == "pending"
    assert [item[0] for item in core.runner.executed] == ["nmap", "nikto"]
    output = capsys.readouterr().out
    assert "job: initial-nmap-job" in output

