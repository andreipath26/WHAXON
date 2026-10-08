"""Tests for whaxon.core.runner.ToolRunner.

Covers argv construction, scope enforcement, subprocess execution via
a real (fast) binary, event emission, timeout handling, and cancellation.

Uses `pytest-asyncio` in auto mode (see pyproject.toml) so async tests
run without an explicit decorator.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from whaxon.core.catalog import Tool, ToolCatalog
from whaxon.core.events import (
    EventBus,
    JobFailed,
    JobFindings,
    JobFinished,
    JobOutput,
    JobStarted,
)
from whaxon.core.runner import ToolRunner
from whaxon.core.scope import OutOfScopeError

# ---------------------------------------------------------------- helpers

def _catalog(tools):
    bus = EventBus()
    cat = ToolCatalog(bus, Path("/tmp/does-not-matter.json"))
    cat._tools = {t.id: t for t in tools}
    return cat


def _runner(tools=None, scope=None):
    bus = EventBus()
    cat = _catalog(tools or [])
    runner = ToolRunner(bus, catalog=cat, scope=scope)
    return runner, bus, cat


class _Recorder:
    """Subscribe to a bus, collect events by type."""

    def __init__(self, bus):
        self.events = {"started": [], "output": [], "finished": [],
                       "failed": [], "findings": []}
        bus.subscribe(JobStarted, lambda e: self.events["started"].append(e))
        bus.subscribe(JobOutput, lambda e: self.events["output"].append(e))
        bus.subscribe(JobFinished, lambda e: self.events["finished"].append(e))
        bus.subscribe(JobFailed, lambda e: self.events["failed"].append(e))
        bus.subscribe(JobFindings, lambda e: self.events["findings"].append(e))


# ---------------------------------------------------------------- build_argv

def test_build_argv_no_catalog():
    runner = ToolRunner(EventBus(), catalog=None)
    with pytest.raises(RuntimeError, match="no catalog"):
        runner.build_argv("nmap", "10.0.0.5")


def test_build_argv_unknown_tool():
    runner, _, _ = _runner(tools=[])
    with pytest.raises(ValueError, match="unknown tool"):
        runner.build_argv("nmap", "10.0.0.5")


def test_build_argv_substitutes_target():
    tool = Tool(id="nmap", name="Nmap", category="recon",
                binary="/usr/bin/nmap", args="-sV {target}")
    runner, _, _ = _runner(tools=[tool])
    argv = runner.build_argv("nmap", "10.0.0.5")
    assert argv == ["/usr/bin/nmap", "-sV", "10.0.0.5"]


def test_build_argv_default_template():
    """No args template — defaults to {target}."""
    tool = Tool(id="dig", name="dig", category="recon",
                binary="/usr/bin/dig", args="")
    runner, _, _ = _runner(tools=[tool])
    argv = runner.build_argv("dig", "example.com")
    assert argv == ["/usr/bin/dig", "example.com"]


def test_build_argv_appends_extra_args():
    tool = Tool(id="nmap", name="Nmap", category="recon",
                binary="/usr/bin/nmap", args="-sV {target}")
    runner, _, _ = _runner(tools=[tool])
    argv = runner.build_argv("nmap", "10.0.0.5", extra_args="-p 80,443")
    assert argv == ["/usr/bin/nmap", "-sV", "10.0.0.5", "-p", "80,443"]


def test_build_argv_rejects_bad_template():
    tool = Tool(id="x", name="X", category="x",
                binary="/bin/echo", args="{nonexistent}")
    runner, _, _ = _runner(tools=[tool])
    with pytest.raises(ValueError, match="bad args template"):
        runner.build_argv("x", "t")


# ---------------------------------------------------------------- run_tool happy path

async def test_run_tool_echo_success():
    """Run /bin/echo and verify events fire in order."""
    tool = Tool(id="echo", name="Echo", category="test",
                binary="/bin/echo", args="{target}")
    runner, bus, _ = _runner(tools=[tool])
    rec = _Recorder(bus)

    job_id = await runner.run_tool("echo", "hello-world", timeout_s=5)

    assert len(rec.events["started"]) == 1
    assert rec.events["started"][0].tool_id == "echo"
    assert rec.events["started"][0].target == "hello-world"
    assert rec.events["started"][0].job_id == job_id

    assert len(rec.events["finished"]) == 1
    assert rec.events["finished"][0].exit_code == 0

    # stdout should contain hello-world
    stdout_lines = [e.line for e in rec.events["output"] if e.stream == "stdout"]
    assert "hello-world" in stdout_lines


async def test_run_tool_captures_stderr():
    """printf writes to stderr; verify it's captured separately."""
    tool = Tool(id="err", name="Err", category="test",
                binary="/bin/sh", args="-c 'echo out; echo err >&2'")
    runner, bus, _ = _runner(tools=[tool])
    rec = _Recorder(bus)

    await runner.run_tool("err", "x", timeout_s=5)

    out = [e.line for e in rec.events["output"] if e.stream == "stdout"]
    err = [e.line for e in rec.events["output"] if e.stream == "stderr"]
    assert "out" in out
    assert "err" in err


# ---------------------------------------------------------------- scope

async def test_run_tool_out_of_scope_raises():
    """With a scope bound, out-of-scope targets raise before spawn."""
    class FakeMatch:
        allowed = False
        reason = "no matching rule"
        matched_rule = ""

    class FakeScope:
        def check(self, target):
            return FakeMatch()

    tool = Tool(id="echo", name="Echo", category="test",
                binary="/bin/echo", args="{target}")
    runner, bus, _ = _runner(tools=[tool], scope=FakeScope())
    rec = _Recorder(bus)

    with pytest.raises(OutOfScopeError):
        await runner.run_tool("echo", "8.8.8.8", timeout_s=5)

    # JobStarted should not have fired
    assert rec.events["started"] == []


async def test_run_tool_out_of_scope_allowed_override():
    class FakeMatch:
        allowed = False
        reason = "no matching rule"
        matched_rule = ""

    class FakeScope:
        def check(self, target):
            return FakeMatch()

    tool = Tool(id="echo", name="Echo", category="test",
                binary="/bin/echo", args="{target}")
    runner, bus, _ = _runner(tools=[tool], scope=FakeScope())
    rec = _Recorder(bus)

    # allow_out_of_scope=True bypasses the check
    await runner.run_tool("echo", "8.8.8.8", timeout_s=5, allow_out_of_scope=True)
    assert len(rec.events["finished"]) == 1


# ---------------------------------------------------------------- missing binary

async def test_run_tool_missing_binary():
    tool = Tool(id="ghost", name="Ghost", category="test",
                binary="/nonexistent/binary/xyz", args="{target}")
    runner, bus, _ = _runner(tools=[tool])
    rec = _Recorder(bus)

    with pytest.raises(FileNotFoundError):
        await runner.run_tool("ghost", "t", timeout_s=5)

    assert len(rec.events["failed"]) == 1
    assert "not found" in rec.events["failed"][0].error


# ---------------------------------------------------------------- timeout

async def test_run_tool_timeout():
    """sleep 30 with a 0.3s timeout should kill and emit JobFailed."""
    tool = Tool(id="slow", name="Slow", category="test",
                binary="/bin/sleep", args="30")
    runner, bus, _ = _runner(tools=[tool])
    rec = _Recorder(bus)

    await runner.run_tool("slow", "x", timeout_s=0.3)

    assert len(rec.events["failed"]) == 1
    assert rec.events["failed"][0].error == "timeout"
    # JobFinished should NOT fire on timeout
    assert rec.events["finished"] == []


# ---------------------------------------------------------------- cancel

async def test_cancel_terminates_sleep():
    """Start sleep 30, cancel it, verify the process ends."""
    tool = Tool(id="slow", name="Slow", category="test",
                binary="/bin/sleep", args="30")
    runner, bus, _ = _runner(tools=[tool])

    task = asyncio.create_task(runner.run_tool("slow", "x", timeout_s=30))
    # Give the subprocess a moment to start
    await asyncio.sleep(0.3)

    # Find the registered job id
    assert len(runner._procs) == 1
    job_id = next(iter(runner._procs))

    await runner.cancel(job_id)
    # The task should complete quickly
    await asyncio.wait_for(task, timeout=5)


async def test_cancel_unknown_job_is_noop():
    tool = Tool(id="echo", name="Echo", category="test",
                binary="/bin/echo", args="{target}")
    runner, _, _ = _runner(tools=[tool])
    # No exception, no side effects
    await runner.cancel("nonexistent-job-id")


# ---------------------------------------------------------------- findings

async def test_run_tool_publishes_findings_when_adapter_matches():
    """Echo a line that nmap's adapter will parse as an open port."""
    tool = Tool(id="nmap", name="Nmap", category="recon",
                binary="/bin/echo",
                args="22/tcp open ssh")
    runner, bus, _ = _runner(tools=[tool])
    rec = _Recorder(bus)

    await runner.run_tool("nmap", "10.0.0.5", timeout_s=5)

    assert len(rec.events["findings"]) == 1
    findings = rec.events["findings"][0].findings
    assert any(f["kind"] == "open_port" and f["data"]["port"] == 22
               for f in findings)