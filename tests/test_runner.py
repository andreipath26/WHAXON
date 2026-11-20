"""Tests for whaxon.core.runner.ToolRunner.

Covers argv construction, scope enforcement, subprocess execution via
a real (fast) binary, event emission, timeout handling, and cancellation.

Uses `pytest-asyncio` in auto mode (see pyproject.toml) so async tests
run without an explicit decorator.
"""
from __future__ import annotations

import asyncio
import sys
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


async def test_run_tool_out_of_scope_allowed_override(tmp_path):
    class FakeMatch:
        allowed = False
        reason = "no matching rule"
        matched_rule = ""

    class FakeScope:
        path = tmp_path / "scope.json"

        def check(self, target):
            return FakeMatch()

    tool = Tool(id="echo", name="Echo", category="test",
                binary="/bin/echo", args="{target}")
    runner, bus, _ = _runner(tools=[tool], scope=FakeScope())
    rec = _Recorder(bus)

    # allow_out_of_scope=True bypasses the check
    await runner.run_tool("echo", "8.8.8.8", timeout_s=5, allow_out_of_scope=True)
    assert len(rec.events["finished"]) == 1
    override_log = tmp_path / "scope_overrides.log"
    assert override_log.is_file()
    assert "echo\t8.8.8.8" in override_log.read_text(encoding="utf-8")


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
    runner, _bus, _ = _runner(tools=[tool])

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

def test_build_argv_rejects_extra_url_target_override():
    """A second URL in extra_args must not bypass scope checks on target."""
    tool = Tool(
        id="sqlmap", name="SQLmap", category="web",
        binary="sqlmap", args="-u {target} --batch",
    )
    runner, _, _ = _runner(tools=[tool])
    with pytest.raises(ValueError, match="cannot specify alternate targets"):
        runner.build_argv(
            "sqlmap", "http://127.0.0.1/item?id=1",
            extra_args="-u http://example.com/other --data=x",
        )


def test_build_argv_allows_non_target_sqlmap_options():
    tool = Tool(
        id="sqlmap", name="SQLmap", category="web",
        binary="sqlmap", args="-u {target} --batch",
    )
    runner, _, _ = _runner(tools=[tool])
    argv = runner.build_argv(
        "sqlmap", "http://127.0.0.1/item?id=1",
        extra_args="--data=x --level=2",
    )
    assert argv == [
        "sqlmap", "-u", "http://127.0.0.1/item?id=1", "--batch",
        "--data=x", "--level=2",
    ]

@pytest.mark.parametrize("extra_args", [
    "-h https://example.com",
    "--target https://example.com",
    "-iL /tmp/targets.txt",
    "-iR 10",
    "--url=https://example.com",
    "-uhttps://example.com",
    "-hexample.com",
    "-iL/tmp/targets.txt",
    "-iR10",
])
def test_build_argv_rejects_alternate_target_flags(extra_args):
    tool = Tool(
        id="nmap", name="Nmap", category="recon",
        binary="nmap", args="-sV {target}",
    )
    runner, _, _ = _runner(tools=[tool])
    with pytest.raises(ValueError, match="cannot specify alternate targets"):
        runner.build_argv("nmap", "127.0.0.1", extra_args=extra_args)

async def test_timeout_kills_descendant_processes(tmp_path):
    """A timed-out shell tool must not leave child scans running in the background."""
    import os
    import shlex

    pid_file = tmp_path / "child.pid"
    script = f"sleep 30 & child=$!; echo $child > {shlex.quote(str(pid_file))}; exit 0"
    tool = Tool(
        id="tree", name="Process tree", category="test",
        binary="/bin/sh", args="-c " + shlex.quote(script),
    )
    runner, _, _ = _runner(tools=[tool])
    await runner.run_tool("tree", "127.0.0.1", timeout_s=0.5)

    assert pid_file.exists(), "child process did not start"
    child_pid = int(pid_file.read_text(encoding="utf-8").strip())
    if Path("/proc").is_dir():
        # On Linux, a killed child may briefly remain as a zombie until init
        # reaps it; zombies cannot execute and are acceptable here.
        def proc_state():
            try:
                fields = Path(f"/proc/{child_pid}/stat").read_text(encoding="utf-8").split()
            except OSError:
                # The kernel can remove the proc entry between exists() and read().
                return None
            return fields[2] if len(fields) > 2 else None

        for _ in range(30):
            state = proc_state()
            if state is None or state == "Z":
                break
            await asyncio.sleep(0.1)
        assert proc_state() in (None, "Z")
    else:
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)

async def test_run_handles_single_output_line_larger_than_stream_limit():
    runner, bus, _ = _runner(tools=[])
    rec = _Recorder(bus)
    await runner.run(
        "test-output",
        argv=[sys.executable, "-c", "print('x' * 200000, end='')"],
        target="127.0.0.1",
        timeout_s=5,
    )
    output = [event.line for event in rec.events["output"]]
    assert len(output) == 1
    assert "[line truncated]" in output[0]
    assert len(output[0]) < 17000
    assert len(rec.events["finished"]) == 1
    assert rec.events["failed"] == []


async def test_run_caps_excessive_subprocess_output():
    runner, bus, _ = _runner(tools=[])
    rec = _Recorder(bus)
    await runner.run(
        "test-output",
        argv=[sys.executable, "-c", "print('x\\n' * 6000, end='')"],
        target="127.0.0.1",
        timeout_s=5,
    )
    output = [event.line for event in rec.events["output"]]
    assert len(output) == 5001
    assert "output truncated" in output[-1]
    assert len(rec.events["finished"]) == 1
    assert rec.events["failed"] == []

async def test_tool_output_uses_private_random_directory_and_is_cleaned(tmp_path):
    import shlex
    import sys

    script = (
        "import pathlib,sys; "
        "p=pathlib.Path(sys.argv[sys.argv.index('--out')+1]); "
        "p.write_text('tool output', encoding='utf-8')"
    )
    tool = Tool(
        id="out", name="Output tool", category="test",
        binary=sys.executable,
        args="-c " + shlex.quote(script) + " {target}",
        outfile_flag="--out",
    )
    runner, _, _ = _runner(tools=[tool])
    observed = {}

    def capture(_tool_id, _job_id, _lines, *, argv=(), target="", outfile=None, lease_token=None):
        observed["argv"] = list(argv)
        observed["outfile"] = outfile
        observed["exists_during_parse"] = bool(outfile and outfile.is_file())
        observed["contents"] = outfile.read_text(encoding="utf-8") if outfile and outfile.is_file() else ""

    runner._publish_findings = capture
    await runner.run_tool("out", "127.0.0.1", timeout_s=5)

    outpath = observed["outfile"]
    assert outpath is not None
    assert outpath.name == "output.json"
    assert outpath.parent.name.startswith("whaxon-")
    assert observed["exists_during_parse"] is True
    assert observed["contents"] == "tool output"
    assert not outpath.parent.exists(), "private temporary output directory should be removed"

async def test_cancel_kills_descendants_after_tool_leader_exits(tmp_path):
    """Cancellation must close inherited pipes by killing the whole process group."""
    import os
    import shlex

    pid_file = tmp_path / "cancel-child.pid"
    script = f"sleep 30 & child=$!; echo $child > {shlex.quote(str(pid_file))}; exit 0"
    tool = Tool(
        id="cancel-tree", name="Cancel process tree", category="test",
        binary="/bin/sh", args="-c " + shlex.quote(script),
    )
    runner, _, _ = _runner(tools=[tool])
    task = asyncio.create_task(
        runner.run_tool("cancel-tree", "127.0.0.1", job_id="cancel-tree-job", timeout_s=10)
    )
    for _ in range(50):
        if pid_file.exists() and "cancel-tree-job" in runner._procs:
            break
        await asyncio.sleep(0.02)
    assert pid_file.exists(), "child process did not start"
    child_pid = int(pid_file.read_text(encoding="utf-8").strip())
    await runner.cancel("cancel-tree-job")
    await asyncio.wait_for(task, timeout=3)

    if Path("/proc").is_dir():
        def proc_state():
            try:
                fields = Path(f"/proc/{child_pid}/stat").read_text(encoding="utf-8").split()
            except OSError:
                return None
            return fields[2] if len(fields) > 2 else None

        for _ in range(30):
            state = proc_state()
            if state is None or state == "Z":
                break
            await asyncio.sleep(0.1)
        assert proc_state() in (None, "Z")
    else:
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)

async def test_smb_password_is_not_passed_in_process_arguments(monkeypatch):
    """SMB credentials are supplied over stdin, not visible in argv/procfs."""
    runner, _, _ = _runner()
    monkeypatch.setenv("WHAXON_SMB_PASS", "secret-smb-password")
    monkeypatch.setenv("WHAXON_SMB_DOMAIN", "LAB")
    captured = {}

    class FakeProcess:
        returncode = 0
        async def communicate(self, data=None):
            captured["stdin"] = data
            return b"ok", b""

    async def fake_spawn(*argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_spawn)
    result = await runner._run_smb_session("smb:tester@127.0.0.1", "whoami", 5)

    assert result == "ok"
    assert "secret-smb-password" not in " ".join(captured["argv"])
    assert captured["argv"][-1] == "LAB/tester@127.0.0.1"
    assert captured["stdin"].startswith(b"secret-smb-password\nwhoami\n")
    assert captured["kwargs"]["stdin"] is asyncio.subprocess.PIPE


async def test_wmi_password_is_not_passed_in_process_arguments(monkeypatch):
    """WMI credentials are supplied over stdin, not visible in argv/procfs."""
    runner, _, _ = _runner()
    monkeypatch.setenv("WHAXON_WMI_PASS", "secret-wmi-password")
    monkeypatch.setenv("WHAXON_WMI_DOMAIN", "LAB")
    captured = {}

    class FakeProcess:
        returncode = 0
        async def communicate(self, data=None):
            captured["stdin"] = data
            return b"ok", b""

    async def fake_spawn(*argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_spawn)
    result = await runner._run_wmi_session("wmi:tester@127.0.0.1", "whoami", 5)

    assert result == "ok"
    assert "secret-wmi-password" not in " ".join(captured["argv"])
    assert "LAB/tester@127.0.0.1" in captured["argv"]
    assert "whoami" in captured["argv"]
    assert captured["stdin"] == b"secret-wmi-password\n"
    assert captured["kwargs"]["stdin"] is asyncio.subprocess.PIPE


def test_build_argv_rejects_whitespace_in_target():
    """A target must remain one argv item after template substitution."""
    tool = Tool(
        id="sqlmap",
        name="SQLMap",
        category="web",
        binary="sqlmap",
        args="-u {target}",
    )
    runner, _, _ = _runner(tools=[tool])

    with pytest.raises(ValueError, match="unsafe target"):
        runner.build_argv(
            "sqlmap",
            "https://allowed.example/path -u https://evil.example",
        )


@pytest.mark.parametrize(
    "extra_args",
    [
        "https://evil.example",
        "ftp://evil.example",
        "8.8.8.8",
        "evil.example",
        "evil.example/path",
        "10.0.0.0/8",
        "--domain=evil.example",
    ],
)
def test_build_argv_rejects_positional_alternate_target(extra_args):
    """Extra arguments must not smuggle a second target past scope checking."""
    tool = Tool(
        id="nmap",
        name="Nmap",
        category="recon",
        binary="nmap",
        args="-sV {target}",
    )
    runner, _, _ = _runner(tools=[tool])

    with pytest.raises(ValueError, match=r"alternate targets|second target"):
        runner.build_argv("nmap", "10.0.0.5", extra_args=extra_args)


async def test_msf_session_dispatch_rechecks_persisted_scope_before_rpc():
    from whaxon.core.catalog import Tool
    class DenyScope:
        def check(self, target):
            class Match:
                allowed = False
                reason = "not in engagement"
                matched_rule = ""
            return Match()

    tool = Tool(
        id="session_test", name="Session test", category="session",
        binary="", transport="msf_session", command="getuid",
    )
    runner, _, _ = _runner(tools=[tool], scope=DenyScope())
    runner.bind_session_lookup(lambda sid: {
        "id": sid, "host": "203.0.113.10", "status": "open",
    })
    with pytest.raises(OutOfScopeError):
        await runner.run_in_session("session_test", "4")
