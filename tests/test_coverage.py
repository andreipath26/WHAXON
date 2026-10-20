"""Coverage ledger tests (§34.2 step 4)."""
import asyncio

from whaxon.core import Core
from whaxon.core.events import CoverageSkipped


def test_record_and_list_coverage(tmp_path):
    core = Core(tmp_path / "data")
    asyncio.run(core.initialize())
    core.store.create("job1")

    core.bus.publish(CoverageSkipped(
        job_id="job1", tool_id="nmap", target="example.com",
        kind="scope_blocked", detail="out of scope: example.com",
    ))
    core.bus.publish(CoverageSkipped(
        job_id="job1", tool_id="nikto", target="example.com",
        kind="binary_missing", detail="nikto not found",
    ))

    rows = core.store.list_coverage("job1")
    assert len(rows) == 2
    assert rows[0]["kind"] == "scope_blocked"
    assert rows[1]["kind"] == "binary_missing"


def test_run_tool_records_scope_block(tmp_path):
    """A tool run against an out-of-scope target records a coverage row."""
    core = Core(tmp_path / "data")
    asyncio.run(core.initialize())
    # Scope is strict by default; example.com is not in it.
    from whaxon.core.scope import OutOfScopeError
    try:
        asyncio.run(core.runner.run_tool("nmap", "example.com", job_id="job1"))
    except OutOfScopeError:
        pass
    rows = core.store.list_coverage("job1")
    assert any(r["kind"] == "scope_blocked" for r in rows), rows


def test_coverage_cmd_reports_missing_job(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    from whaxon.core import Core
    from whaxon.interfaces.cli import coverage_cmd
    core = Core(tmp_path / "data")
    asyncio.run(core.initialize())
    rc = coverage_cmd.main(["nonexistent"])
    assert rc == coverage_cmd.EXIT_NOT_FOUND
