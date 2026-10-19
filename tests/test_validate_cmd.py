"""Tests for the deterministic validation command."""
import asyncio

from whaxon.interfaces.cli import validate_cmd


def test_validate_updates_status(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Setup core and a finding
    from whaxon.core import Core
    core = Core(tmp_path / "data")
    asyncio.run(core.initialize())
    
    from whaxon.core.findings import Finding
    f = Finding(kind="sql_injection", severity="high", source="test", data={"target": "127.0.0.1"}, raw_line="test")
    core.store.create("job1")
    core.store.append_finding("job1", f, 1)
    
    # Run the command
    rc = validate_cmd.main(["job1", "1"])
    assert rc == 0
    
    # Check the DB
    findings = core.store.get_findings("job1")
    assert findings[0]["verification_status"] == "candidate"  # Stubbed validator returns candidate for now
