"""Tests for the deterministic validation command (CLI wiring only).

The validation logic itself is covered by test_validator_engine.py.
These tests prove: the command finds the finding, calls the validator,
writes the status back to the store, and does not crash on missing data.
"""
import asyncio

from whaxon.interfaces.cli import validate_cmd


def test_validate_writes_status_to_store(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from whaxon.core import Core
    from whaxon.core.findings import Finding

    core = Core(tmp_path / "data")
    asyncio.run(core.initialize())
    core.store.create("job1")
    # Set a target so URL building has something to work with.
    core.store.set_started("job1", "sqlmap", "127.0.0.1:80")

    f = Finding(kind="sqli", severity="high", source="test",
                data={"parameter": "id"}, raw_line="test")
    core.store.append_finding("job1", f, 1)

    rc = validate_cmd.main(["job1", "1"])
    assert rc == 0

    findings = core.store.get_findings("job1")
    # sqlmap at 127.0.0.1:80 is not reachable in the test, so the
    # validator returns candidate with a reason. The store must reflect
    # whatever the validator returned.
    assert findings[0]["verification_status"] in ("candidate", "refuted", "verified")


def test_validate_missing_finding_returns_not_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from whaxon.core import Core

    core = Core(tmp_path / "data")
    asyncio.run(core.initialize())
    core.store.create("job1")

    rc = validate_cmd.main(["job1", "99"])
    assert rc == validate_cmd.EXIT_NOT_FOUND


def test_validate_no_args_prints_usage(capsys):
    rc = validate_cmd.main([])
    assert rc == validate_cmd.EXIT_USAGE
    captured = capsys.readouterr()
    assert "Usage" in captured.err


def test_validate_refuses_target_removed_from_current_scope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from whaxon.core import Core
    from whaxon.core.findings import Finding

    core = Core(tmp_path / "data")
    asyncio.run(core.initialize(drain=False))
    core.store.create("job-out")
    core.store.set_started("job-out", "sqlmap", "outside.example")
    core.store.append_finding(
        "job-out",
        Finding(kind="sqli", severity="high", source="test",
                data={"parameter": "id"}, raw_line="test"),
        1,
    )

    def must_not_replay(*args, **kwargs):
        raise AssertionError("validator must not contact a target outside current scope")

    monkeypatch.setattr(validate_cmd.Validator, "validate", must_not_replay)
    rc = validate_cmd.main(["job-out", "1"])
    assert rc == validate_cmd.EXIT_OUT_OF_SCOPE
    assert core.store.get_findings("job-out")[0]["verification_status"] is None
