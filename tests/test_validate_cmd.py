"""Tests for the validation command migration gate and CLI wiring."""
import asyncio

from whaxon.interfaces.cli import validate_cmd


def test_validate_blocks_legacy_execution_by_default(tmp_path, monkeypatch, capsys):
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
    assert rc == validate_cmd.EXIT_V2_WORKFLOW_REQUIRED
    assert "no request was sent" in capsys.readouterr().err
    assert core.store.get_findings("job1")[0]["verification_status"] == "candidate"


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

def test_validate_refuses_out_of_scope_target(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    from whaxon.core import Core
    from whaxon.core.findings import Finding

    core = Core(tmp_path / "data")
    asyncio.run(core.initialize())
    core.store.create("outside")
    core.store.set_started("outside", "sqlmap", "google.com")
    core.store.append_finding(
        "outside",
        Finding(kind="sqli", severity="high", source="test",
                data={"parameter": "id"}, raw_line="test"),
        1,
    )

    rc = validate_cmd.main(["outside", "1"])
    assert rc == validate_cmd.EXIT_SCOPE_BLOCKED
    assert "out of scope" in capsys.readouterr().err.lower()


def test_validate_refuses_to_mutate_engine_v2_evidence(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    from whaxon.core import Core
    from whaxon.core.findings import Finding

    core = Core(tmp_path / "data")
    asyncio.run(core.initialize(drain=False))
    core.store.create("0123456789ab")
    core.store.set_started("0123456789ab", "sqlmap", "127.0.0.1:80")
    core.store.append_finding("0123456789ab", Finding(
        kind="sqli", severity="high", source="sqlmap",
        data={"parameter": "id"}, raw_line="candidate",
    ), 0)
    core.store.mark_engine_v2_execution_job("0123456789ab")

    rc = validate_cmd.main(["0123456789ab", "0"])

    assert rc == validate_cmd.EXIT_V2_WORKFLOW_REQUIRED
    assert "plan propose-verification" in capsys.readouterr().err
    assert core.store.get_findings("0123456789ab")[0]["verification_status"] == "candidate"
