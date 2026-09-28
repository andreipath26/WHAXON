"""Store round-trip for ai_runs + step persistence."""
from __future__ import annotations

from pathlib import Path

from whaxon.core.store import JobStore


def test_ai_run_roundtrip(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-abc", "scan 10.0.0.1")
    s.append_ai_run_step("ai-abc", 1,
        {"kind": "run_tool", "tool_id": "nmap", "target": "10.0.0.1"},
        {"ok": True, "job_id": "ai-1-nmap"})
    s.append_ai_run_step("ai-abc", 2,
        {"kind": "stop", "rationale": "done"},
        {"ok": True, "summary": "done"})
    s.set_ai_run_finished("ai-abc", status="done")

    run = s.get_ai_run("ai-abc")
    assert run is not None
    assert run["id"] == "ai-abc"
    assert run["goal"] == "scan 10.0.0.1"
    assert run["status"] == "done"
    assert len(run["steps"]) == 2
    assert run["steps"][0]["action"]["tool_id"] == "nmap"
    assert run["steps"][1]["action"]["kind"] == "stop"
    assert run["phase"] == "recon"
    assert run["phase"] == "recon"


def test_ai_run_list_orders_by_started(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-1", "one")
    s.create_ai_run("ai-2", "two")
    runs = s.list_ai_runs()
    ids = [r["id"] for r in runs]
    assert "ai-1" in ids and "ai-2" in ids


def test_ai_run_get_missing_returns_none(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    assert s.get_ai_run("nope") is None