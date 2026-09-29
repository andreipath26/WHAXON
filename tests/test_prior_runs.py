"""Cross-run summary — v2 of docs/agent-architecture.md §11."""
from __future__ import annotations

from pathlib import Path

from whaxon.ai.prior_runs import summarize
from whaxon.core.store import JobStore


def _seed(store: JobStore, run_id: str, goal: str, tool_id: str, ok: bool = True,
          phase: str = "recon") -> None:
    store.create_ai_run(run_id, goal, phase=phase)
    store.append_ai_run_step(run_id, 1,
        {"kind": "run_tool", "tool_id": tool_id, "target": "10.0.0.5"},
        {"ok": ok, "job_id": f"{run_id}-1-{tool_id}",
         "summary": f"{tool_id} ran", "findings": [], "error": ""})
    store.set_ai_run_finished(run_id, status="done")


def test_summarize_no_matches(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    out = summarize(s, "10.0.0.5")
    assert out["run_count"] == 0
    assert out["tools_used"] == []


def test_summarize_empty_target(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    out = summarize(s, "")
    assert out["run_count"] == 0


def test_summarize_single_matching_run(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    _seed(s, "ai-1", "enumerate 10.0.0.5", "nmap")
    out = summarize(s, "10.0.0.5")
    assert out["run_count"] == 1
    assert out["tools_used"] == ["nmap"]
    assert out["successful_tools"] == ["nmap"]
    assert out["target"] == "10.0.0.5"


def test_summarize_only_matching_target(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    _seed(s, "ai-1", "enumerate 10.0.0.5", "nmap")
    _seed(s, "ai-2", "enumerate 10.0.0.6", "nikto")
    out = summarize(s, "10.0.0.5")
    assert out["run_count"] == 1
    assert out["tools_used"] == ["nmap"]


def test_summarize_successful_vs_attempted(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    _seed(s, "ai-1", "enumerate 10.0.0.5", "nmap", ok=True)
    _seed(s, "ai-2", "enumerate 10.0.0.5", "nikto", ok=False)
    out = summarize(s, "10.0.0.5")
    assert set(out["tools_used"]) == {"nmap", "nikto"}
    assert out["successful_tools"] == ["nmap"]


def test_summarize_last_phase_present(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    _seed(s, "ai-1", "enumerate 10.0.0.5", "nmap", phase="post-access")
    out = summarize(s, "10.0.0.5")
    assert out["last_phase"] == "post-access"


def test_summarize_limit(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    for i in range(10):
        _seed(s, f"ai-{i}", "enumerate 10.0.0.5", "nmap")
    out = summarize(s, "10.0.0.5", limit=3)
    assert out["run_count"] <= 3