"""Phase F — override, resume-from-approval, concurrency lock."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from whaxon.core import Core
from whaxon.core.store import JobStore


def _core(tmp_path: Path) -> Core:
    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text('{"tools":[]}')
    return Core(data_dir=data)


def test_last_approval_none_when_empty(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-1", "goal")
    assert s.last_approval("ai-1") is None


def test_last_approval_returns_most_recent(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-1", "goal")
    s.add_approval("ai-1", 1, "alice", "y", "first")
    s.add_approval("ai-1", 2, "bob", "n", "second")
    last = s.last_approval("ai-1")
    assert last is not None
    assert last["seq"] == 2
    assert last["user"] == "bob"
    assert last["answer"] == "n"


def test_last_approval_isolated_per_run(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-1", "g")
    s.create_ai_run("ai-2", "g")
    s.add_approval("ai-1", 1, "alice", "y", "")
    assert s.last_approval("ai-2") is None


def test_resume_body_records_approval(tmp_path: Path, monkeypatch) -> None:
    """_resume_body writes the answer to approvals before running."""
    from whaxon.interfaces.cli import ai_cmd
    from whaxon.ai.executor import Executor
    from whaxon.ai.actions import Action, ActionResult

    core = _core(tmp_path)
    core.store.create_ai_run("ai-r", "goal")
    core.store.append_ai_run_step(
        "ai-r", 1,
        {"kind": "ask_human", "rationale": "q"},
        {"ok": True, "summary": "q"},
    )

    async def fake_run(self, goal, job_id_prefix="ai", target_lock=None,
                       initial_history=None):
        return [ActionResult(action=Action.stop("done", ai_source="test"), ok=True)]

    monkeypatch.setattr(Executor, "run", fake_run)
    ai_cmd._resume_body("ai-r", tmp_path / "data", 5, "y", user="alice")
    rows = core.store.list_approvals("ai-r")
    assert len(rows) == 1
    assert rows[0]["user"] == "alice"
    assert rows[0]["answer"] == "y"


def test_resume_lock_blocks_second_invocation(tmp_path: Path) -> None:
    """_run_resume refuses if a lock file exists."""
    from whaxon.interfaces.cli import ai_cmd
    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text('{"tools":[]}')
    lock_dir = data / "locks"
    lock_dir.mkdir()
    (lock_dir / "ai-x.lock").write_text("99999")
    with pytest.raises(SystemExit) as e:
        ai_cmd._run_resume("ai-x", data, 5, "y")
    assert e.value.code == 3


def test_resume_lock_removed_after_success(tmp_path: Path, monkeypatch) -> None:
    from whaxon.interfaces.cli import ai_cmd
    from whaxon.ai.executor import Executor
    from whaxon.ai.actions import Action, ActionResult

    core = _core(tmp_path)
    core.store.create_ai_run("ai-lock", "goal")
    core.store.append_ai_run_step(
        "ai-lock", 1,
        {"kind": "ask_human", "rationale": "q"},
        {"ok": True, "summary": "q"},
    )

    async def fake_run(self, goal, job_id_prefix="ai", target_lock=None,
                       initial_history=None):
        return [ActionResult(action=Action.stop("done", ai_source="test"), ok=True)]

    monkeypatch.setattr(Executor, "run", fake_run)
    ai_cmd._run_resume("ai-lock", tmp_path / "data", 5, "y")
    assert not (tmp_path / "data" / "locks" / "ai-lock.lock").exists()
