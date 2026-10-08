"""Phase transitions: ask_human with proposed_phase (step 5)."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from whaxon.ai import ExecutorLimits
from whaxon.ai.actions import Action
from whaxon.ai.provider import Provider
from whaxon.core import Core
from whaxon.core.ai_bridge import build_executor


@pytest.fixture
def core(tmp_path: Path) -> Core:
    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text(
        "{\"tools\":[{\"id\":\"echo\",\"name\":\"Echo\","
        "\"category\":\"test\",\"binary\":\"/bin/echo\","
        "\"args\":\"{target}\"}]}"
    )
    return Core(data_dir=data)


class Scripted(Provider):
    name = "scripted"
    def __init__(self, actions):
        self._actions = actions
    def plan_step(self, goal, history, catalog, scope_summary, step,
                  max_steps, phase="recon", prior_runs=None):
        idx = step - 1
        if idx < len(self._actions):
            return self._actions[idx]
        return Action.stop("script exhausted", ai_source=self.name)


def _approve(_action):
    async def _a(_act):
        return "y"
    return asyncio.run(_a(_action)) if False else _a


def test_transition_approved_writes_new_phase(core: Core) -> None:
    async def answer(_action: Action) -> str:
        return "y"

    scripted = Scripted([
        Action.ask_human("recon complete, move to enumeration?",
                         ai_source="scripted",
                         proposed_phase="enumeration"),
        Action.stop("done", ai_source="scripted"),
    ])
    ex = build_executor(core, provider=scripted,
                        limits=ExecutorLimits(max_steps=5),
                        ask_human=answer)
    run_id = "ai-tx-1"
    core.store.create_ai_run(run_id, "test", phase="recon")
    ex.phase_get = lambda: (core.store.get_ai_run(run_id) or {}).get("phase") or "recon"
    ex.phase_set = lambda p: core.store.set_ai_run_phase(run_id, p)

    history = asyncio.run(ex.run("test", job_id_prefix=run_id))

    run = core.store.get_ai_run(run_id)
    assert run is not None
    assert run["phase"] == "enumeration"
    # History: ask_human, ack, tx, stop
    kinds = [r.action.kind for r in history]
    assert kinds[0] == "ask_human"
    assert history[-1].action.kind == "stop"


def test_transition_rejected_keeps_phase(core: Core) -> None:
    async def answer(_action: Action) -> str:
        return "n"

    scripted = Scripted([
        Action.ask_human("recon complete, move to enumeration?",
                         ai_source="scripted",
                         proposed_phase="enumeration"),
        Action.stop("done", ai_source="scripted"),
    ])
    ex = build_executor(core, provider=scripted,
                        limits=ExecutorLimits(max_steps=5),
                        ask_human=answer)
    run_id = "ai-tx-2"
    core.store.create_ai_run(run_id, "test", phase="recon")
    ex.phase_get = lambda: (core.store.get_ai_run(run_id) or {}).get("phase") or "recon"
    ex.phase_set = lambda p: core.store.set_ai_run_phase(run_id, p)

    asyncio.run(ex.run("test", job_id_prefix=run_id))

    run = core.store.get_ai_run(run_id)
    assert run is not None
    assert run["phase"] == "recon"


def test_transition_invalid_phase_not_written(core: Core) -> None:
    async def answer(_action: Action) -> str:
        return "y"

    scripted = Scripted([
        Action.ask_human("move to bogus phase",
                         ai_source="scripted",
                         proposed_phase="teleportation"),
        Action.stop("done", ai_source="scripted"),
    ])
    ex = build_executor(core, provider=scripted,
                        limits=ExecutorLimits(max_steps=5),
                        ask_human=answer)
    run_id = "ai-tx-3"
    core.store.create_ai_run(run_id, "test", phase="recon")
    ex.phase_get = lambda: (core.store.get_ai_run(run_id) or {}).get("phase") or "recon"
    ex.phase_set = lambda p: core.store.set_ai_run_phase(run_id, p)

    history = asyncio.run(ex.run("test", job_id_prefix=run_id))

    run = core.store.get_ai_run(run_id)
    assert run is not None
    assert run["phase"] == "recon"
    # One of the entries should have an error about invalid phase
    errors = [r.error for r in history if r.error]
    assert any("invalid phase" in e for e in errors)


def test_ask_human_without_proposed_phase_does_not_change_phase(core: Core) -> None:
    async def answer(_action: Action) -> str:
        return "y"

    scripted = Scripted([
        Action.ask_human("which tool?", ai_source="scripted"),
        Action.stop("done", ai_source="scripted"),
    ])
    ex = build_executor(core, provider=scripted,
                        limits=ExecutorLimits(max_steps=5),
                        ask_human=answer)
    run_id = "ai-tx-4"
    core.store.create_ai_run(run_id, "test", phase="recon")
    ex.phase_get = lambda: (core.store.get_ai_run(run_id) or {}).get("phase") or "recon"
    ex.phase_set = lambda p: core.store.set_ai_run_phase(run_id, p)

    asyncio.run(ex.run("test", job_id_prefix=run_id))

    run = core.store.get_ai_run(run_id)
    assert run is not None
    assert run["phase"] == "recon"


def test_phase_history_accumulates(tmp_path: Path) -> None:
    from whaxon.core.store import JobStore
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-h", "test", phase="recon")
    s.set_ai_run_phase("ai-h", "enumeration")
    s.set_ai_run_phase("ai-h", "vulnerability")
    run = s.get_ai_run("ai-h")
    assert run is not None
    assert run["phase"] == "vulnerability"
    import json
    hist = json.loads(run["phase_history"])
    assert len(hist) == 2
    assert hist[0]["phase"] == "enumeration"
    assert hist[1]["phase"] == "vulnerability"


def test_phase_isolation_between_runs(tmp_path: Path) -> None:
    from whaxon.core.store import JobStore
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-a", "a", phase="recon")
    s.create_ai_run("ai-b", "b", phase="recon")
    s.set_ai_run_phase("ai-a", "enumeration")
    a = s.get_ai_run("ai-a")
    b = s.get_ai_run("ai-b")
    assert a["phase"] == "enumeration"
    assert b["phase"] == "recon"