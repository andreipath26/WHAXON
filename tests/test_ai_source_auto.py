"""§4.1: auto-answered steps must record ai_source='auto', not 'human'.

The executor produced ack/tx/nack Actions with a hardcoded
ai_source="human" for every ask_human response, whether the response
came from a human at a terminal or from auto_answers. That
misattributed every --auto decision as human in reports and the store.
"""
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


def _run(core, ask, source, actions):
    results = []
    ex = build_executor(
        core,
        limits=ExecutorLimits(max_steps=10),
        on_action=lambda a: None,
        on_result=lambda r: results.append(r),
        ask_human=ask,
        ask_human_source=source,
        target_lock=None,
    )
    ex.agent.provider = Scripted(actions)
    asyncio.run(ex.run(goal="test", job_id_prefix="j"))
    return results


def test_auto_answered_step_records_auto(core: Core) -> None:
    async def auto_ask(action: Action) -> str:
        return "y"

    results = _run(core, auto_ask, "auto", [
        Action.ask_human("continue?", ai_source="scripted"),
        Action.stop("done", ai_source="scripted"),
    ])
    ack = next(r for r in results if "human answered" in r.action.rationale)
    assert ack.action.ai_source == "auto", (
        f"expected 'auto', got {ack.action.ai_source!r}"
    )


def test_human_answered_step_records_human(core: Core) -> None:
    async def human_ask(action: Action) -> str:
        return "y"

    results = _run(core, human_ask, "human", [
        Action.ask_human("continue?", ai_source="scripted"),
        Action.stop("done", ai_source="scripted"),
    ])
    ack = next(r for r in results if "human answered" in r.action.rationale)
    assert ack.action.ai_source == "human"


def test_phase_transition_records_source(core: Core) -> None:
    async def auto_ask(action: Action) -> str:
        return "y"

    results = _run(core, auto_ask, "auto", [
        Action.ask_human("advance to initial-access?", ai_source="scripted",
                         proposed_phase="initial-access"),
        Action.stop("done", ai_source="scripted"),
    ])
    tx = next((r for r in results if "phase transitioned" in r.action.rationale), None)
    assert tx is not None, "phase transition result missing"
    assert tx.action.ai_source == "auto"


def test_invalid_phase_rejection_records_source(core: Core) -> None:
    async def auto_ask(action: Action) -> str:
        return "y"

    results = _run(core, auto_ask, "auto", [
        Action.ask_human("advance to exploit?", ai_source="scripted",
                         proposed_phase="exploit"),
        Action.stop("done", ai_source="scripted"),
    ])
    nack = next((r for r in results if "rejected invalid phase" in r.action.rationale), None)
    assert nack is not None, "invalid-phase rejection missing"
    assert nack.action.ai_source == "auto"
