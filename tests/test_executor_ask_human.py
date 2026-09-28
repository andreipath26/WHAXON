"""ask_human pause/resume behavior in the executor loop.

Step 1 of the migration plan in docs/agent-architecture.md §13:
when an ask_human callback is provided, ask_human Actions pause
the loop and resume instead of terminating it.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from whaxon.core import Core
from whaxon.core.ai_bridge import build_executor
from whaxon.ai import ExecutorLimits
from whaxon.ai.actions import Action
from whaxon.ai.provider import Provider


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
    """Emits a scripted list of Actions, one per step."""
    name = "scripted"

    def __init__(self, actions: list[Action]) -> None:
        self._actions = actions

    def plan_step(self, goal, history, catalog, scope_summary, step, max_steps):
        idx = step - 1
        if idx < len(self._actions):
            return self._actions[idx]
        return Action.stop("script exhausted", ai_source=self.name)


def test_no_callback_terminates_on_ask_human(core: Core) -> None:
    """Existing behavior preserved: no callback -> loop ends at ask_human."""
    scripted = Scripted([
        Action.ask_human("need input", ai_source="scripted"),
        Action.run_tool("echo", "127.0.0.1", ai_source="scripted"),  # unreached
    ])
    ex = build_executor(core, provider=scripted,
                        limits=ExecutorLimits(max_steps=5))
    history = asyncio.run(ex.run("test", job_id_prefix="aitest"))
    assert len(history) == 1
    assert history[0].action.kind == "ask_human"
    assert history[0].ok is True


def test_callback_yes_continues_loop(core: Core) -> None:
    """Callback provided -> ask_human pauses, resumes, next step runs."""
    answers: list[str] = []

    async def answer(_action: Action) -> str:
        answers.append("y")
        return "y"

    scripted = Scripted([
        Action.ask_human("approve?", ai_source="scripted"),
        Action.run_tool("echo", "127.0.0.1",
                        extra_args="hello",
                        confidence=0.9, ai_source="scripted"),
        Action.stop("done", ai_source="scripted"),
    ])
    ex = build_executor(core, provider=scripted,
                        limits=ExecutorLimits(max_steps=5))
    ex.ask_human = answer
    history = asyncio.run(ex.run("test", job_id_prefix="aitest"))

    assert answers == ["y"]
    assert len(history) == 4
    assert history[0].action.kind == "ask_human"
    assert history[1].action.kind == "stop"     # the ack result
    assert history[1].action.ai_source == "human"
    assert history[1].summary == "y"
    assert history[2].action.kind == "run_tool"
    assert history[2].ok is True
    assert history[3].action.kind == "stop"


def test_callback_no_rejection_appears_in_history(core: Core) -> None:
    """A 'no' answer is recorded in history so the planner sees it."""
    async def answer(_action: Action) -> str:
        return "n"

    seen_history: list[list[dict]] = []

    class Recorder(Provider):
        name = "recorder"
        def __init__(self) -> None:
            self._script = [
                Action.ask_human("approve?", ai_source="recorder"),
                Action.stop("aborting per human", ai_source="recorder"),
            ]
        def plan_step(self, goal, history, catalog, scope_summary, step, max_steps):
            seen_history.append(list(history))
            idx = step - 1
            if idx < len(self._script):
                return self._script[idx]
            return Action.stop("done", ai_source=self.name)

    ex = build_executor(core, provider=Recorder(),
                        limits=ExecutorLimits(max_steps=5))
    ex.ask_human = answer
    history = asyncio.run(ex.run("test", job_id_prefix="aitest"))

    # Step 2 should see the human's answer in history.
    assert len(seen_history) >= 2
    step2_history = seen_history[1]
    human_entries = [h for h in step2_history
                     if h.get("action", {}).get("ai_source") == "human"]
    assert len(human_entries) == 1
    assert human_entries[0]["summary"] == "n"
    assert history[-1].action.kind == "stop"
