"""whaxon ai --resume — pause and resume of ai_runs (agent-arch step 7)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from whaxon.ai import Agent, Executor, ExecutorLimits
from whaxon.ai.actions import Action, ActionResult
from whaxon.ai.provider import Provider
from whaxon.core.store import JobStore


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


def _bare_executor(actions, initial_history=None, ask_human=None):
    return Executor(
        agent=Agent(provider=Scripted(actions)),
        catalog_lookup=lambda _: None,
        scope_check=lambda _: (True, ""),
        run_tool=None,  # type: ignore[arg-type]
        get_findings=lambda _: [],
        catalog_all=list,
        scope_summary=dict,
        limits=ExecutorLimits(max_steps=10),
        ask_human=ask_human,
    )


def test_initial_history_starts_step_count_correctly() -> None:
    """initial_history raises the starting step; script index follows."""
    initial = [
        ActionResult(
            action=Action.run_tool("nmap", "1.2.3.4", rationale="prior",
                                   ai_source="scripted"),
            ok=True, summary="prior step", error="",
        ),
        ActionResult(
            action=Action.ask_human("approve?", ai_source="scripted"),
            ok=True, summary="approve?", error="",
        ),
        # The synthetic ack from the human's recorded answer
        ActionResult(
            action=Action.stop("human answered: 'y'", ai_source="human"),
            ok=True, summary="y", error="",
        ),
    ]
    # The provider is called with step=len(initial_history)+1 = 4 on
    # resume. Scripted indexes with step-1, so index 3 is what runs
    # next.
    actions = [
        Action.stop("unused-0", ai_source="scripted"),
        Action.stop("unused-1", ai_source="scripted"),
        Action.stop("unused-2", ai_source="scripted"),
        Action.run_tool("echo", "1.2.3.4", rationale="resumed step",
                        ai_source="scripted"),
        Action.stop("done", ai_source="scripted"),
    ]
    ex = _bare_executor(actions)

    async def answer(_action):
        return "y"

    ex.ask_human = answer
    history = asyncio.run(ex.run("test", initial_history=initial))

    # initial had 3 entries; the loop starts at step 4 so script index 3
    # (the run_tool at index 2 corresponds to step 3 of a fresh run; on
    # resume, step numbering is offset by len(initial). Verify the new
    # action from the run is the "resumed step" run_tool.
    tool_calls = [r.action.tool_id for r in history if r.action.kind == "run_tool"]
    assert "echo" in tool_calls


def test_pause_recording_in_store(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-p", "goal")
    s.set_ai_run_waiting("ai-p", json.dumps({"rationale": "approve?"}))
    r = s.get_ai_run("ai-p")
    assert r is not None
    assert r["status"] == "waiting"
    assert "approve?" in r["pending_question"]


def test_finalise_marks_waiting_when_last_is_ask_human(tmp_path: Path) -> None:
    """The CLI helper sets 'waiting' status when the loop pauses."""
    from whaxon.core import Core
    from whaxon.interfaces.cli.ai_cmd import _finalise

    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text('{"tools":[]}')
    core = Core(data_dir=data)
    core.store.create_ai_run("ai-f", "goal")

    hist = [ActionResult(
        action=Action.ask_human("approve?", ai_source="scripted"),
        ok=True, summary="approve?", error="",
    )]
    _finalise(core, "ai-f", hist)
    r = core.store.get_ai_run("ai-f")
    assert r["status"] == "waiting"
    assert "approve?" in r["pending_question"]


def test_finalise_marks_done_when_last_is_stop(tmp_path: Path) -> None:
    from whaxon.core import Core
    from whaxon.interfaces.cli.ai_cmd import _finalise

    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text('{"tools":[]}')
    core = Core(data_dir=data)
    core.store.create_ai_run("ai-d", "goal")

    hist = [ActionResult(
        action=Action.stop("done", ai_source="scripted"),
        ok=True, summary="done", error="",
    )]
    _finalise(core, "ai-d", hist)
    r = core.store.get_ai_run("ai-d")
    assert r["status"] == "done"


def test_question_json_contains_key_fields() -> None:
    from whaxon.interfaces.cli.ai_cmd import _question_json
    a = Action.ask_human("approve move to enumeration?",
                         confidence=0.8, ai_source="x",
                         proposed_phase="enumeration")
    q = json.loads(_question_json(a))
    assert q["kind"] == "ask_human"
    assert q["rationale"] == "approve move to enumeration?"
    assert q["proposed_phase"] == "enumeration"
    assert abs(q["confidence"] - 0.8) < 1e-6


def test_question_json_with_session_id() -> None:
    from whaxon.interfaces.cli.ai_cmd import _question_json
    a = Action.ask_human("proceed on session?",
                         ai_source="x")
    # session_id defaults to None on ask_human; verify the field is present
    q = json.loads(_question_json(a))
    assert "session_id" in q


def test_resume_rejects_missing_run(tmp_path: Path, capsys) -> None:
    from whaxon.interfaces.cli.ai_cmd import _run_resume

    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text('{"tools":[]}')

    with pytest.raises(SystemExit) as e:
        _run_resume("ai-nope", data, 5, "y")
    assert e.value.code == 1


def test_resume_rejects_run_with_no_steps(tmp_path: Path) -> None:
    from whaxon.core import Core
    from whaxon.interfaces.cli.ai_cmd import _run_resume

    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text('{"tools":[]}')
    core = Core(data_dir=data)
    core.store.create_ai_run("ai-empty", "goal")

    with pytest.raises(SystemExit) as e:
        _run_resume("ai-empty", data, 5, "y")
    assert e.value.code == 1