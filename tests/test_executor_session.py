"""Executor session branch — step 5 of session-execution migration."""
from __future__ import annotations

import asyncio

from whaxon.ai import Agent, Executor, ExecutorLimits
from whaxon.ai.actions import Action
from whaxon.ai.provider import Provider


class Scripted(Provider):
    name = "scripted"
    def __init__(self, actions):
        self._actions = actions
    def plan_step(self, goal, history, catalog, scope_summary, step,
                  max_steps, phase="recon", prior_runs=None):
        idx = step - 1
        if idx < len(self._actions):
            return self._actions[idx]
        return Action.stop("done", ai_source=self.name)


def _make_executor(actions, session_check=None, run_in_session=None,
                   catalog=None):
    agent = Agent(provider=Scripted(actions))
    return Executor(
        agent=agent,
        catalog_lookup=lambda tid: (catalog or {}).get(tid),
        scope_check=lambda t: (True, ""),
        run_tool=None,  # type: ignore[arg-type]
        get_findings=lambda jid: [],
        catalog_all=lambda: [],
        scope_summary=lambda: {},
        limits=ExecutorLimits(max_steps=4),
        session_check=session_check or (lambda sid: True),
        run_in_session=run_in_session,
    )


def test_session_action_runs_via_session_path() -> None:
    calls = []
    async def runner(tool_id, session_id, job_id):
        calls.append((tool_id, session_id, job_id))
        return "job-1"

    catalog = {"msf_sysinfo": {"id": "msf_sysinfo", "transport": "msf_session"}}
    actions = [
        Action.run_in_session("msf_sysinfo", "3",
                              rationale="enumerate", confidence=0.9,
                              ai_source="scripted"),
        Action.stop("done", ai_source="scripted"),
    ]
    ex = _make_executor(actions, run_in_session=runner, catalog=catalog)
    history = asyncio.run(ex.run("test"))

    assert len(calls) == 1
    assert calls[0][0] == "msf_sysinfo"
    assert calls[0][1] == "3"
    assert history[0].ok is True
    assert "session 3" in history[0].summary


def test_session_action_rejected_if_tool_not_session_scoped() -> None:
    catalog = {"nmap": {"id": "nmap", "transport": "cli"}}
    actions = [
        Action.run_in_session("nmap", "3",
                              rationale="wrong", ai_source="scripted"),
        Action.stop("done", ai_source="scripted"),
    ]
    ex = _make_executor(actions, catalog=catalog)
    history = asyncio.run(ex.run("test"))
    assert history[0].ok is False
    assert "not session-scoped" in history[0].error


def test_session_action_rejected_if_session_not_found() -> None:
    async def runner(tid, sid, jid):
        raise AssertionError("should not be called")

    catalog = {"msf_sysinfo": {"id": "msf_sysinfo", "transport": "msf_session"}}
    actions = [
        Action.run_in_session("msf_sysinfo", "99",
                              rationale="gone", ai_source="scripted"),
        Action.stop("done", ai_source="scripted"),
    ]
    ex = _make_executor(actions, session_check=lambda sid: False,
                        run_in_session=runner, catalog=catalog)
    history = asyncio.run(ex.run("test"))
    assert history[0].ok is False
    assert "not found" in history[0].error


def test_session_action_rejected_if_target_also_set() -> None:
    catalog = {"msf_sysinfo": {"id": "msf_sysinfo", "transport": "msf_session"}}
    # Build manually: classmethod forbids both, so construct directly.
    action = Action(kind="run_tool", tool_id="msf_sysinfo", target="10.0.0.5",
                    session_id="3", rationale="ambiguous", ai_source="scripted")
    actions = [action, Action.stop("done", ai_source="scripted")]
    ex = _make_executor(actions, catalog=catalog)
    history = asyncio.run(ex.run("test"))
    assert history[0].ok is False
    assert "must not also set target" in history[0].error


def test_session_action_rejected_if_no_runner() -> None:
    catalog = {"msf_sysinfo": {"id": "msf_sysinfo", "transport": "msf_session"}}
    actions = [
        Action.run_in_session("msf_sysinfo", "3",
                              rationale="x", ai_source="scripted"),
        Action.stop("done", ai_source="scripted"),
    ]
    ex = _make_executor(actions, run_in_session=None, catalog=catalog)
    history = asyncio.run(ex.run("test"))
    assert history[0].ok is False
    assert "no run_in_session callable" in history[0].error
    