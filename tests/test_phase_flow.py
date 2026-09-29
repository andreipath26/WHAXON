"""Phase propagation: store <-> agent <-> provider (step 3)."""
from __future__ import annotations

from pathlib import Path

from whaxon.ai.actions import Action
from whaxon.ai.agent import Agent
from whaxon.ai.provider import Provider
from whaxon.core.store import JobStore


def test_create_ai_run_default_phase_is_recon(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-1", "goal")
    run = s.get_ai_run("ai-1")
    assert run is not None
    assert run["phase"] == "recon"


def test_create_ai_run_custom_phase_round_trips(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-2", "goal", phase="enumeration")
    run = s.get_ai_run("ai-2")
    assert run is not None
    assert run["phase"] == "enumeration"


def test_list_ai_runs_includes_phase(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-3", "goal", phase="vulnerability")
    runs = s.list_ai_runs()
    match = [r for r in runs if r["id"] == "ai-3"]
    assert len(match) == 1
    assert match[0]["phase"] == "vulnerability"


class _PhaseSpy(Provider):
    """Records the phase passed into plan_step."""
    name = "phase-spy"

    def __init__(self) -> None:
        self.seen_phase: str | None = None

    def plan_step(self, goal, history, catalog, scope_summary, step,
                  max_steps, phase="recon", prior_runs=None):
        self.seen_phase = phase
        return Action.stop("done", ai_source=self.name)


def test_agent_next_action_forwards_phase() -> None:
    spy = _PhaseSpy()
    agent = Agent(provider=spy)
    action = agent.next_action(
        goal="x",
        history=[],
        catalog=[],
        scope_summary={},
        step=1,
        phase="initial-access",
    )
    assert action.kind == "stop"
    assert spy.seen_phase == "initial-access"