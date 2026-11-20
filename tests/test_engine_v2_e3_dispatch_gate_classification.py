"""E3 scheduler: closed durable dispatch gate is not always cancellation."""
from __future__ import annotations

import pytest

from whaxon.core.scheduler import WorkflowScheduler
from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


@pytest.mark.asyncio
@pytest.mark.parametrize("gate", ["deadline", "cost", "cancel"])
async def test_dispatch_gate_failure_records_exact_non_execution_reason(tmp_path, gate):
    store = JobStore(tmp_path / "gate.db")
    store.create_mission("mission", "E3 dispatch boundary")
    store.save_workflow_plan("plan", WorkflowPlan(
        "mission", (WorkflowTask("task", "fixture", "192.0.2.10"),),
    ))
    policies = []
    dispatched = []

    def authorize(_task):
        policies.append(True)
        if len(policies) == 2:
            if gate == "deadline":
                import time
                store.set_workflow_deadline("plan", deadline_at=time.time() - 1)
            elif gate == "cost":
                store.set_mission_cost_limit("mission", max_cost_microusd=0)
            else:
                store.request_workflow_cancellation("plan")
        return True

    def dispatch(_task):
        dispatched.append(True)
        raise AssertionError("blocked or cancelled task must never dispatch")

    result = await WorkflowScheduler(
        store, authorize=authorize, dispatch=dispatch,
    ).run("plan", max_tasks=1)
    assert len(policies) == 2
    assert dispatched == []
    expected = "cancelled" if gate == "cancel" else "blocked"
    assert result["outcomes"][0]["status"] == expected
    assert result["tasks"][0]["status"] == expected
    attempts = store.list_workflow_attempts("plan")
    assert attempts[0]["status"] == expected
    assert "before provider dispatch" in attempts[0]["error"]
    assert not [
        e for e in store.list_workflow_events("plan")
        if e["event_type"] == "dispatch_started"
    ]
