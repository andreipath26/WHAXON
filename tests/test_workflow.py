import asyncio
import inspect
from concurrent.futures import ThreadPoolExecutor

import pytest


def _run_async_test(test_function):
    """Run an async test without competing pytest event-loop plugins.

    pytest-playwright and pytest-asyncio both wrap coroutine tests when
    asyncio_mode=auto. Keep these scheduler tests independent of browser
    fixtures by exposing a synchronous pytest test that owns its loop.
    """
    def run(*args, **kwargs):
        # Some optional pytest plugins start an event loop in the worker
        # thread even for synchronous tests. Own a separate thread so this
        # test's asyncio loop can never collide with that loop.
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(
                asyncio.run, test_function(*args, **kwargs)
            ).result()

    # Preserve fixture discovery without exposing a coroutine function to
    # pytest-asyncio's auto mode (which would wrap it in a second event loop).
    run.__signature__ = inspect.signature(test_function)
    run.__name__ = test_function.__name__
    run.__qualname__ = test_function.__qualname__
    run.__doc__ = test_function.__doc__
    return run

from whaxon.core.workflow import (
    ApprovalBinding,
    WorkflowPlan,
    WorkflowTask,
)


def _plan():
    return WorkflowPlan(
        mission_id="mission-1",
        tasks=(
            WorkflowTask(
                id="recon", capability_id="network.port_scan", target="192.0.2.10",
                inputs={"ports": [80, 443]}, permissions=("network.scan",),
            ),
            WorkflowTask(
                id="web", capability_id="web.fingerprint", target="192.0.2.10",
                depends_on=("recon",), impact="low",
            ),
        ),
    )


def test_plan_roundtrip_is_stable_and_digest_is_deterministic():
    plan = _plan()
    restored = WorkflowPlan.from_dict(plan.to_dict())
    assert restored == plan
    assert restored.digest == plan.digest
    assert len(plan.digest) == 64


def test_plan_rejects_missing_dependency_and_cycle():

    with pytest.raises(ValueError, match="unknown dependencies"):
        WorkflowPlan("m", (WorkflowTask("a", "x", "host", depends_on=("missing",)),))
    with pytest.raises(ValueError, match="cycle"):
        WorkflowPlan(
            "m",
            (
                WorkflowTask("a", "x", "host", depends_on=("b",)),
                WorkflowTask("b", "y", "host", depends_on=("a",)),
            ),
        )


def test_task_rejects_unsafe_or_invalid_contract_values():

    with pytest.raises(ValueError, match="impact"):
        WorkflowTask("x", "cap", "host", impact="unbounded")
    with pytest.raises(ValueError, match="timeout"):
        WorkflowTask("x", "cap", "host", timeout_s=0)


def test_approval_binding_is_invalidated_by_any_bound_change():
    plan = _plan()
    task = plan.tasks[0]
    approval = ApprovalBinding(
        plan_digest=plan.digest,
        task_id=task.id,
        target=task.target,
        input_digest=ApprovalBinding.digest_inputs(task.inputs),
        policy_version="policy.v1",
        expires_at=200.0,
        permissions=task.permissions,
        impact=task.impact,
    )
    assert approval.is_valid(
        plan_digest=plan.digest, task=task, policy_version="policy.v1", now=100.0,
    )
    assert not approval.is_valid(
        plan_digest="changed", task=task, policy_version="policy.v1", now=100.0,
    )
    changed = WorkflowTask(
        id=task.id, capability_id=task.capability_id, target=task.target,
        inputs={"ports": [22]}, permissions=task.permissions, impact=task.impact,
    )
    assert not approval.is_valid(
        plan_digest=plan.digest, task=changed, policy_version="policy.v1", now=100.0,
    )
    assert not approval.is_valid(
        plan_digest=plan.digest, task=task, policy_version="policy.v2", now=100.0,
    )
    assert not approval.is_valid(
        plan_digest=plan.digest, task=task, policy_version="policy.v1", now=200.0,
    )


@_run_async_test
async def test_scheduler_cannot_override_persisted_parallel_limit(tmp_path):
    import asyncio

    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "scheduler-durable-limits.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan("p", WorkflowPlan("m", tuple(
        WorkflowTask(str(i), "cap", f"192.0.2.{i + 1}") for i in range(3)
    )))
    store.set_workflow_limits("p", max_total_attempts=2, max_concurrency=1)
    active = 0
    peak = 0

    async def dispatch(task):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return {"ok": True}

    result = await WorkflowScheduler(
        store, authorize=lambda task: True, dispatch=dispatch,
    ).run("p", max_tasks=100, max_concurrency=100)
    assert peak == 1
    assert result["attempts"] == 2
    assert sum(t["status"] == "pending" for t in result["tasks"]) == 1


def test_workflow_limits_are_durable_across_store_instances(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    path = tmp_path / "workflow-limits.db"
    store = JobStore(path)
    store.create_mission("m", "objective")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "cap", "192.0.2.1"),
        WorkflowTask("b", "cap", "192.0.2.2"),
        WorkflowTask("c", "cap", "192.0.2.3"),
    )))
    store.set_workflow_limits("p", max_total_attempts=2, max_concurrency=1)
    first = store.claim_ready_workflow_task("p", "worker-a")
    assert first is not None
    second_store = JobStore(path)
    assert second_store.claim_ready_workflow_task("p", "worker-b") is None
    store.finish_task_attempt(first["attempt_id"], "succeeded")
    second = second_store.claim_ready_workflow_task("p", "worker-b")
    assert second is not None
    second_store.finish_task_attempt(second["attempt_id"], "succeeded")
    assert store.claim_ready_workflow_task("p", "worker-c") is None
    assert store.list_workflow_tasks("p")[2]["status"] == "pending"
    with pytest.raises(ValueError, match="cannot be relaxed"):
        store.set_workflow_limits("p", max_total_attempts=3, max_concurrency=1)


def test_workflow_events_record_claim_finish_and_cancellation(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "events.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(claim["attempt_id"], "succeeded", result={"ok": True})
    store.request_workflow_cancellation("p")
    events = JobStore(path).list_workflow_events("p")
    assert [event["event_type"] for event in events] == [
        "task_claimed", "task_succeeded", "cancellation_requested", "task_cancelled",
    ]
    assert events[0]["detail"]["worker_id"] == "worker"
    assert len(store.list_workflow_events("p", events[0]["id"], 1)) == 1
    store.request_workflow_cancellation("p")
    assert len(store.list_workflow_events("p")) == 4


def test_workflow_reconciliation_and_dependency_block_record_events(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "events-recovery.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    assert claim is not None
    assert store.reconcile_workflow_attempts() == 1
    assert store.claim_ready_workflow_task("p", "next-worker") is None
    events = store.list_workflow_events("p")
    assert [e["event_type"] for e in events] == [
        "task_claimed", "task_uncertain", "task_blocked",
    ]
    assert events[1]["detail"]["reason"] == "stale_worker_lease"


def test_workflow_progress_is_durable_and_does_not_hide_active_attempts(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "workflow-progress.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    initial = store.get_workflow_progress("p")
    assert initial["total_tasks"] == 2
    assert initial["terminal_tasks"] == 0
    assert initial["attempts"] == 0
    assert initial["complete"] is False
    claim = store.claim_ready_workflow_task("p", "worker")
    assert claim is not None
    store.request_workflow_cancellation("p")
    progress = JobStore(path).get_workflow_progress("p")
    assert progress["cancellation_requested"] is True
    assert progress["counts"] == {"cancelled": 1, "running": 1}
    assert progress["attempts"] == 1
    assert progress["complete"] is False
    store.finish_task_attempt(claim["attempt_id"], "uncertain")
    final = JobStore(path).get_workflow_progress("p")
    assert final["complete"] is True
    assert final["counts"] == {"cancelled": 1, "uncertain": 1}


def test_workflow_cancellation_persists_across_reopen_and_prevents_claims(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "workflow-cancel.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    assert store.request_workflow_cancellation("p") == 2
    assert store.request_workflow_cancellation("p") == 0
    reopened = JobStore(path)
    assert reopened.get_workflow_plan("p")["status"] == "cancel_requested"
    assert reopened.claim_ready_workflow_task("p", "worker") is None
    assert [task["status"] for task in reopened.list_workflow_tasks("p")] == [
        "cancelled", "cancelled",
    ]


def test_cancellation_does_not_falsify_running_attempt_outcome(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "workflow-inflight.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claimed = store.claim_ready_workflow_task("p", "worker")
    assert claimed is not None
    assert store.request_workflow_cancellation("p") == 1
    assert store.claim_ready_workflow_task("p", "other-worker") is None
    states = store.list_workflow_tasks("p")
    assert [task["status"] for task in states] == ["running", "cancelled"]
    assert store.finish_task_attempt(
        claimed["attempt_id"], "uncertain",
        error="provider cancellation outcome not confirmed",
    )
    assert [task["status"] for task in store.list_workflow_tasks("p")] == [
        "uncertain", "cancelled",
    ]


@_run_async_test
async def test_cancellation_while_authorizing_prevents_provider_dispatch(tmp_path):
    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "cancel-auth.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    dispatched = []

    def authorize(task):
        store.request_workflow_cancellation("p")
        return True

    result = await WorkflowScheduler(
        store, authorize=authorize, dispatch=lambda task: dispatched.append(task.id),
    ).run("p")
    assert dispatched == []
    assert result["tasks"] == [
        {"id": "recon", "status": "cancelled"},
        {"id": "web", "status": "cancelled"},
    ]
    assert result["complete"] is True


@_run_async_test
async def test_scheduler_blocks_dependants_when_dispatch_outcome_is_uncertain(tmp_path):
    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "scheduler-exhausted.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    calls = []

    def dispatch(task):
        calls.append(task.id)
        raise RuntimeError("provider unavailable")

    scheduler = WorkflowScheduler(store, authorize=lambda task: True, dispatch=dispatch)
    result = await scheduler.run("p", max_attempts=1)
    assert calls == ["recon"]
    assert result["tasks"] == [
        {"id": "recon", "status": "uncertain"},
        {"id": "web", "status": "blocked"},
    ]
    assert result["complete"] is True


@_run_async_test
async def test_scheduler_blocks_dependants_after_policy_denial(tmp_path):
    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "scheduler-blocked.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    result = await WorkflowScheduler(
        store, authorize=lambda task: False, dispatch=lambda task: None,
    ).run("p")
    assert result["tasks"] == [
        {"id": "recon", "status": "blocked"},
        {"id": "web", "status": "blocked"},
    ]
    assert result["complete"] is True


def test_workflow_contract_nested_mappings_are_immutable():

    inputs = {"options": {"ports": [80, 443]}}
    metadata = {"labels": ["approved"]}
    task = WorkflowTask("scan", "network.port_scan", "192.0.2.10", inputs=inputs)
    plan = WorkflowPlan("m", (task,), metadata=metadata)
    digest = plan.digest
    inputs["options"]["ports"].append(8080)
    metadata["labels"].append("changed")
    assert plan.digest == digest
    with pytest.raises(TypeError, match="immutable"):
        task.inputs["new"] = "value"
    with pytest.raises(TypeError, match="immutable"):
        task.inputs["options"]["new"] = "value"
    assert task.inputs["options"]["ports"] == (80, 443)


def test_workflow_task_rejects_non_finite_timeout():
    import math


    with pytest.raises(ValueError, match="finite"):
        WorkflowTask("bad", "cap", "host", timeout_s=math.inf)
    with pytest.raises(ValueError, match="finite"):
        WorkflowTask("bad", "cap", "host", timeout_s=math.nan)


@_run_async_test
async def test_scheduler_applies_timeout_to_synchronous_provider(tmp_path):
    import time

    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "scheduler-sync-timeout.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan(
        "p", WorkflowPlan("m", (
            WorkflowTask("slow", "provider.sync", "192.0.2.10", timeout_s=0.3),
        )),
    )

    dispatched = []

    def dispatch(task):
        dispatched.append(task.id)
        time.sleep(0.8)
        return {"done": True}

    async def authorize(task):
        return True

    result = await WorkflowScheduler(
        store, authorize=authorize, dispatch=dispatch,
    ).run("p")
    assert dispatched == ["slow"]
    assert result["tasks"] == [{"id": "slow", "status": "uncertain"}]
    assert result["attempts"] == 1



@_run_async_test
async def test_scheduler_runs_independent_tasks_concurrently(tmp_path):
    import asyncio

    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "scheduler-parallel.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "provider.a", "192.0.2.10"),
        WorkflowTask("b", "provider.b", "192.0.2.11"),
        WorkflowTask("c", "provider.c", "192.0.2.12", depends_on=("a", "b")),
    )))
    active = 0
    peak = 0
    gate = asyncio.Event()

    async def dispatch(task):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if task.id in ("a", "b"):
            if peak >= 2:
                gate.set()
            await asyncio.wait_for(gate.wait(), timeout=1)
        else:
            assert task.id == "c"
            states = store.list_workflow_tasks("p")
            assert all(x["status"] == "succeeded" for x in states[:2])
        active -= 1
        return {"task": task.id}

    result = await WorkflowScheduler(
        store, authorize=lambda task: True, dispatch=dispatch,
    ).run("p", max_concurrency=2)

    assert peak == 2
    assert result["attempts"] == 3
    assert result["complete"] is True
    assert [task["status"] for task in result["tasks"]] == [
        "succeeded", "succeeded", "succeeded",
    ]


@_run_async_test
async def test_scheduler_respects_max_concurrency_and_task_budget(tmp_path):
    import asyncio

    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "scheduler-budget.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan("p", WorkflowPlan("m", tuple(
        WorkflowTask(f"task-{i}", "provider.scan", f"192.0.2.{i + 1}")
        for i in range(5)
    )))
    active = 0
    peak = 0

    async def dispatch(task):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return task.id

    result = await WorkflowScheduler(
        store, authorize=lambda task: True, dispatch=dispatch,
    ).run("p", max_tasks=3, max_concurrency=2)

    assert result["attempts"] == 3
    assert peak <= 2
    assert sum(task["status"] == "succeeded" for task in result["tasks"]) == 3
    assert result["complete"] is False


@_run_async_test
async def test_scheduler_applies_task_deadline_to_synchronous_authorization(tmp_path):
    import time

    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "scheduler-auth-timeout.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "provider.scan", "192.0.2.10", timeout_s=0.02),
    )))
    dispatched = []

    def authorize(task):
        time.sleep(0.1)
        return True

    result = await WorkflowScheduler(
        store, authorize=authorize, dispatch=lambda task: dispatched.append(task.id),
    ).run("p")
    assert result["tasks"] == [{"id": "scan", "status": "blocked"}]
    assert dispatched == []


@_run_async_test
async def test_scheduler_applies_task_deadline_to_async_authorization(tmp_path):
    import asyncio

    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "scheduler-async-auth-timeout.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "provider.scan", "192.0.2.10", timeout_s=0.02),
    )))
    dispatched = []

    async def authorize(task):
        await asyncio.sleep(0.1)
        return True

    result = await WorkflowScheduler(
        store, authorize=authorize, dispatch=lambda task: dispatched.append(task.id),
    ).run("p")
    assert result["tasks"] == [{"id": "scan", "status": "blocked"}]
    assert dispatched == []


def test_plan_scoped_recovery_preserves_fresh_lease_and_other_plans(tmp_path):
    import sqlite3
    import time

    from whaxon.core.store import JobStore

    path = tmp_path / "plan-recovery.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    store.save_workflow_plan("other", WorkflowPlan(
        "mission-1", (WorkflowTask("other", "network.port_scan", "192.0.2.11"),),
    ))
    old = store.claim_ready_workflow_task("p", "dead-worker")
    live = store.claim_ready_workflow_task("other", "live-worker")
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE task_attempts SET heartbeat_at=? WHERE id=?",
            (time.time() - 120, old["attempt_id"]),
        )
    assert store.reconcile_workflow_plan("p", stale_after_s=60) == 1
    assert store.reconcile_workflow_plan("p", stale_after_s=60) == 0
    assert store.list_workflow_tasks("p")[0]["status"] == "uncertain"
    assert store.list_workflow_tasks("other")[0]["status"] == "running"
    assert store.heartbeat_workflow_attempt(live["attempt_id"]) is True
    assert store.heartbeat_workflow_attempt(old["attempt_id"]) is False
    assert store.list_workflow_events("p")[-1]["detail"]["reason"] == "expired_lease"


def test_workflow_progress_rejects_unknown_plan(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "unknown-plan.db")
    with pytest.raises(ValueError, match="unknown workflow plan"):
        store.get_workflow_progress("missing")
    with pytest.raises(ValueError, match="unknown workflow plan"):
        store.list_workflow_events("missing")
    with pytest.raises(ValueError, match="unknown workflow plan"):
        store.reconcile_workflow_plan("missing")
    with pytest.raises(ValueError, match="unknown workflow plan"):
        store.set_workflow_limits("missing", max_total_attempts=1, max_concurrency=1)


def test_workflow_events_reject_invalid_polling_bounds(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "poll-bounds.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    with pytest.raises(ValueError, match="after_id"):
        store.list_workflow_events("p", after_id=-1)
    with pytest.raises(ValueError, match="limit"):
        store.list_workflow_events("p", limit=1001)


@_run_async_test
async def test_cancellation_during_provider_dispatch_is_not_reported_as_success(tmp_path):
    import asyncio

    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "cancel-in-flight.db")
    store.create_mission("m", "controlled local test")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.10"),
        WorkflowTask("b", "fixture", "192.0.2.11", depends_on=("a",)),
    )))

    async def dispatch(task):
        assert task.id == "a"
        store.request_workflow_cancellation("p")
        await asyncio.sleep(0)
        return {"dispatched": True}

    result = await WorkflowScheduler(
        store, authorize=lambda task: True, dispatch=dispatch,
    ).run("p")
    assert result["tasks"] == [
        {"id": "a", "status": "uncertain"},
        {"id": "b", "status": "cancelled"},
    ]
    assert result["complete"] is True
    assert "task_uncertain" in [
        event["event_type"] for event in store.list_workflow_events("p")
    ]


def test_manual_attempt_cannot_bypass_cancellation_or_durable_limits(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "manual-attempt-guards.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    store.set_workflow_limits("p", max_total_attempts=1, max_concurrency=1)
    assert store.start_task_attempt("manual-1", "recon", 1, plan_id="p")
    with pytest.raises(ValueError, match="budget"):
        store.start_task_attempt("manual-2", "web", 1, plan_id="p")
    store.finish_task_attempt("manual-1", "failed")
    with pytest.raises(ValueError, match="budget"):
        store.start_task_attempt("manual-3", "recon", 2, plan_id="p")
    store.request_workflow_cancellation("p")
    with pytest.raises(ValueError, match="cancellation"):
        store.start_task_attempt("manual-4", "recon", 2, plan_id="p")


def test_manual_attempt_records_event_and_requires_sequential_attempt_numbers(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "manual-attempt-events.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    with pytest.raises(ValueError, match="next positive sequence"):
        store.start_task_attempt("a0", "recon", 2, plan_id="p")
    assert store.start_task_attempt("a1", "recon", 1, worker_id="manual", plan_id="p")
    events = store.list_workflow_events("p")
    assert events[0]["attempt_id"] == "a1"
    assert events[0]["detail"]["worker_id"] == "manual"
    store.finish_task_attempt("a1", "failed")
    with pytest.raises(ValueError, match="next positive sequence"):
        store.start_task_attempt("a2", "recon", 1, plan_id="p")
    assert store.start_task_attempt("a2", "recon", 2, plan_id="p")


@_run_async_test
async def test_dispatch_boundary_rechecks_authorization_when_scope_changes(tmp_path):
    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "policy-recheck.db")
    store.create_mission("m", "controlled lab")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    checks = []
    dispatched = []

    def authorize(task):
        checks.append(task.id)
        return len(checks) == 1

    result = await WorkflowScheduler(
        store, authorize=authorize, dispatch=lambda task: dispatched.append(task.id),
    ).run("p")
    assert checks == ["scan", "scan"]
    assert dispatched == []
    assert result["tasks"] == [{"id": "scan", "status": "blocked"}]


def test_limits_configuration_is_audited_idempotently(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "limit-audit.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    store.set_workflow_limits("p", max_total_attempts=3, max_concurrency=2)
    store.set_workflow_limits("p", max_total_attempts=3, max_concurrency=2)
    store.set_workflow_limits("p", max_total_attempts=2, max_concurrency=1)
    events = store.list_workflow_events("p")
    assert [event["event_type"] for event in events] == [
        "limits_configured", "limits_configured",
    ]
    assert events[-1]["detail"] == {
        "max_total_attempts": 2, "max_concurrency": 1,
    }


def test_progress_reports_durable_remaining_budget_and_active_workers(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "progress-budget.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    store.set_workflow_limits("p", max_total_attempts=1, max_concurrency=1)
    initial = store.get_workflow_progress("p")
    assert initial["remaining_attempt_budget"] == 1
    assert initial["active_attempts"] == 0
    claim = store.claim_ready_workflow_task("p", "worker")
    during = JobStore(path).get_workflow_progress("p")
    assert during["remaining_attempt_budget"] == 0
    assert during["active_attempts"] == 1
    assert during["attempt_budget_exhausted"] is True
    store.finish_task_attempt(claim["attempt_id"], "succeeded")
    after = store.get_workflow_progress("p")
    assert after["active_attempts"] == 0
    assert after["attempt_budget_exhausted"] is True


def test_dispatch_intent_is_atomic_auditable_and_cancellation_fenced(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "dispatch-intent.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    assert claim is not None
    assert store.mark_workflow_dispatch_started("p", claim["attempt_id"]) is True
    with pytest.raises(ValueError, match="already recorded"):
        store.mark_workflow_dispatch_started("p", claim["attempt_id"])
    assert [event["event_type"] for event in store.list_workflow_events("p")][:2] == [
        "task_claimed", "dispatch_started",
    ]
    store.request_workflow_cancellation("p")
    assert store.mark_workflow_dispatch_started("p", claim["attempt_id"]) is False


def test_attempt_diagnostics_survive_restart_and_exclude_sensitive_inputs(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "attempt-diagnostics.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(claim["attempt_id"], "failed", error="fixture error")
    attempts = JobStore(path).list_workflow_attempts("p")
    assert len(attempts) == 1
    assert attempts[0]["task_key"] == "recon"
    assert attempts[0]["worker_id"] == "worker"
    assert attempts[0]["status"] == "failed"
    assert attempts[0]["error"] == "fixture error"
    assert "inputs" not in attempts[0]
    assert "result_json" not in attempts[0]
    assert store.list_workflow_attempts("p", after_started=attempts[0]["started_at"]) == []


def test_attempt_diagnostics_reject_bad_pagination(tmp_path):
    import math

    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "attempt-pagination.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    for invalid in (-1, math.nan, math.inf, True):
        with pytest.raises(ValueError, match="after_started"):
            store.list_workflow_attempts("p", after_started=invalid)
    for invalid in (0, 1001, True):
        with pytest.raises(ValueError, match="limit"):
            store.list_workflow_attempts("p", limit=invalid)


def test_mission_plan_listing_is_durable_and_scoped(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "mission-plans.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.create_mission("mission-2", "other")
    store.save_workflow_plan("p1", _plan())
    rows = JobStore(path).list_workflow_mission_plans("mission-1")
    assert len(rows) == 1
    assert rows[0]["id"] == "p1"
    assert len(rows[0]["digest"]) == 64
    assert JobStore(path).list_workflow_mission_plans("mission-2") == []
    with pytest.raises(ValueError, match="unknown mission"):
        store.list_workflow_mission_plans("missing")


def test_durable_mission_listing_is_bounded_and_does_not_expose_metadata(tmp_path):
    import math

    from whaxon.core.store import JobStore

    path = tmp_path / "missions-list.db"
    store = JobStore(path)
    store.create_mission("m1", "first", metadata={"secret": "not in listing"})
    store.create_mission("m2", "second")
    rows = JobStore(path).list_missions(limit=1)
    assert len(rows) == 1
    assert rows[0]["id"] == "m1"
    assert "metadata" not in rows[0]
    assert len(store.list_missions()) == 2
    for invalid in (0, 1001, True):
        with pytest.raises(ValueError, match="limit"):
            store.list_missions(limit=invalid)
    for invalid in (-1, math.nan, True):
        with pytest.raises(ValueError, match="after_created"):
            store.list_missions(after_created=invalid)


def test_workflow_audit_integrity_detects_missing_events(tmp_path):
    import sqlite3

    from whaxon.core.store import JobStore

    path = tmp_path / "audit-integrity.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(claim["attempt_id"], "succeeded")
    assert store.get_workflow_audit_integrity("p")["consistent"] is True
    with sqlite3.connect(path) as db:
        db.execute(
            "DELETE FROM workflow_events "
            "WHERE attempt_id=? AND event_type='task_succeeded'",
            (claim["attempt_id"],),
        )
    audit = store.get_workflow_audit_integrity("p")
    assert audit["consistent"] is False
    assert audit["missing_or_duplicate_terminal_events"] == [claim["attempt_id"]]


def test_reconciliation_report_identifies_dispatch_uncertainty(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "reconciliation-report.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    before = store.get_workflow_dispatch_reconciliation("p")
    assert before[0]["external_effect_possible"] is False
    assert before[0]["manual_reconciliation_required"] is False
    store.mark_workflow_dispatch_started("p", claim["attempt_id"])
    store.finish_task_attempt(claim["attempt_id"], "uncertain")
    after = store.get_workflow_dispatch_reconciliation("p")
    assert after[0]["external_effect_possible"] is True
    assert after[0]["manual_reconciliation_required"] is True
    assert after[0]["status"] == "uncertain"


def test_workflow_absolute_deadline_is_durable_and_unextendable(tmp_path):
    import time

    from whaxon.core.store import JobStore

    path = tmp_path / "deadlines.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    past = time.time() - 5
    store.set_workflow_deadline("p", deadline_at=past)
    other = JobStore(path)
    assert other.get_workflow_deadline("p") == past
    assert other.claim_ready_workflow_task("p", "worker") is None
    with pytest.raises(ValueError, match="cannot be extended"):
        store.set_workflow_deadline("p", deadline_at=time.time() + 100)
    with pytest.raises(ValueError, match="deadline exceeded"):
        other.start_task_attempt("a", "recon", 1, plan_id="p")
    assert [e["event_type"] for e in store.list_workflow_events("p")] == ["deadline_set"]


def test_workflow_dispatch_deadline_fences_claimed_task(tmp_path):
    import time

    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "deadline-dispatch.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    store.set_workflow_deadline("p", deadline_at=time.time() - 1)
    assert store.mark_workflow_dispatch_started("p", claim["attempt_id"]) is False


def test_manual_attempt_is_not_allowed_to_bypass_dag_dependencies(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "manual-dependencies.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    with pytest.raises(ValueError, match="dependencies"):
        store.start_task_attempt("web-1", "web", 1, plan_id="p")
    assert store.start_task_attempt("recon-1", "recon", 1, plan_id="p")
    with pytest.raises(ValueError, match="dependencies"):
        store.start_task_attempt("web-2", "web", 1, plan_id="p")
    store.finish_task_attempt("recon-1", "succeeded")
    assert store.start_task_attempt("web-3", "web", 1, plan_id="p")


def test_durable_rate_limit_fences_claims_across_restarted_workers(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    path = tmp_path / "rate-limit.db"
    store = JobStore(path)
    store.create_mission("m", "controlled test")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.1"),
        WorkflowTask("b", "fixture", "192.0.2.2"),
    )))
    store.set_workflow_rate_limit("p", min_spacing_s=60.0)
    first = store.claim_ready_workflow_task("p", "worker-1")
    assert first is not None
    store.finish_task_attempt(first["attempt_id"], "succeeded")
    reopened = JobStore(path)
    assert reopened.claim_ready_workflow_task("p", "worker-2") is None
    with pytest.raises(ValueError, match="rate budget"):
        reopened.start_task_attempt("manual", "b", 1, plan_id="p")
    with pytest.raises(ValueError, match="cannot be relaxed"):
        store.set_workflow_rate_limit("p", min_spacing_s=1.0)
    assert [e["event_type"] for e in store.list_workflow_events("p")][:2] == [
        "rate_limit_set", "task_claimed",
    ]


def test_workflow_resource_summary_does_not_fabricate_cost_or_memory(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "resource-summary.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(claim["attempt_id"], "succeeded")
    summary = JobStore(path).get_workflow_resource_summary("p")
    assert summary["attempts"] == 1
    assert summary["active_attempts"] == 0
    assert summary["completed_attempt_wall_seconds"] >= 0
    assert summary["cost_usd"] is None
    assert summary["cpu_seconds"] is None
    assert summary["memory_peak_bytes"] is None
    assert summary["cost_accounting_available"] is False


def test_workflow_attempt_ownership_fence_survives_restart(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "ownership.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    assert JobStore(path).workflow_attempt_owned(claim["attempt_id"]) is True
    store.reconcile_workflow_attempts()
    assert JobStore(path).workflow_attempt_owned(claim["attempt_id"]) is False
    assert store.workflow_attempt_owned("unknown") is False


def test_workflow_readiness_rejects_uncertain_external_effects(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "readiness.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    store.mark_workflow_dispatch_started("p", claim["attempt_id"])
    store.finish_task_attempt(claim["attempt_id"], "uncertain")
    status = store.get_workflow_readiness("p")
    assert status["ready_to_report_success"] is False
    assert "uncertain_task_outcomes" in status["blockers"]
    assert "external_effect_reconciliation_required" in status["blockers"]


def test_workflow_readiness_no_premature_success(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "readiness-pending.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    status = store.get_workflow_readiness("p")
    assert status["complete"] is False
    assert status["ready_to_report_success"] is False


def test_workflow_approval_is_durable_exact_bound_and_revocable(tmp_path):
    import time

    from whaxon.core.store import JobStore

    path = tmp_path / "approvals.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    expiry = time.time() + 300
    assert store.grant_workflow_approval(
        "p", "recon", "approval-1", "operator", expires_at=expiry,
    ) is True
    reopened = JobStore(path)
    assert reopened.has_valid_workflow_approval("p", "recon")
    assert not reopened.has_valid_workflow_approval("p", "web")
    assert not reopened.has_valid_workflow_approval("p", "recon", policy_version="policy.v2")
    assert len(reopened.list_workflow_approvals("p")) == 1
    assert reopened.grant_workflow_approval(
        "p", "recon", "approval-1", "operator", expires_at=expiry,
    ) is False
    with pytest.raises(ValueError, match="immutable"):
        reopened.grant_workflow_approval(
            "p", "recon", "approval-1", "different-actor", expires_at=expiry,
        )
    assert reopened.revoke_workflow_approval("p", "approval-1", actor="operator")
    assert not reopened.has_valid_workflow_approval("p", "recon")
    assert not reopened.revoke_workflow_approval("p", "approval-1", actor="operator")
    assert [event["event_type"] for event in store.list_workflow_events("p")] == [
        "approval_granted", "approval_revoked",
    ]


def test_workflow_approval_rejects_expired_and_cancelled_plan(tmp_path):
    import time

    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "approval-invalid.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    with pytest.raises(ValueError, match="future"):
        store.grant_workflow_approval(
            "p", "recon", "approval-expired", "operator", expires_at=time.time() - 1,
        )
    store.request_workflow_cancellation("p")
    with pytest.raises(ValueError, match="cancellation"):
        store.grant_workflow_approval(
            "p", "recon", "approval-cancelled", "operator", expires_at=time.time() + 300,
        )


@_run_async_test
async def test_scheduler_does_not_replay_unknown_post_dispatch_outcome(tmp_path):
    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "retryable-completion.db")
    store.create_mission("m", "controlled test")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.10"),
    )))

    def failing_dispatch(_task):
        raise RuntimeError("fixture failure")

    scheduler = WorkflowScheduler(
        store, authorize=lambda _task: True, dispatch=failing_dispatch,
    )
    first = await scheduler.run("p", max_tasks=1, max_attempts=2)
    assert first["attempts"] == 1
    assert first["tasks"][0]["status"] == "uncertain"
    assert first["complete"] is True
    second = await scheduler.run("p", max_tasks=1, max_attempts=2)
    assert second["attempts"] == 0
    assert second["tasks"][0]["status"] == "uncertain"
    assert second["complete"] is True


def test_durable_progress_does_not_mark_retryable_failure_complete(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "retry-progress.db")
    store.create_mission("m", "controlled test")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("only", "fixture", "192.0.2.10"),
    )))
    attempt = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(attempt["attempt_id"], "failed")
    progress = store.get_workflow_progress("p")
    assert progress["counts"]["failed"] == 1
    assert progress["terminal_tasks"] == 0
    assert progress["complete"] is False


def test_workflow_event_cursor_is_durable_monotone_and_plan_scoped(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "workflow-cursor.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    store.save_workflow_plan("p2", WorkflowPlan(
        "mission-1", (WorkflowTask("other", "network.port_scan", "192.0.2.11"),),
    ))
    one = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(one["attempt_id"], "succeeded")
    events = store.list_unacknowledged_workflow_events("p", "reporter")
    assert len(events) >= 2
    first = events[0]["id"]
    assert store.acknowledge_workflow_events("p", "reporter", first) == first
    reloaded = JobStore(path)
    assert reloaded.get_workflow_event_cursor("p", "reporter") == first
    assert reloaded.get_workflow_event_cursor("p", "other") == 0
    assert reloaded.list_unacknowledged_workflow_events("p", "reporter")[0]["id"] > first
    with pytest.raises(ValueError, match="this workflow"):
        reloaded.acknowledge_workflow_events("p2", "reporter", first)
    assert reloaded.acknowledge_workflow_events("p", "reporter", events[-1]["id"]) == events[-1]["id"]
    with pytest.raises(ValueError, match="backwards"):
        reloaded.acknowledge_workflow_events("p", "reporter", first)
    assert reloaded.list_unacknowledged_workflow_events("p", "reporter") == []


def test_workflow_event_cursor_rejects_invalid_acknowledgements(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "workflow-invalid-cursor.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    for event_id in (0, -1, True, 1.5):
        with pytest.raises(ValueError, match="event_id"):
            store.acknowledge_workflow_events("p", "reporter", event_id)
    with pytest.raises(ValueError, match="consumer_id"):
        store.get_workflow_event_cursor("p", "")


def test_attempt_aggregation_is_unpaginated_and_plan_scoped(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "attempt-aggregation.db")
    store.create_mission("m", "controlled")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.1"),
    )))
    store.save_workflow_plan("other", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.2"),
    )))
    assert store.count_workflow_task_attempts("p") == {}
    first = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(first["attempt_id"], "failed")
    second = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(second["attempt_id"], "succeeded")
    assert store.count_workflow_task_attempts("p") == {"a": 2}
    assert store.count_workflow_task_attempts("other") == {}


def test_workflow_events_reject_boolean_pagination_bounds(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "boolean-pagination.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    with pytest.raises(ValueError, match="after_id"):
        store.list_workflow_events("p", after_id=True)
    with pytest.raises(ValueError, match="limit"):
        store.list_workflow_events("p", limit=True)


@_run_async_test
async def test_scheduler_rejects_bool_and_fractional_execution_budgets(tmp_path):
    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore

    scheduler = WorkflowScheduler(
        JobStore(tmp_path / "invalid-budget.db"),
        authorize=lambda task: True, dispatch=lambda task: True,
    )
    for budget in (True, 1.5, 0, -1):
        with pytest.raises(ValueError, match="positive integers"):
            await scheduler.run("missing", max_tasks=budget)


def test_workflow_claim_rejects_noninteger_attempt_limits(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "invalid-claim-budget.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    for invalid in (True, False, 1.5, 0, -1, "2"):
        with pytest.raises(ValueError, match="positive integer"):
            store.claim_ready_workflow_task("p", "worker", max_attempts=invalid)
    assert store.claim_ready_workflow_task("p", "worker", max_attempts=1) is not None


def test_mission_wide_attempt_cap_applies_across_independent_plans(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    path = tmp_path / "mission-budget.db"
    store = JobStore(path)
    store.create_mission("m", "controlled")
    for plan_id, target in (("p1", "192.0.2.10"), ("p2", "192.0.2.12")):
        store.save_workflow_plan(plan_id, WorkflowPlan("m", (
            WorkflowTask("scan", "fixture", target),
        )))
    store.set_mission_execution_limits("m", max_total_attempts=1, max_concurrency=1)
    first = store.claim_ready_workflow_task("p1", "worker-1")
    assert first is not None
    assert JobStore(path).claim_ready_workflow_task("p2", "worker-2") is None
    store.finish_task_attempt(first["attempt_id"], "succeeded")
    assert JobStore(path).claim_ready_workflow_task("p2", "worker-2") is None
    usage = JobStore(path).get_mission_execution_limits("m")
    assert usage["attempts"] == 1
    assert usage["active_attempts"] == 0
    with pytest.raises(ValueError, match="cannot be relaxed"):
        store.set_mission_execution_limits("m", max_total_attempts=2, max_concurrency=1)


def test_mission_concurrency_cap_releases_after_completed_attempt(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "mission-concurrency.db")
    store.create_mission("m", "controlled")
    for plan_id, target in (("p1", "192.0.2.11"), ("p2", "192.0.2.13")):
        store.save_workflow_plan(plan_id, WorkflowPlan("m", (
            WorkflowTask("scan", "fixture", target),
        )))
    store.set_mission_execution_limits("m", max_total_attempts=3, max_concurrency=1)
    first = store.claim_ready_workflow_task("p1", "worker")
    assert store.claim_ready_workflow_task("p2", "worker") is None
    store.finish_task_attempt(first["attempt_id"], "succeeded")
    assert store.claim_ready_workflow_task("p2", "worker") is not None
    usage = store.get_mission_execution_limits("m")
    assert usage["attempts"] == 2
    assert usage["active_attempts"] == 1


def test_mission_budget_rejects_direct_attempt_bypass(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "mission-direct.db")
    store.create_mission("m", "controlled")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.10"),
        WorkflowTask("b", "fixture", "192.0.2.11"),
    )))
    store.set_mission_execution_limits("m", max_total_attempts=1, max_concurrency=1)
    claim = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(claim["attempt_id"], "succeeded")
    with pytest.raises(ValueError, match="mission execution budget"):
        store.start_task_attempt("manual", "b", 1, plan_id="p")


def test_mission_deadline_stops_all_plans_and_is_durable(tmp_path):
    import time

    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    path = tmp_path / "mission-deadline.db"
    store = JobStore(path)
    store.create_mission("m", "controlled")
    store.create_mission("other", "unrelated")
    for plan_id, target in (("p1", "192.0.2.1"), ("p2", "192.0.2.2")):
        store.save_workflow_plan(plan_id, WorkflowPlan("m", (
            WorkflowTask("scan", "fixture", target),
        )))
    store.save_workflow_plan("p3", WorkflowPlan("other", (
        WorkflowTask("scan", "fixture", "192.0.2.3"),
    )))
    cutoff = time.time() - 1
    store.set_mission_deadline("m", deadline_at=cutoff)
    restarted = JobStore(path)
    assert restarted.get_mission_deadline("m") == cutoff
    assert restarted.claim_ready_workflow_task("p1", "worker") is None
    assert restarted.claim_ready_workflow_task("p2", "worker") is None
    assert restarted.claim_ready_workflow_task("p3", "worker") is not None
    with pytest.raises(ValueError, match="mission deadline exceeded"):
        restarted.start_task_attempt("manual", "scan", 1, plan_id="p1")
    with pytest.raises(ValueError, match="cannot be extended"):
        restarted.set_mission_deadline("m", deadline_at=time.time() + 10)


def test_mission_deadline_blocks_dispatch_after_claim(tmp_path):
    import time

    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "mission-dispatch-deadline.db")
    store.create_mission("m", "controlled")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.1"),
    )))
    claim = store.claim_ready_workflow_task("p", "worker")
    store.set_mission_deadline("m", deadline_at=time.time() - 1)
    assert store.mark_workflow_dispatch_started("p", claim["attempt_id"]) is False


def test_mission_cost_ledger_is_durable_idempotent_and_fail_closed(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    path = tmp_path / "cost-ledger.db"
    store = JobStore(path)
    store.create_mission("m", "controlled")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.1"),
        WorkflowTask("b", "fixture", "192.0.2.2"),
    )))
    store.set_mission_cost_limit("m", max_cost_microusd=10)
    claim = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(claim["attempt_id"], "succeeded")
    assert JobStore(path).claim_ready_workflow_task("p", "worker") is None
    assert store.get_mission_cost_summary("m")["unreported_attempts"] == 1
    assert store.record_workflow_attempt_cost(
        claim["attempt_id"], cost_microusd=4, source="provider-invoice",
    ) == 4
    assert store.record_workflow_attempt_cost(
        claim["attempt_id"], cost_microusd=4, source="provider-invoice",
    ) == 4
    with pytest.raises(ValueError, match="conflicting"):
        store.record_workflow_attempt_cost(
            claim["attempt_id"], cost_microusd=7, source="provider-invoice",
        )
    assert JobStore(path).get_mission_cost_summary("m")["accounted_cost_microusd"] == 4
    next_claim = JobStore(path).claim_ready_workflow_task("p", "worker")
    assert next_claim is not None
    store.finish_task_attempt(next_claim["attempt_id"], "succeeded")
    store.record_workflow_attempt_cost(
        next_claim["attempt_id"], cost_microusd=6, source="provider-invoice",
    )
    assert store.get_mission_cost_summary("m")["exhausted"] is True
    assert store.get_mission_cost_summary("m")["pre_dispatch_cost_reservations_available"] is False


def test_mission_cost_ledger_rejects_bad_values_and_running_attempt(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "bad-costs.db")
    store.create_mission("m", "controlled")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.1"),
    )))
    claim = store.claim_ready_workflow_task("p", "worker")
    with pytest.raises(ValueError, match="running"):
        store.record_workflow_attempt_cost(
            claim["attempt_id"], cost_microusd=1, source="invoice",
        )
    for bad in (True, -1, 1.5, "5"):
        with pytest.raises(ValueError, match="nonnegative integer"):
            store.record_workflow_attempt_cost(
                claim["attempt_id"], cost_microusd=bad, source="invoice",
            )


def test_workflow_integrity_detects_persisted_plan_and_dag_tampering(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "integrity.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    proof = store.verify_workflow_plan_integrity("p")
    assert proof["valid"] is True
    assert proof["task_count"] == 2
    conn = store._conn()
    try:
        conn.execute(
            "UPDATE workflow_tasks SET target='192.0.2.99' "
            "WHERE plan_id='p' AND task_key='recon'"
        )
    finally:
        conn.close()
    with pytest.raises(ValueError, match="integrity verification failed"):
        store.verify_workflow_plan_integrity("p")
    with pytest.raises(ValueError, match="integrity verification failed"):
        store.claim_ready_workflow_task("p", "worker")
    assert store.list_workflow_attempts("p") == []


def test_workflow_integrity_prevents_postclaim_dispatch_after_tampering(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "dispatch-integrity.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claimed = store.claim_ready_workflow_task("p", "worker")
    conn = store._conn()
    try:
        conn.execute(
            "UPDATE workflow_tasks SET depends_on_json='[]' "
            "WHERE plan_id='p' AND task_key='web'"
        )
    finally:
        conn.close()
    with pytest.raises(ValueError, match="integrity verification failed"):
        store.mark_workflow_dispatch_started("p", claimed["attempt_id"])


def test_workflow_integrity_rejects_mutated_plan_snapshot(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "plan-integrity.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    conn = store._conn()
    try:
        conn.execute(
            "UPDATE workflow_plans SET digest='corrupted' WHERE id='p'"
        )
    finally:
        conn.close()
    with pytest.raises(ValueError, match="integrity verification failed"):
        store.claim_ready_workflow_task("p", "worker")


def test_workflow_integrity_preserves_integer_timeout_digests_across_restart(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "integer-timeout-integrity.db"
    store = JobStore(path)
    store.create_mission("m", "objective")
    plan = WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.1", timeout_s=15),
        WorkflowTask("b", "fixture", "192.0.2.2", timeout_s=30, depends_on=("a",)),
    ))
    assert WorkflowPlan.from_dict(plan.to_dict()).digest == plan.digest
    store.save_workflow_plan("p", plan)
    reopened = JobStore(path)
    assert reopened.verify_workflow_plan_integrity("p")["digest"] == plan.digest
    assert reopened.claim_ready_workflow_task("p", "worker") is not None


def test_workflow_task_rejects_boolean_timeout_and_non_numeric_contract():
    for invalid in (True, False, "10", None, [], {}):
        with pytest.raises(ValueError, match="timeout_s"):
            WorkflowTask("a", "fixture", "192.0.2.1", timeout_s=invalid)


def test_workflow_integrity_rejects_dependency_target_or_capability_tampering(tmp_path):
    from whaxon.core.store import JobStore

    for column, bad in (
        ("capability_id", "unexpected.provider"),
        ("target", "192.0.2.250"),
        ("depends_on_json", '["bad-reference"]'),
        ("permissions_json", '["unapproved.permission"]'),
    ):
        store = JobStore(tmp_path / f"integrity-{column}.db")
        store.create_mission("m", "objective")
        store.save_workflow_plan("p", WorkflowPlan("m", (
            WorkflowTask("a", "fixture", "192.0.2.1"),
            WorkflowTask("b", "fixture", "192.0.2.2", depends_on=("a",)),
        )))
        conn = store._conn()
        try:
            conn.execute(
                f"UPDATE workflow_tasks SET {column}=? WHERE plan_id='p' AND task_key='b'",
                (bad,),
            )
        finally:
            conn.close()
        with pytest.raises(ValueError, match="integrity verification failed"):
            store.claim_ready_workflow_task("p", "worker")
        assert store.count_workflow_task_attempts("p") == {}


def test_heartbeat_cannot_refresh_attempt_that_lost_task_ownership(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "heartbeat-fence.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    assert store.heartbeat_workflow_attempt(claim["attempt_id"]) is True
    conn = store._conn()
    try:
        conn.execute(
            "UPDATE workflow_tasks SET active_attempt_id=NULL WHERE plan_id='p' AND task_key='recon'"
        )
    finally:
        conn.close()
    assert store.heartbeat_workflow_attempt(claim["attempt_id"]) is False


def test_success_after_cancellation_is_recorded_uncertain_atomically(tmp_path):
    from whaxon.core.store import JobStore

    path = tmp_path / "cancel-completion-race.db"
    store = JobStore(path)
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    claim = store.claim_ready_workflow_task("p", "worker")
    assert store.mark_workflow_dispatch_started("p", claim["attempt_id"]) is True
    JobStore(path).request_workflow_cancellation("p")
    assert store.finish_task_attempt(
        claim["attempt_id"], "succeeded", result={"unsafe": "success"},
    ) is True
    reopened = JobStore(path)
    assert reopened.list_workflow_tasks("p")[0]["status"] == "uncertain"
    assert reopened.list_workflow_attempts("p")[0]["status"] == "uncertain"
    assert reopened.list_workflow_events("p")[-1]["event_type"] == "task_uncertain"


@_run_async_test
async def test_provider_failure_after_cancellation_is_uncertain(tmp_path):
    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "cancel-provider-error.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())

    async def dispatch(task):
        store.request_workflow_cancellation("p")
        raise RuntimeError("provider disconnected")

    result = await WorkflowScheduler(
        store, authorize=lambda task: True, dispatch=dispatch,
    ).run("p")
    assert result["tasks"][0]["status"] == "uncertain"
    assert store.list_workflow_attempts("p")[0]["status"] == "uncertain"


@_run_async_test
async def test_scheduler_outcome_reflects_cancellation_winning_finish_race(tmp_path):
    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "cancel-finish-serialized.db")
    store.create_mission("mission-1", "objective")
    store.save_workflow_plan("p", _plan())
    original_finish = store.finish_task_attempt

    def racing_finish(attempt_id, status, result=None, error=""):
        if status == "succeeded":
            JobStore(store.path).request_workflow_cancellation("p")
        return original_finish(attempt_id, status, result=result, error=error)

    store.finish_task_attempt = racing_finish
    result = await WorkflowScheduler(
        store, authorize=lambda task: True,
        dispatch=lambda task: {"ok": True},
    ).run("p")
    assert result["outcomes"][0]["status"] == "uncertain"
    assert result["tasks"][0]["status"] == "uncertain"


def test_mission_control_changes_are_durable_audited_and_idempotent(tmp_path):
    import time

    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    path = tmp_path / "mission-control-audit.db"
    store = JobStore(path)
    store.create_mission("m", "controlled")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.1"),
    )))
    store.set_mission_cost_limit("m", max_cost_microusd=500)
    store.set_mission_execution_limits("m", max_total_attempts=5, max_concurrency=2)
    deadline = time.time() + 300
    store.set_mission_deadline("m", deadline_at=deadline)
    expected = [
        "mission_cost_limit_set", "mission_execution_limits_set", "mission_deadline_set",
    ]
    events = JobStore(path).list_workflow_events("p")
    assert [item["event_type"] for item in events] == expected
    store.set_mission_cost_limit("m", max_cost_microusd=500)
    store.set_mission_execution_limits("m", max_total_attempts=5, max_concurrency=2)
    store.set_mission_deadline("m", deadline_at=deadline)
    assert [e["event_type"] for e in store.list_workflow_events("p")] == expected
    with pytest.raises(ValueError, match="cannot be relaxed"):
        store.set_mission_cost_limit("m", max_cost_microusd=501)
    with pytest.raises(ValueError, match="cannot be relaxed"):
        store.set_mission_execution_limits("m", max_total_attempts=6, max_concurrency=2)
    with pytest.raises(ValueError, match="cannot be extended"):
        store.set_mission_deadline("m", deadline_at=deadline + 10)


def test_attempt_cost_source_is_canonical_for_idempotent_replays(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "normalized-invoice.db")
    store.create_mission("m", "controlled")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.1"),
    )))
    claim = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(claim["attempt_id"], "succeeded")
    store.record_workflow_attempt_cost(
        claim["attempt_id"], cost_microusd=10, source="  provider-invoice  ",
    )
    store.record_workflow_attempt_cost(
        claim["attempt_id"], cost_microusd=10, source="provider-invoice",
    )
    assert len([e for e in store.list_workflow_events("p")
                if e["event_type"] == "cost_recorded"]) == 1


def test_dispatch_rechecks_tightened_mission_budget_after_claim(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "tightened-mission-dispatch.db")
    store.create_mission("m", "controlled")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.1"),
        WorkflowTask("b", "fixture", "192.0.2.2"),
    )))
    first = store.claim_ready_workflow_task("p", "worker-a")
    second = store.claim_ready_workflow_task("p", "worker-b")
    assert first is not None and second is not None
    store.set_mission_execution_limits(
        "m", max_total_attempts=1, max_concurrency=1,
    )
    assert store.mark_workflow_dispatch_started("p", first["attempt_id"]) is False
    assert store.mark_workflow_dispatch_started("p", second["attempt_id"]) is False
    assert not [event for event in store.list_workflow_events("p")
                if event["event_type"] == "dispatch_started"]


def test_dispatch_rechecks_tightened_plan_budget_after_claim(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "tightened-plan-dispatch.db")
    store.create_mission("m", "controlled")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.1"),
        WorkflowTask("b", "fixture", "192.0.2.2"),
    )))
    first = store.claim_ready_workflow_task("p", "worker-a")
    second = store.claim_ready_workflow_task("p", "worker-b")
    assert first is not None and second is not None
    store.set_workflow_limits("p", max_total_attempts=1, max_concurrency=1)
    assert store.mark_workflow_dispatch_started("p", first["attempt_id"]) is False
    assert store.mark_workflow_dispatch_started("p", second["attempt_id"]) is False


def test_dispatch_rechecks_cost_cap_tightening_after_claim(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "tightened-cost-dispatch.db")
    store.create_mission("m", "controlled")
    store.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("a", "fixture", "192.0.2.1"),
    )))
    first = store.claim_ready_workflow_task("p", "worker")
    store.set_mission_cost_limit("m", max_cost_microusd=0)
    assert store.mark_workflow_dispatch_started("p", first["attempt_id"]) is False
    assert not [event for event in store.list_workflow_events("p")
                if event["event_type"] == "dispatch_started"]


def test_mission_rate_limit_serializes_claims_across_plans_and_restart(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    db = tmp_path / "mission-rate.db"
    store = JobStore(db)
    store.create_mission("m", "controlled lab")
    for plan_id, target in (("p1", "192.0.2.10"), ("p2", "192.0.2.11")):
        store.save_workflow_plan(plan_id, WorkflowPlan(
            "m", (WorkflowTask("scan", "fixture", target),),
        ))
    store.set_mission_rate_limit("m", min_spacing_s=3600)
    assert store.claim_ready_workflow_task("p1", "worker-a") is not None
    reopened = JobStore(db)
    assert reopened.claim_ready_workflow_task("p2", "worker-b") is None
    with pytest.raises(ValueError, match="cannot be relaxed"):
        reopened.set_mission_rate_limit("m", min_spacing_s=1)
    reopened.set_mission_rate_limit("m", min_spacing_s=7200)
    assert reopened.claim_ready_workflow_task("p2", "worker-b") is None


def test_mission_rate_limit_rejects_invalid_configuration(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "invalid-rate.db")
    store.create_mission("m", "controlled lab")
    for invalid in (True, False, 0, -1, float("nan"), float("inf"), "1"):
        with pytest.raises(ValueError, match="min_spacing_s"):
            store.set_mission_rate_limit("m", min_spacing_s=invalid)
    with pytest.raises(ValueError, match="unknown mission"):
        store.set_mission_rate_limit("missing", min_spacing_s=1)


def test_mission_rate_limit_cannot_be_bypassed_by_manual_attempt(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "manual-mission-rate.db")
    store.create_mission("m", "controlled lab")
    for plan_id, target in (("p1", "192.0.2.10"), ("p2", "192.0.2.11")):
        store.save_workflow_plan(plan_id, WorkflowPlan(
            "m", (WorkflowTask("scan", "fixture", target),),
        ))
    store.set_mission_rate_limit("m", min_spacing_s=3600)
    assert store.start_task_attempt("a1", "scan", 1, plan_id="p1")
    with pytest.raises(ValueError, match="mission rate budget exhausted"):
        store.start_task_attempt("a2", "scan", 1, plan_id="p2")
    assert store.claim_ready_workflow_task("p2", "worker") is None


@pytest.mark.parametrize("payload, error", [
    (None, "workflow plan must be an object"),
    ({}, "missing required field: mission_id"),
    ({"mission_id": "m"}, "missing required field: tasks"),
    ({"mission_id": 42, "tasks": []}, "mission_id is required"),
    ({"mission_id": "m", "tasks": {}}, "tasks must be an array"),
    ({"mission_id": "m", "tasks": [None]}, "workflow task must be an object"),
    ({"mission_id": "m", "tasks": [{}]}, "missing required field: id"),
    ({"mission_id": "m", "tasks": [{"id": "a", "capability_id": "x", "target": 9}]}, "task id, capability_id and target are required"),
    ({"mission_id": "m", "tasks": [{"id": "a", "capability_id": "x", "target": "host", "inputs": []}]}, "task inputs must be an object"),
    ({"mission_id": "m", "tasks": [{"id": "a", "capability_id": "x", "target": "host", "depends_on": "another"}]}, "dependencies and permissions must be arrays"),
    ({"mission_id": "m", "tasks": [{"id": "a", "capability_id": "x", "target": "host", "permissions": [None]}]}, "dependencies and permissions must be non-empty strings"),
    ({"mission_id": "m", "tasks": [{"id": "a", "capability_id": "x", "target": "host", "idempotency_key": 10}]}, "idempotency_key must be a string"),
    ({"mission_id": "m", "tasks": [{"id": "a", "capability_id": "x", "target": "host"}], "metadata": []}, "plan metadata must be an object"),
])
def test_malformed_workflow_contracts_fail_with_actionable_validation(payload, error):
    with pytest.raises((TypeError, ValueError), match=error):
        WorkflowPlan.from_dict(payload)


def test_malformed_direct_workflow_task_and_plan_construction_fails_closed():
    with pytest.raises(TypeError, match="dependencies and permissions must be arrays"):
        WorkflowTask(id="a", capability_id="x", target="host", permissions="network.scan")
    with pytest.raises(TypeError, match="plan tasks must be an array"):
        WorkflowPlan(mission_id="m", tasks="not a task list")


@_run_async_test
async def test_provider_exception_after_external_effect_is_not_automatically_retried(
    tmp_path,
):
    """An external effect may have happened before an exception was raised."""
    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "provider-unknown-effect.db")
    store.create_mission("mission", "controlled regression")
    store.save_workflow_plan(
        "plan", WorkflowPlan("mission", (
            WorkflowTask("task", "fixture", "192.0.2.10"),
        )),
    )
    external_effects = []

    async def dispatch(_task):
        external_effects.append("effect-started")
        raise RuntimeError("provider lost connection after external operation")

    scheduler = WorkflowScheduler(
        store, authorize=lambda _task: True, dispatch=dispatch,
    )
    first = await scheduler.run("plan", max_tasks=1, max_attempts=5)
    assert first["outcomes"][0]["status"] == "uncertain"
    assert len(external_effects) == 1
    attempts = store.list_workflow_attempts("plan")
    assert len(attempts) == 1
    assert attempts[0]["status"] == "uncertain"
    assert "reconcile before retry" in attempts[0]["error"]

    # Reopening storage or increasing the allowed attempts cannot change the
    # uncertain effect into a new automatically executable task.
    reopened = JobStore(store.path)
    again = await WorkflowScheduler(
        reopened, authorize=lambda _task: True, dispatch=dispatch,
    ).run("plan", max_tasks=5, max_attempts=5)
    assert again["attempts"] == 0
    assert len(external_effects) == 1
    assert reopened.list_workflow_attempts("plan")[0]["status"] == "uncertain"


@_run_async_test
async def test_scheduler_rejects_tampered_plan_after_all_tasks_succeed(tmp_path):
    from whaxon.core.scheduler import WorkflowScheduler
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "scheduler-terminal-integrity.db")
    store.create_mission("m", "terminal plan integrity")
    store.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("t", "cap", "192.0.2.10"),)),
    )
    dispatched = []
    scheduler = WorkflowScheduler(
        store, authorize=lambda task: True,
        dispatch=lambda task: dispatched.append(task.id) or {"ok": True},
    )

    completed = await scheduler.run("p")
    assert completed["complete"] is True
    assert completed["tasks"] == [{"id": "t", "status": "succeeded"}]
    assert dispatched == ["t"]

    conn = store._conn()
    try:
        conn.execute(
            "UPDATE workflow_tasks SET target=? WHERE plan_id=?",
            ("192.0.2.99", "p"),
        )
    finally:
        conn.close()

    with pytest.raises(ValueError, match="integrity"):
        await scheduler.run("p")
    assert dispatched == ["t"]
