"""E3 adversarial queue/attempt durability: cancellation and audit atomicity."""
from __future__ import annotations

import time

import pytest

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _running(tmp_path):
    core = Core(tmp_path)
    core.create_mission("mission", "E3 durable audit regression")
    core.save_workflow_plan(
        "plan", WorkflowPlan("mission", (
            WorkflowTask("task", "fixture", "192.0.2.10"),
        )),
    )
    req = core.enqueue_workflow_run("plan")
    claim = core.workflow_requests.claim("worker")
    assert claim is not None
    return core, req, claim


def _block_audit(core):
    conn = core.store._conn()
    try:
        conn.execute(
            "CREATE TRIGGER deny_uncertain_audit BEFORE INSERT ON workflow_events "
            "WHEN NEW.event_type='workflow_run_uncertain' "
            "BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END"
        )
    finally:
        conn.close()


@pytest.mark.parametrize("outcome", ["completed", "incomplete", "failed", "uncertain"])
def test_run_completion_after_plan_cancellation_is_uncertain(tmp_path, outcome):
    core, request, claim = _running(tmp_path)
    core.cancel_workflow_plan("plan")
    assert core.workflow_requests.finish(
        request["id"], claim["lease_token"], status=outcome,
    )
    public = core.workflow_run_request(request["id"])
    assert public["status"] == "uncertain"
    assert "cancelled" in public["error"]
    assert "lease_token" not in public
    assert not core.workflow_requests.finish(
        request["id"], claim["lease_token"], status="completed",
    )
    events = [
        e for e in core.store.list_workflow_events("plan")
        if e["event_type"] == "workflow_run_uncertain"
    ]
    assert len(events) == 1
    assert events[0]["detail"]["reason"] == "plan_cancelled_during_run"


def test_audit_insert_failure_rolls_back_cancelled_run_completion(tmp_path):
    core, request, claim = _running(tmp_path)
    core.cancel_workflow_plan("plan")
    _block_audit(core)
    with pytest.raises(Exception, match="audit unavailable"):
        core.workflow_requests.finish(
            request["id"], claim["lease_token"], status="completed",
        )
    still_running = core.workflow_run_request(request["id"])
    assert still_running["status"] == "running"
    assert still_running["completed_at"] is None
    assert core.workflow_requests.heartbeat(request["id"], claim["lease_token"])


def test_audit_insert_failure_rolls_back_stale_run_reconciliation(tmp_path):
    core, request, claim = _running(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=? WHERE id=?",
            (time.time() - 1000, request["id"]),
        )
    finally:
        conn.close()
    _block_audit(core)
    with pytest.raises(Exception, match="audit unavailable"):
        core.workflow_requests.reconcile_stale(older_than_s=60)
    assert core.workflow_run_request(request["id"])["status"] == "running"
    assert core.workflow_requests.heartbeat(request["id"], claim["lease_token"])


def test_missing_source_plan_refuses_successful_run_completion(tmp_path):
    core, request, claim = _running(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET plan_id=? WHERE id=?",
            ("missing-plan", request["id"]),
        )
    finally:
        conn.close()
    assert core.workflow_requests.finish(
        request["id"], claim["lease_token"], status="completed",
    )
    public = core.workflow_run_request(request["id"])
    assert public["status"] == "uncertain"
    assert "source plan missing" in public["error"]
    assert "lease_token" not in public


def test_audit_insert_failure_rolls_back_claim_time_digest_quarantine(tmp_path):
    core = Core(tmp_path)
    core.create_mission("m", "E3 digest fail-closed audit")
    core.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("t", "fixture", "192.0.2.11"),)),
    )
    request = core.enqueue_workflow_run("p")
    conn = core.store._conn()
    try:
        conn.execute("UPDATE workflow_run_requests SET plan_digest=? WHERE id=?",
                     ("stale-digest", request["id"]))
    finally:
        conn.close()
    _block_audit(core)
    with pytest.raises(Exception, match="audit unavailable"):
        core.workflow_requests.claim("new-worker")
    assert core.workflow_run_request(request["id"])["status"] == "queued"


def test_stale_task_recovery_audit_failure_never_partially_updates_task(tmp_path):
    core = Core(tmp_path)
    core.create_mission("m", "E3 attempt audit rollback")
    core.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("t", "fixture", "192.0.2.10"),)),
    )
    attempt = core.store.claim_ready_workflow_task("p", "worker")
    assert attempt is not None
    conn = core.store._conn()
    try:
        conn.execute("CREATE TRIGGER deny_task_audit BEFORE INSERT ON workflow_events "
                     "WHEN NEW.event_type='task_uncertain' "
                     "BEGIN SELECT RAISE(ABORT, 'task audit unavailable'); END")
        conn.execute("UPDATE task_attempts SET heartbeat_at=? WHERE id=?",
                     (time.time() - 1000, attempt["attempt_id"]))
    finally:
        conn.close()
    with pytest.raises(Exception, match="task audit unavailable"):
        core.store.reconcile_workflow_attempts(stale_after_s=60)
    assert core.store.workflow_attempt_owned(attempt["attempt_id"])
    assert core.store.get_workflow_attempt_status(attempt["attempt_id"]) == "running"
