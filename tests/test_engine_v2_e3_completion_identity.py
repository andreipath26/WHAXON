"""Engine V2 E3: completion cannot rebind to changed plan identity."""
from __future__ import annotations

import pytest

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _queue(tmp_path):
    core = Core(tmp_path)
    core.create_mission("m", "E3 completion evidence")
    core.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("t", "fixture", "192.0.2.10"),)),
    )
    request = core.enqueue_workflow_run("p")
    claim = core.workflow_requests.claim("worker")
    assert claim and claim["id"] == request["id"]
    return core, request, claim


def _events(core):
    return [
        e for e in core.store.list_workflow_events("p")
        if e["event_type"] == "workflow_run_uncertain"
    ]


@pytest.mark.parametrize("outcome", ["completed", "incomplete", "failed", "uncertain"])
def test_changed_plan_digest_refuses_clean_run_completion(tmp_path, outcome):
    core, request, claim = _queue(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_plans SET digest=? WHERE id=?",
            ("new-persisted-plan-digest", "p"),
        )
    finally:
        conn.close()
    assert core.workflow_requests.finish(
        request["id"], claim["lease_token"], status=outcome,
    )
    observed = core.workflow_run_request(request["id"])
    assert observed["status"] == "uncertain"
    assert observed["plan_digest"] == request["plan_digest"]
    assert "digest changed" in observed["error"]
    assert "lease_token" not in observed
    assert [e["detail"]["reason"] for e in _events(core)] == [
        "plan_digest_changed_during_run"
    ]
    assert not core.workflow_requests.finish(
        request["id"], claim["lease_token"], status="completed",
    )


def test_worker_reported_uncertain_has_one_durable_audit_event(tmp_path):
    core, request, claim = _queue(tmp_path)
    assert core.workflow_requests.finish(
        request["id"], claim["lease_token"],
        status="uncertain", error="provider outcome could not be verified",
    )
    assert core.workflow_run_request(request["id"])["status"] == "uncertain"
    assert [e["detail"]["reason"] for e in _events(core)] == [
        "worker_reported_uncertain"
    ]
    assert not core.workflow_requests.finish(
        request["id"], claim["lease_token"], status="uncertain",
    )
    assert len(_events(core)) == 1


def test_audit_failure_does_not_partially_accept_worker_uncertainty(tmp_path):
    core, request, claim = _queue(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "CREATE TRIGGER deny_uncertainty_audit BEFORE INSERT ON workflow_events "
            "WHEN NEW.event_type='workflow_run_uncertain' "
            "BEGIN SELECT RAISE(ABORT, 'audit store failed'); END"
        )
    finally:
        conn.close()
    with pytest.raises(Exception, match="audit store failed"):
        core.workflow_requests.finish(
            request["id"], claim["lease_token"], status="uncertain",
        )
    row = core.workflow_run_request(request["id"])
    assert row["status"] == "running"
    assert row["completed_at"] is None
    assert core.workflow_requests.heartbeat(request["id"], claim["lease_token"])



def test_tampered_plan_downgrades_inflight_success_to_uncertain(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "completion-plan-integrity.db")
    store.create_mission("m", "completion integrity")
    store.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("t", "fixture", "192.0.2.10"),)),
    )
    attempt = store.claim_ready_workflow_task("p", "worker", max_attempts=1)
    assert attempt is not None
    attempt_id = attempt["attempt_id"]
    assert store.mark_workflow_dispatch_started("p", attempt_id)

    conn = store._conn()
    try:
        conn.execute(
            "UPDATE workflow_tasks SET target=? WHERE plan_id=?",
            ("192.0.2.99", "p"),
        )
    finally:
        conn.close()

    store.finish_task_attempt(
        attempt_id, "succeeded", result={"job_id": "must-not-seal"},
    )

    assert store.get_workflow_attempt_status(attempt_id) == "uncertain"
    tasks = store.list_workflow_tasks("p")
    assert tasks[0]["status"] == "uncertain"
    assert tasks[0]["result"] is None
    assert "integrity failed" in tasks[0]["error"]
    conn = store._conn()
    try:
        seal_count = conn.execute(
            "SELECT COUNT(*) FROM workflow_evidence_seals WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()[0]
    finally:
        conn.close()
    assert seal_count == 0
