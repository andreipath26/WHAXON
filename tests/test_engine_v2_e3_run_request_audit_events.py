"""E3 durable audit events for run requests with uncertain external outcomes."""
import json
import time

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _core(tmp_path):
    core = Core(tmp_path)
    core.create_mission("mission", "auditable synthetic run request")
    core.save_workflow_plan(
        "plan", WorkflowPlan("mission", (
            WorkflowTask("task", "unsupported.fixture", "192.0.2.10"),
        )),
    )
    return core


def _uncertain_events(core):
    return [
        item for item in core.store.list_workflow_events("plan")
        if item["event_type"] == "workflow_run_uncertain"
    ]


def test_e3_changed_plan_digest_creates_exactly_one_durable_audit_event(tmp_path):
    core = _core(tmp_path)
    request = core.enqueue_workflow_run("plan")
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET plan_digest=? WHERE id=?",
            ("tampered", request["id"]),
        )
    finally:
        conn.close()
    reopened = Core(tmp_path)
    assert reopened.workflow_requests.claim("worker") is None
    assert reopened.workflow_run_request(request["id"])["status"] == "uncertain"
    assert reopened.workflow_requests.claim("other") is None
    events = _uncertain_events(Core(tmp_path))
    assert len(events) == 1
    assert events[0]["detail"] == {
        "request_id": request["id"], "reason": "plan_digest_changed",
    }


def test_e3_stale_worker_recovery_audits_uncertainty_and_fences_old_token(tmp_path):
    core = _core(tmp_path)
    request = core.enqueue_workflow_run("plan")
    claim = core.workflow_requests.claim("worker-with-private-token")
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=? WHERE id=?",
            (time.time() - 1000, request["id"]),
        )
    finally:
        conn.close()
    reopened = Core(tmp_path)
    assert reopened.workflow_requests.reconcile_stale(older_than_s=60) == 1
    assert reopened.workflow_requests.reconcile_stale(older_than_s=60) == 0
    assert core.workflow_requests.heartbeat(request["id"], claim["lease_token"]) is False
    events = _uncertain_events(reopened)
    assert len(events) == 1
    assert events[0]["detail"] == {
        "request_id": request["id"], "reason": "worker_lease_lost",
    }
    assert claim["lease_token"] not in json.dumps(events)
    assert "worker-with-private-token" not in json.dumps(events)
    assert reopened.workflow_run_request(request["id"])["status"] == "uncertain"


def test_e3_healthy_worker_does_not_emit_uncertain_audit_event(tmp_path):
    core = _core(tmp_path)
    request = core.enqueue_workflow_run("plan")
    claim = core.workflow_requests.claim("healthy-worker")
    assert claim["id"] == request["id"]
    assert core.workflow_requests.reconcile_stale(older_than_s=60) == 0
    assert _uncertain_events(core) == []
    assert core.workflow_run_request(request["id"])["status"] == "running"
