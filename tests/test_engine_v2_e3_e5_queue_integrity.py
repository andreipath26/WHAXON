"""E3/E5 durable execution limits: reject corrupt persisted queues before claim."""
import pytest

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _two_requests(tmp_path):
    core = Core(tmp_path)
    core.create_mission("m", "durable queue acceptance")
    for index in (1, 2):
        core.save_workflow_plan(
            f"plan-{index}",
            WorkflowPlan("m", (WorkflowTask(
                f"task-{index}", "fixture", f"192.0.2.{index}",
            ),)),
        )
    old = core.enqueue_workflow_run("plan-1")
    valid = core.enqueue_workflow_run("plan-2")
    return core, old, valid


@pytest.mark.parametrize("corrupt", (
    "not-json", "null", "[]", "{}",
    '{"max_tasks":true,"max_attempts":2,"max_concurrency":4}',
    '{"max_tasks":0,"max_attempts":2,"max_concurrency":4}',
    '{"max_tasks":1,"max_attempts":2,"max_concurrency":4,"extra":1}',
))
def test_bad_stored_limits_cannot_claim_or_starve_valid_work(tmp_path, corrupt):
    core, bad, good = _two_requests(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET limits_json=?,submitted_at=1 "
            "WHERE id=?", (corrupt, bad["id"]),
        )
    finally:
        conn.close()

    restarted = Core(tmp_path)
    observed = restarted.workflow_run_request(bad["id"])
    assert observed["limits"] is None
    assert observed["limits_integrity"] == "invalid"
    assert "lease_token" not in observed
    with pytest.raises(ValueError, match="invalid persisted limits"):
        restarted.enqueue_workflow_run("plan-1")

    claimed = restarted.workflow_requests.claim("worker")
    assert claimed is not None and claimed["id"] == good["id"]
    assert claimed["limits_integrity"] == "valid"
    status = restarted.workflow_run_request(bad["id"])
    assert status["status"] == "uncertain"
    assert status["error"] == "invalid persisted execution limits"
    assert status["completed_at"] is not None
    assert restarted.workflow_requests.claim("second") is None
    events = [
        item for item in restarted.store.list_workflow_events("plan-1")
        if item["event_type"] == "workflow_run_uncertain"
    ]
    assert len(events) == 1
    assert events[0]["detail"] == {
        "request_id": bad["id"], "reason": "invalid_execution_limits",
    }


def test_valid_stored_limits_preserve_durable_worker_fencing(tmp_path):
    core, old, _ = _two_requests(tmp_path)
    claim = core.workflow_requests.claim("worker")
    assert claim is not None and claim["id"] == old["id"]
    assert claim["limits"] == {
        "max_tasks": 100, "max_attempts": 2, "max_concurrency": 4,
    }
    assert claim["limits_integrity"] == "valid"
    assert "lease_token" in claim
    public = core.workflow_run_request(old["id"])
    assert public["limits_integrity"] == "valid"
    assert "lease_token" not in public
