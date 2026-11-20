"""Private run-queue lease credentials never cross client-facing interfaces."""
from __future__ import annotations

import json

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.web.server import AsyncRunner, JobRegistry, create_app


def _core(tmp_path):
    core = Core(tmp_path)
    core.create_mission("mission", "lease-credential privacy regression")
    core.save_workflow_plan(
        "plan",
        WorkflowPlan("mission", (
            WorkflowTask("task", "unsupported.fixture", "192.0.2.10"),
        )),
    )
    return core


def test_e1_enqueued_and_duplicate_queued_records_never_have_worker_token(tmp_path):
    core = _core(tmp_path)
    initial = core.enqueue_workflow_run("plan")
    duplicate = Core(tmp_path).enqueue_workflow_run("plan")
    assert initial["id"] == duplicate["id"]
    assert "lease_token" not in initial
    assert "lease_token" not in duplicate
    assert "lease_token" not in core.workflow_run_request(initial["id"])


def test_e1_duplicate_running_enqueue_does_not_expose_active_fencing_token(tmp_path):
    core = _core(tmp_path)
    queued = core.enqueue_workflow_run("plan")
    worker_claim = Core(tmp_path).workflow_requests.claim("private-worker")
    assert worker_claim["id"] == queued["id"]
    assert isinstance(worker_claim["lease_token"], str)
    assert worker_claim["lease_token"]

    another_client = Core(tmp_path)
    duplicate = another_client.enqueue_workflow_run("plan")
    assert duplicate["status"] == "running"
    assert duplicate["id"] == worker_claim["id"]
    assert "lease_token" not in duplicate
    assert "lease_token" not in another_client.workflow_run_request(queued["id"])
    assert worker_claim["lease_token"] not in json.dumps(duplicate)

    # Worker fencing must remain intact despite public redaction.
    assert core.workflow_requests.heartbeat(
        queued["id"], worker_claim["lease_token"],
    )
    assert not core.workflow_requests.finish(
        queued["id"], "untrusted-token", status="completed",
    )
    assert core.workflow_requests.finish(
        queued["id"], worker_claim["lease_token"], status="completed",
    )


def test_e1_uncertain_request_duplicate_keeps_token_private(tmp_path):
    core = _core(tmp_path)
    queued = core.enqueue_workflow_run("plan")
    worker_claim = core.workflow_requests.claim("worker")
    assert core.workflow_requests.finish(
        queued["id"], worker_claim["lease_token"], status="uncertain",
    )
    duplicate = Core(tmp_path).enqueue_workflow_run("plan")
    assert duplicate["id"] == queued["id"]
    assert duplicate["status"] == "uncertain"
    assert "lease_token" not in duplicate


def test_e1_public_core_api_paths_do_not_publish_lease_token(tmp_path, monkeypatch):
    core = _core(tmp_path)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    client = app.test_client()
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, callback: None)
    queued = core.enqueue_workflow_run("plan")
    claim = core.workflow_requests.claim("worker")
    assert claim["lease_token"]
    resubmit = client.post("/api/v2/workflows/plan/run", json={
        "max_tasks": 100, "max_attempts": 2, "max_concurrency": 4,
    })
    assert resubmit.status_code == 202
    payload = resubmit.get_json()
    assert payload["run_request_id"] == queued["id"]
    assert claim["lease_token"] not in resubmit.get_data(as_text=True)
    detail = client.get(f"/api/v2/workflow-runs/{queued['id']}")
    assert detail.status_code == 200
    assert "lease_token" not in detail.get_json()
    assert claim["lease_token"] not in detail.get_data(as_text=True)
