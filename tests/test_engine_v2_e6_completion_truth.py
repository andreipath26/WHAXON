"""E6 refuses to report successful assessment when only request processing finishes.

Synthetic blocked capability; no scanner, external target, or browser.
"""
from __future__ import annotations

import asyncio

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.web.server import AsyncRunner, JobRegistry, create_app


def test_e6_completed_queue_request_does_not_mean_verified_workflow(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    monkeypatch.setenv("WHAXON_V2_EXTERNAL_WORKER", "1")
    core = Core(tmp_path)
    core.create_mission("e6-truth", "inert blocked-completion acceptance")
    core.save_workflow_plan(
        "e6-truth-plan",
        WorkflowPlan("e6-truth", (
            WorkflowTask("cannot-run", "unsupported.fixture", "192.0.2.10"),
        )),
    )

    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    client = app.test_client()
    accepted = client.post("/api/v2/workflows/e6-truth-plan/run", json={})
    assert accepted.status_code == 202
    request_id = accepted.get_json()["run_request_id"]
    assert core.workflow_run_request(request_id)["status"] == "queued"

    # Dedicated worker makes a bounded attempt; unsupported fixture blocks
    # without making any network request or implying verified findings.
    assert asyncio.run(core.drain_workflow_run_requests()) == 1

    # Reconnected web client reads durable state only.
    fresh = Core(tmp_path)
    next_app = create_app(fresh, JobRegistry(fresh), AsyncRunner(fresh))
    next_app.config["TESTING"] = True
    reconnected = next_app.test_client()
    request_state = reconnected.get(
        f"/api/v2/workflow-runs/{request_id}",
    ).get_json()
    progress = reconnected.get(
        "/api/v2/workflows/e6-truth-plan/progress",
    ).get_json()
    readiness = reconnected.get(
        "/api/v2/workflows/e6-truth-plan/readiness",
    ).get_json()
    snapshot = reconnected.get(
        f"/api/v2/workflow-runs/{request_id}/snapshot",
    ).get_json()

    assert request_state["status"] == "completed"
    assert progress["counts"]["blocked"] == 1
    assert readiness["ready_to_report_success"] is False
    assert snapshot["request"]["status"] == "completed"
    assert snapshot["worker_liveness_verified"] is False
    assert snapshot["automatic_uncertain_replay"] is False
