"""E6 contract-first preflight while the supplied V2 UI remains unfinished.

The API must expose durable truthful state without browser-owned execution.
No scanner, target or browser is needed for these negative-contract checks.
"""
from __future__ import annotations

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.web.server import AsyncRunner, JobRegistry, create_app


def test_e6_unfinished_ui_can_reconnect_without_claiming_execution(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    monkeypatch.setenv("WHAXON_V2_EXTERNAL_WORKER", "1")
    core = Core(tmp_path)
    core.create_mission("e6-mission", "inert E6 preflight")
    core.save_workflow_plan(
        "e6-plan",
        WorkflowPlan("e6-mission", (
            WorkflowTask("inert", "unsupported.fixture", "192.0.2.10"),
        )),
    )

    def forbidden_submit(*_args, **_kwargs):
        raise AssertionError("E6 web client must never own the V2 worker")

    monkeypatch.setattr(AsyncRunner, "submit", forbidden_submit)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    response = app.test_client().post("/api/v2/workflows/e6-plan/run", json={})
    assert response.status_code == 202
    accepted = response.get_json()
    assert accepted["execution_completed"] is False
    request_id = accepted["run_request_id"]

    # Recreate Core and Flask app just as a browser reconnecting to another
    # web process would. The worker remains independently supervised.
    restarted = Core(tmp_path)
    next_app = create_app(restarted, JobRegistry(restarted), AsyncRunner(restarted))
    next_app.config["TESTING"] = True
    client = next_app.test_client()

    status = client.get(accepted["run_request_url"])
    assert status.status_code == 200
    assert status.get_json()["id"] == request_id
    assert status.get_json()["status"] == "queued"
    assert "lease_token" not in status.get_json()

    snapshot = client.get(accepted["run_snapshot_url"])
    assert snapshot.status_code == 200
    snapshot_body = snapshot.get_json()
    assert snapshot_body["worker_liveness_verified"] is False
    assert snapshot_body["automatic_uncertain_replay"] is False
    assert "lease_token" not in str(snapshot_body)

    summary = client.get("/api/v2/workflow-runs/summary").get_json()
    assert summary["counts"]["queued"] == 1
    assert summary["worker_liveness_verified"] is False
    assert summary["automatic_uncertain_replay"] is False

    readiness = client.get("/api/v2/workflows/e6-plan/readiness")
    assert readiness.status_code == 200
    assert readiness.get_json()["ready_to_report_success"] is False
    assert client.get("/api/v2/workflow-runs/not-a-request/snapshot").status_code == 404
    assert client.get("/api/v2/workflow-runs/not-a-request").status_code == 404
    assert restarted.workflow_run_request(request_id)["status"] == "queued"
