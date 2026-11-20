"""E6 cross-client service truth and no-execution parity, independent of UI readiness."""
from __future__ import annotations

import json

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.cli.workflow_cmd import main as workflow_main
from whaxon.interfaces.web.server import AsyncRunner, JobRegistry, create_app


def _scenario(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    monkeypatch.setenv("WHAXON_V2_EXTERNAL_WORKER", "1")
    core = Core(tmp_path)
    core.create_mission("e6-parity", "inert contract validation")
    core.save_workflow_plan(
        "e6-parity-plan",
        WorkflowPlan("e6-parity", (
            WorkflowTask("blocked-fixture", "unsupported.fixture", "192.0.2.10"),
        )),
    )
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    return core, app.test_client()


def _cli_json(tmp_path, capsys, *args, expected_exit=0):
    assert workflow_main(["--data-dir", str(tmp_path), *args]) == expected_exit
    return json.loads(capsys.readouterr().out)


def test_e6_api_cli_reconnect_and_cancel_share_durable_identity(
    tmp_path, monkeypatch, capsys,
):
    core, client = _scenario(tmp_path, monkeypatch)
    submitted = client.post("/api/v2/workflows/e6-parity-plan/run", json={})
    assert submitted.status_code == 202
    accepted = submitted.get_json()
    assert accepted["execution_completed"] is False
    request_id = accepted["run_request_id"]

    cli_snapshot = _cli_json(
        tmp_path, capsys, "plan", "run-snapshot", "--id", request_id,
    )
    api_snapshot = client.get(accepted["run_snapshot_url"]).get_json()
    assert cli_snapshot == api_snapshot
    assert cli_snapshot["request"]["status"] == "queued"
    assert cli_snapshot["worker_liveness_verified"] is False
    assert cli_snapshot["automatic_uncertain_replay"] is False

    cli_progress = _cli_json(
        tmp_path, capsys, "plan", "progress", "--id", "e6-parity-plan",
    )
    assert cli_progress == client.get(
        "/api/v2/workflows/e6-parity-plan/progress",
    ).get_json()
    assert core.workflow_run_request(request_id)["status"] == "queued"

    cancelled = _cli_json(
        tmp_path, capsys, "plan", "cancel-request", "--id", request_id,
    )
    assert cancelled["cancellation_requested"] is True
    assert cancelled["external_effects_stopped"] is False
    assert client.get(accepted["run_request_url"]).get_json()["status"] == "cancelled"
    assert core.workflow_requests.claim("e6-forbidden-worker") is None

    after = client.get(accepted["run_snapshot_url"]).get_json()
    assert after["request"]["status"] == "cancelled"
    assert after["progress"]["cancellation_requested"] is True
    assert after["worker_liveness_verified"] is False


def test_e6_unexecuted_evidence_and_readiness_match_api_cli(
    tmp_path, monkeypatch, capsys,
):
    _core, client = _scenario(tmp_path, monkeypatch)
    api_evidence = client.get("/api/v2/workflows/e6-parity-plan/evidence")
    assert api_evidence.status_code == 200
    cli_evidence = _cli_json(
        tmp_path, capsys, "plan", "evidence", "--id", "e6-parity-plan",
    )
    assert cli_evidence == api_evidence.get_json()
    assert cli_evidence["all_evidence_recorded"] is False
    assert cli_evidence["attempts"] == []

    cli_readiness = _cli_json(
        tmp_path, capsys, "plan", "readiness", "--id", "e6-parity-plan",
        expected_exit=1,
    )
    api_readiness = client.get(
        "/api/v2/workflows/e6-parity-plan/readiness",
    )
    assert api_readiness.status_code == 200
    assert api_readiness.get_json() == cli_readiness
    assert cli_readiness["ready_to_report_success"] is False


def test_e6_request_cancellation_refuses_cross_origin_and_unknown_id(
    tmp_path, monkeypatch, capsys,
):
    core, client = _scenario(tmp_path, monkeypatch)
    submitted = client.post("/api/v2/workflows/e6-parity-plan/run", json={})
    assert submitted.status_code == 202
    request_id = submitted.get_json()["run_request_id"]
    forbidden = client.post(
        f"/api/v2/workflow-runs/{request_id}/cancel",
        headers={"Origin": "https://attacker.invalid"},
    )
    assert forbidden.status_code == 403
    assert core.workflow_run_request(request_id)["status"] == "queued"
    assert client.post(
        "/api/v2/workflow-runs/unknown-request/cancel",
    ).status_code == 404
    assert workflow_main([
        "--data-dir", str(tmp_path), "plan", "cancel-request",
        "--id", "unknown-request",
    ]) == 1
    assert "unknown workflow run request" in capsys.readouterr().err
    assert core.workflow_run_request(request_id)["status"] == "queued"
