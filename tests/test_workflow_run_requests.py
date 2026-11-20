"""Durable Engine V2 workflow-run request acceptance and restart behavior."""
from __future__ import annotations

import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.cli import workflow_cmd
from whaxon.interfaces.web.server import AsyncRunner, JobRegistry, create_app, create_app_factory


def _core(tmp_path):
    core = Core(tmp_path)
    core.create_mission("m", "authorized controlled workflow")
    core.save_workflow_plan("p", WorkflowPlan(
        "m", (WorkflowTask("recon", "fixture", "192.0.2.10"),),
    ))
    return core


def test_run_request_survives_core_restart_and_deduplicates(tmp_path):
    first = _core(tmp_path)
    limits = {"max_tasks": 3, "max_attempts": 2, "max_concurrency": 1}
    queued = first.workflow_requests.enqueue("p", limits=limits)
    same = first.workflow_requests.enqueue("p", limits=limits)
    assert queued["id"] == same["id"]
    with pytest.raises(ValueError, match="different limits"):
        first.workflow_requests.enqueue(
            "p", limits={**limits, "max_concurrency": 2},
        )
    second = Core(tmp_path)
    from_disk = second.workflow_run_request(queued["id"])
    assert from_disk["status"] == "queued"
    assert from_disk["plan_digest"] == queued["plan_digest"]
    assert from_disk["limits"] == limits


def test_run_request_uses_atomic_claim_and_lease_fencing(tmp_path):
    first = _core(tmp_path)
    row = first.enqueue_workflow_run("p")
    second = Core(tmp_path)
    claim = second.workflow_requests.claim("worker-a")
    assert claim["id"] == row["id"]
    assert first.workflow_requests.claim("worker-b") is None
    assert not first.workflow_requests.heartbeat(row["id"], "wrong-token")
    assert not first.workflow_requests.finish(
        row["id"], "wrong-token", status="completed",
    )
    assert second.workflow_requests.heartbeat(row["id"], claim["lease_token"])
    assert second.workflow_requests.finish(
        row["id"], claim["lease_token"], status="completed",
    )
    assert first.workflow_run_request(row["id"])["status"] == "completed"


def test_stale_run_is_uncertain_not_automatically_replayed(tmp_path):
    core = _core(tmp_path)
    request = core.enqueue_workflow_run("p")
    claimed = core.workflow_requests.claim("worker")
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=? WHERE id=?",
            (time.time() - 1000, request["id"]),
        )
    finally:
        conn.close()
    assert core.workflow_requests.reconcile_stale(older_than_s=60) == 1
    assert core.workflow_run_request(request["id"])["status"] == "uncertain"
    assert core.workflow_requests.claim("other") is None
    assert not core.workflow_requests.finish(
        request["id"], claimed["lease_token"], status="completed",
    )
    with pytest.raises(ValueError, match="different limits"):
        core.enqueue_workflow_run(
            "p", max_tasks=1, max_attempts=2, max_concurrency=4,
        )


def test_drain_queued_work_after_restart_without_unsafe_reexecution(tmp_path):
    first = _core(tmp_path)
    request = first.enqueue_workflow_run("p")
    second = Core(tmp_path)
    # The fixture capability cannot execute: policy must block it, rather
    # than using an unverified binary or another execution path.
    with ThreadPoolExecutor(max_workers=1) as executor:
        assert executor.submit(
            lambda: asyncio.run(second.drain_workflow_run_requests()),
        ).result() == 1
    row = first.workflow_run_request(request["id"])
    assert row["status"] == "completed"
    assert first.workflow_progress("p")["counts"]["blocked"] == 1
    with ThreadPoolExecutor(max_workers=1) as executor:
        assert executor.submit(
            lambda: asyncio.run(second.drain_workflow_run_requests()),
        ).result() == 0


def test_e5_cli_and_api_submit_same_bounded_durable_intent(
    tmp_path, monkeypatch, capsys,
):
    original = _core(tmp_path)
    args = [
        "--data-dir", str(tmp_path), "plan", "submit-run",
        "--id", "p", "--max-tasks", "3",
        "--max-attempts", "2", "--max-concurrency", "1",
    ]
    assert workflow_cmd.main(args) == 0
    submitted = json.loads(capsys.readouterr().out)
    request_id = submitted["run_request_id"]
    assert submitted["execution_completed"] is False
    assert submitted["request_status"] == "queued"
    assert original.workflow_run_request(request_id)["status"] == "queued"
    assert workflow_cmd.main(args) == 0
    assert json.loads(capsys.readouterr().out)["run_request_id"] == request_id

    monkeypatch.setattr(AsyncRunner, "submit", lambda self, callback: None)
    web_core = Core(tmp_path)
    app = create_app(web_core, JobRegistry(web_core), AsyncRunner(web_core))
    app.config["TESTING"] = True
    response = app.test_client().post("/api/v2/workflows/p/run", json={
        "max_tasks": 3, "max_attempts": 2, "max_concurrency": 1,
    })
    assert response.status_code == 202
    assert response.get_json()["run_request_id"] == request_id
    assert workflow_cmd.main([*args[:-1], "2"]) == 2
    assert "different limits" in capsys.readouterr().err


def test_api_202_is_persisted_before_worker_wakeup(tmp_path, monkeypatch):
    monkeypatch.delenv("WHAXON_V2_EXTERNAL_WORKER", raising=False)
    core = _core(tmp_path)
    recorded = []
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, callback: recorded.append(callback))
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    client = app.test_client()
    result = client.post("/api/v2/workflows/p/run", json={
        "max_tasks": 2, "max_attempts": 2, "max_concurrency": 1,
    })
    assert result.status_code == 202
    payload = result.get_json()
    request_id = payload["run_request_id"]
    assert payload["execution_completed"] is False
    assert len(recorded) == 1
    assert core.workflow_run_request(request_id)["status"] == "queued"
    assert client.get(payload["run_request_url"]).get_json()["id"] == request_id
    again = client.post("/api/v2/workflows/p/run", json={
        "max_tasks": 2, "max_attempts": 2, "max_concurrency": 1,
    })
    assert again.get_json()["run_request_id"] == request_id
    assert client.get("/api/v2/workflow-runs/missing").status_code == 404
    assert client.post("/api/v2/workflows/missing/run").status_code == 404
    assert client.post("/api/v2/workflows/p/run", json={
        "max_tasks": 0,
    }).status_code == 400
    assert client.post("/api/v2/workflows/p/run", json={
        "max_tasks": True,
    }).status_code == 400


def test_e5_external_worker_mode_never_starts_web_drain(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_V2_EXTERNAL_WORKER", "1")
    core = _core(tmp_path)

    def unexpectedly_submitted(*_args, **_kwargs):
        raise AssertionError("web must not start a second E5 worker")

    monkeypatch.setattr(AsyncRunner, "submit", unexpectedly_submitted)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    response = app.test_client().post("/api/v2/workflows/p/run", json={})
    assert response.status_code == 202
    body = response.get_json()
    assert body["execution_completed"] is False
    assert core.workflow_run_request(body["run_request_id"])["status"] == "queued"
    # A distinct Core has permission to claim the persisted intent.
    separate = Core(tmp_path)
    claimed = separate.workflow_requests.claim("dedicated-worker")
    assert claimed is not None and claimed["id"] == body["run_request_id"]
    assert "lease_token" not in body


def test_e5_external_worker_mode_prevents_factory_startup_local_drain(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_V2_EXTERNAL_WORKER", "1")
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    monkeypatch.setenv("WHAXON_HOST", "127.0.0.1")
    monkeypatch.setenv("WHAXON_AUTH_USER", "whaxon")
    monkeypatch.setenv("WHAXON_AUTH_PASS", "whaxon")
    monkeypatch.delenv("WHAXON_AUTH_PASS_HASH", raising=False)
    called = []

    def unexpected_drain(*_args, **_kwargs):
        called.append(True)
        raise AssertionError("dedicated worker must own durable V2 queue")

    monkeypatch.setattr(AsyncRunner, "submit", unexpected_drain)
    app = create_app_factory()
    app.config["TESTING"] = True
    assert not called
    response = app.test_client().get("/api/health")
    assert response.status_code == 503
    assert response.get_json()["checks"]["v2_worker"] == "unavailable"
    assert not called


def test_cancelled_workflow_cannot_be_newly_submitted(tmp_path):
    core = _core(tmp_path)
    core.cancel_workflow_plan("p")
    with pytest.raises(ValueError, match="cancelled"):
        core.enqueue_workflow_run("p")

def test_cancel_closes_queued_run_request_without_executing(tmp_path):
    core = _core(tmp_path)
    request = core.enqueue_workflow_run("p")
    core.cancel_workflow_plan("p")
    assert core.workflow_run_request(request["id"])["status"] == "cancelled"
    assert core.workflow_requests.claim("worker") is None
    assert core.workflow_progress("p")["cancellation_requested"] is True



def test_e4_blocked_execution_never_enters_followup_planner(tmp_path, monkeypatch):
    """Review-only E4 planning must not poison E3 request completion."""
    core = _core(tmp_path)
    request = core.enqueue_workflow_run("p")

    def forbidden(_plan_id):
        raise AssertionError("blocked tasks cannot produce follow-up proposals")

    monkeypatch.setattr(core, "propose_workflow_followups", forbidden)
    with ThreadPoolExecutor(max_workers=1) as executor:
        assert executor.submit(
            lambda: asyncio.run(core.drain_workflow_run_requests()),
        ).result(timeout=15) == 1
    assert core.workflow_run_request(request["id"])["status"] == "completed"
    assert core.workflow_progress("p")["counts"]["blocked"] == 1


def test_e4_secondary_planner_error_preserves_successful_scheduler_result(
    tmp_path, monkeypatch,
):
    """An optional follow-up fault cannot change a completed source effect."""
    core = _core(tmp_path)

    class StubScheduler:
        async def run(self, *_args, **_kwargs):
            return {
                "plan_id": "p", "attempts": 1,
                "complete": True,
                "tasks": [{"id": "recon", "status": "succeeded"}],
            }

    monkeypatch.setattr(
        core, "workflow_scheduler", lambda **_kwargs: StubScheduler(),
    )

    def failed_planner(_plan_id):
        raise OSError("evidence store temporarily unavailable")

    monkeypatch.setattr(core, "propose_workflow_followups", failed_planner)
    with ThreadPoolExecutor(max_workers=1) as executor:
        result = executor.submit(
            lambda: asyncio.run(core.run_workflow_plan("p")),
        ).result(timeout=15)
    assert result["complete"] is True
    assert result["tasks"][0]["status"] == "succeeded"
    assert result["followup_error"] == "OSError"

def test_queue_summary_reports_stale_and_uncertain_without_claiming_live_workers(
    tmp_path,
):
    core = _core(tmp_path)
    empty = core.workflow_run_queue_summary()
    assert empty["total"] == 0
    assert empty["active_requests"] == []
    assert empty["worker_liveness_verified"] is False
    queued = core.enqueue_workflow_run("p")
    summary = Core(tmp_path).workflow_run_queue_summary()
    assert summary["counts"]["queued"] == 1
    assert summary["active_requests"] == [{
        "id": queued["id"], "plan_id": "p", "status": "queued",
        "submitted_at": queued["submitted_at"],
    }]
    assert summary["oldest_queued_age_s"] >= 0
    assert summary["requires_reconciliation_count"] == 0
    claim = core.workflow_requests.claim("worker")
    assert claim["id"] == queued["id"]
    live = core.workflow_run_queue_summary()
    assert live["counts"]["running"] == 1
    assert live["active_requests"][0]["status"] == "running"
    assert live["active_requests"][0]["id"] == queued["id"]
    assert "lease_token" not in json.dumps(live["active_requests"])
    assert live["stale_running_count"] == 0
    assert live["worker_liveness_verified"] is False
    assert "lease_token" not in live
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=? WHERE id=?",
            (time.time() - 1000, queued["id"]),
        )
    finally:
        conn.close()
    stale = core.workflow_run_queue_summary()
    assert stale["stale_running_count"] == 1
    assert stale["requires_reconciliation_count"] == 1
    # Inspection is never a mutation or a retry.
    assert core.workflow_run_request(queued["id"])["status"] == "running"
    assert core.workflow_requests.reconcile_stale() == 1
    uncertain = core.workflow_run_queue_summary()
    assert uncertain["counts"]["uncertain"] == 1
    assert uncertain["active_requests"][0]["status"] == "uncertain"
    assert uncertain["active_requests"][0]["id"] == queued["id"]
    assert uncertain["requires_reconciliation_count"] == 1
    assert uncertain["automatic_uncertain_replay"] is False


@pytest.mark.parametrize("value", [True, 0, -1, float("nan"), float("inf")])
def test_queue_summary_rejects_invalid_stale_threshold(tmp_path, value):
    core = _core(tmp_path)
    with pytest.raises(ValueError, match="finite and positive"):
        core.workflow_requests.summary(stale_after_s=value)


def test_queue_summary_cli_api_share_persisted_state(tmp_path, monkeypatch, capsys):
    import json

    from whaxon.interfaces.cli.workflow_cmd import main as workflow_main

    core = _core(tmp_path)
    core.enqueue_workflow_run("p")
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.get("/api/v2/workflow-runs/summary")
    assert response.status_code == 200
    assert response.get_json()["counts"]["queued"] == 1
    assert workflow_main([
        "--data-dir", str(tmp_path), "plan", "queue-summary",
    ]) == 0
    cli_state = json.loads(capsys.readouterr().out)
    api_state = response.get_json()
    assert cli_state["counts"] == api_state["counts"]
    assert cli_state["requires_reconciliation_count"] == api_state[
        "requires_reconciliation_count"
    ]
    assert client.post("/api/v2/workflow-runs/summary").status_code == 405


def test_missing_running_heartbeat_is_uncertain_and_never_replayed(tmp_path):
    """A running request with missing heartbeat must not be stuck forever."""
    core = _core(tmp_path)
    request = core.enqueue_workflow_run("p")
    claimed = core.workflow_requests.claim("worker-lost")
    assert claimed["id"] == request["id"]

    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=NULL WHERE id=?",
            (request["id"],),
        )
    finally:
        conn.close()

    restarted = Core(tmp_path)
    before = restarted.workflow_run_queue_summary()
    assert before["stale_running_count"] == 1
    assert before["requires_reconciliation_count"] == 1

    assert restarted.workflow_requests.reconcile_stale(older_than_s=60) == 1
    after = restarted.workflow_run_queue_summary()
    assert after["counts"]["running"] == 0
    assert after["counts"]["uncertain"] == 1
    assert after["stale_running_count"] == 0
    assert after["requires_reconciliation_count"] == 1

    assert restarted.workflow_requests.claim("new-worker") is None
    assert not core.workflow_requests.heartbeat(
        request["id"], claimed["lease_token"],
    )
    assert not core.workflow_requests.finish(
        request["id"], claimed["lease_token"], status="completed",
    )


def test_stale_reconciliation_keeps_fresh_running_request_owned(tmp_path):
    """Recovery must isolate stale workers from still-live independent plans."""
    core = _core(tmp_path)
    core.save_workflow_plan(
        "p2", WorkflowPlan(
            "m", (WorkflowTask("recon2", "fixture", "192.0.2.11"),),
        ),
    )
    old = core.enqueue_workflow_run("p")
    fresh = core.enqueue_workflow_run("p2")
    old_claim = core.workflow_requests.claim("old-worker")
    fresh_claim = core.workflow_requests.claim("fresh-worker")
    assert old_claim["id"] == old["id"]
    assert fresh_claim["id"] == fresh["id"]

    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=NULL WHERE id=?",
            (old["id"],),
        )
    finally:
        conn.close()

    restarted = Core(tmp_path)
    assert restarted.workflow_requests.reconcile_stale(older_than_s=60) == 1
    assert restarted.workflow_run_request(old["id"])["status"] == "uncertain"
    assert restarted.workflow_run_request(fresh["id"])["status"] == "running"
    assert restarted.workflow_requests.heartbeat(
        fresh["id"], fresh_claim["lease_token"],
    )
    assert restarted.workflow_requests.finish(
        fresh["id"], fresh_claim["lease_token"], status="completed",
    )
    assert restarted.workflow_run_request(fresh["id"])["status"] == "completed"


def test_e5_api_client_reconnect_after_server_restart_keeps_durable_identity(
    tmp_path, monkeypatch,
):
    first = _core(tmp_path)
    # Suppress only the process-local wakeup; the persisted intent must be
    # observable from an independently constructed server instance.
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, callback: None)
    app = create_app(first, JobRegistry(first), AsyncRunner(first))
    app.config["TESTING"] = True
    response = app.test_client().post(
        "/api/v2/workflows/p/run",
        json={"max_tasks": 3, "max_attempts": 2, "max_concurrency": 1},
    )
    assert response.status_code == 202
    accepted = response.get_json()
    assert accepted["execution_completed"] is False
    restarted = Core(tmp_path)
    second_app = create_app(
        restarted, JobRegistry(restarted), AsyncRunner(restarted),
    )
    second_app.config["TESTING"] = True
    client = second_app.test_client()
    recovered = client.get(accepted["run_request_url"])
    assert recovered.status_code == 200
    assert recovered.get_json()["id"] == accepted["run_request_id"]
    assert recovered.get_json()["status"] == "queued"
    assert "lease_token" not in recovered.get_json()
    assert client.get(accepted["durable_progress_url"]).status_code == 200
    # An identical submission from the reconnected client must not create a
    # second external execution intent.
    repeated = client.post(
        "/api/v2/workflows/p/run",
        json={"max_tasks": 3, "max_attempts": 2, "max_concurrency": 1},
    )
    assert repeated.status_code == 202
    assert repeated.get_json()["run_request_id"] == accepted["run_request_id"]
    assert client.get("/api/v2/workflow-runs/summary").get_json()["total"] == 1


def test_e5_queue_summary_failure_rolls_back_read_transaction(tmp_path, monkeypatch):
    core = _core(tmp_path)
    core.enqueue_workflow_run("p")
    # Verify the ordinary snapshot remains stable and does not claim that a
    # recently heartbeating worker is live.
    snapshot = core.workflow_run_queue_summary()
    assert snapshot["counts"]["queued"] == 1
    assert snapshot["worker_liveness_verified"] is False
    assert snapshot["automatic_uncertain_replay"] is False
    assert snapshot["total"] == sum(snapshot["counts"].values())
    assert core.workflow_requests.claim("worker") is not None
    newer = core.workflow_run_queue_summary()
    assert newer["counts"]["queued"] == 0
    assert newer["counts"]["running"] == 1
    assert newer["total"] == 1


def test_e5_run_snapshot_reconnect_and_lease_secrecy(tmp_path, monkeypatch):
    core = _core(tmp_path)
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, callback: None)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    response = app.test_client().post("/api/v2/workflows/p/run", json={})
    assert response.status_code == 202
    run_id = response.get_json()["run_request_id"]

    restarted = Core(tmp_path)
    recovered = restarted.workflow_run_snapshot(run_id)
    assert recovered["schema_version"] == "whaxon.workflow-run-snapshot.v1"
    assert recovered["request"]["id"] == run_id
    assert recovered["worker_liveness_verified"] is False
    assert recovered["automatic_uncertain_replay"] is False
    assert "lease_token" not in recovered["request"]
    assert recovered["progress"] == restarted.workflow_progress("p")
    second = create_app(
        restarted, JobRegistry(restarted), AsyncRunner(restarted),
    )
    second.config["TESTING"] = True
    client = second.test_client()
    snapshot = client.get(f"/api/v2/workflow-runs/{run_id}/snapshot")
    assert snapshot.status_code == 200
    assert snapshot.get_json()["request"]["id"] == run_id
    assert client.get("/api/v2/workflow-runs/unknown/snapshot").status_code == 404

    claimed = restarted.workflow_requests.claim("worker")
    assert claimed is not None
    assert claimed["id"] == run_id
    running = client.get(f"/api/v2/workflow-runs/{run_id}/snapshot").get_json()
    assert running["request"]["status"] == "running"
    assert "lease_token" not in running["request"]
    assert claimed["lease_token"] not in str(running)


def test_e5_submission_advertises_reconnect_snapshot_without_execution_claim(
    tmp_path, monkeypatch,
):
    core = _core(tmp_path)
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, callback: None)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    client = app.test_client()
    accepted = client.post("/api/v2/workflows/p/run", json={})
    assert accepted.status_code == 202
    body = accepted.get_json()
    assert body["execution_completed"] is False
    assert body["request_status"] == "queued"
    assert body["run_snapshot_url"].endswith(
        f"/{body['run_request_id']}/snapshot"
    )
    snapshot = client.get(body["run_snapshot_url"])
    assert snapshot.status_code == 200
    assert snapshot.get_json()["request"]["id"] == body["run_request_id"]
    assert snapshot.get_json()["request"]["status"] == "queued"
    assert snapshot.get_json()["worker_liveness_verified"] is False
    duplicate = client.post("/api/v2/workflows/p/run", json={})
    assert duplicate.status_code == 202
    assert duplicate.get_json()["run_request_id"] == body["run_request_id"]
    assert core.workflow_run_queue_summary()["total"] == 1


def test_e5_cancelled_intent_stays_cancelled_across_api_restart(
    tmp_path, monkeypatch,
):
    core = _core(tmp_path)
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, callback: None)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    client = app.test_client()
    accepted = client.post("/api/v2/workflows/p/run", json={})
    assert accepted.status_code == 202
    run_id = accepted.get_json()["run_request_id"]
    cancelled = client.post("/api/v2/workflows/p/cancel")
    assert cancelled.status_code == 200
    assert cancelled.get_json()["external_effects_stopped"] is False
    assert core.workflow_run_request(run_id)["status"] == "cancelled"

    restarted = Core(tmp_path)
    second = create_app(
        restarted, JobRegistry(restarted), AsyncRunner(restarted),
    )
    second.config["TESTING"] = True
    snapshot = second.test_client().get(
        f"/api/v2/workflow-runs/{run_id}/snapshot"
    )
    assert snapshot.status_code == 200
    assert snapshot.get_json()["request"]["status"] == "cancelled"
    assert snapshot.get_json()["automatic_uncertain_replay"] is False
    assert restarted.workflow_requests.claim("replacement-worker") is None


def test_e5_lease_loss_visible_after_reconnect_without_credential_leak(tmp_path):
    core = _core(tmp_path)
    queued = core.enqueue_workflow_run("p")
    claimed = core.workflow_requests.claim("lost-worker")
    assert claimed is not None
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=1 WHERE id=?",
            (queued["id"],),
        )
    finally:
        conn.close()
    restarted = Core(tmp_path)
    assert restarted.workflow_requests.reconcile_stale(older_than_s=120) == 1
    app = create_app(
        restarted, JobRegistry(restarted), AsyncRunner(restarted),
    )
    app.config["TESTING"] = True
    result = app.test_client().get(
        f"/api/v2/workflow-runs/{queued['id']}/snapshot"
    )
    assert result.status_code == 200
    data = result.get_json()
    assert data["request"]["status"] == "uncertain"
    assert "lease_token" not in data["request"]
    assert claimed["lease_token"] not in str(data)
    assert data["automatic_uncertain_replay"] is False
    assert restarted.workflow_requests.claim("replacement-worker") is None


def test_e5_request_identity_cancel_api_is_durable_and_fails_closed(
    tmp_path, monkeypatch,
):
    core = _core(tmp_path)
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, callback: None)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    client = app.test_client()
    assert client.post(
        "/api/v2/workflow-runs/unknown/cancel",
    ).status_code == 404
    accepted = client.post("/api/v2/workflows/p/run", json={})
    request_id = accepted.get_json()["run_request_id"]
    response = client.post(
        f"/api/v2/workflow-runs/{request_id}/cancel"
    )
    assert response.status_code == 200
    result = response.get_json()
    assert result["run_request_id"] == request_id
    assert result["external_effects_stopped"] is False
    assert result["request"]["status"] == "cancelled"
    assert Core(tmp_path).workflow_run_request(request_id)["status"] == "cancelled"
    assert Core(tmp_path).workflow_requests.claim("worker") is None


def test_e5_concurrent_duplicate_api_submissions_share_one_durable_intent(
    tmp_path, monkeypatch,
):
    core = _core(tmp_path)
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, callback: None)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True

    def submit(_):
        # Each request gets its own Flask test client, as in separate
        # client connections racing to persist the same plan intent.
        response = app.test_client().post(
            "/api/v2/workflows/p/run", json={
                "max_tasks": 10, "max_attempts": 2, "max_concurrency": 1,
            },
        )
        return response.status_code, response.get_json()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(submit, range(24)))
    assert all(status == 202 for status, _ in results)
    ids = {body["run_request_id"] for _, body in results}
    assert len(ids) == 1
    assert core.workflow_run_queue_summary()["counts"]["queued"] == 1
    assert core.workflow_run_queue_summary()["total"] == 1
    assert all(
        body["run_snapshot_url"].endswith(
            f"/{body['run_request_id']}/snapshot"
        ) for _, body in results
    )


def test_e5_concurrent_cancel_and_claim_never_replays_queued_intent(tmp_path):
    core = _core(tmp_path)
    queued = core.enqueue_workflow_run("p")
    barrier = __import__("threading").Barrier(2)

    def cancel():
        barrier.wait()
        return Core(tmp_path).cancel_workflow_run_request(queued["id"])

    def claim():
        barrier.wait()
        return Core(tmp_path).workflow_requests.claim("racing-worker")

    with ThreadPoolExecutor(max_workers=2) as pool:
        cancelled_future = pool.submit(cancel)
        claimed_future = pool.submit(claim)
        cancelled = cancelled_future.result(timeout=15)
        claimed = claimed_future.result(timeout=15)
    assert cancelled["cancellation_requested"] is True
    assert cancelled["external_effects_stopped"] is False
    state = Core(tmp_path).workflow_run_request(queued["id"])
    assert state["status"] in {"cancelled", "running"}
    if state["status"] == "cancelled":
        assert claimed is None
    else:
        assert claimed is not None and claimed["id"] == queued["id"]
        assert Core(tmp_path).workflow_requests.claim("late-worker") is None
        assert "lease_token" not in state
    assert Core(tmp_path).workflow_requests.claim("another-worker") is None
