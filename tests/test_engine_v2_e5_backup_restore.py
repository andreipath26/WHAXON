"""E5 durable queue backup/restore is independently reconciled, never replayed."""
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _create_source(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    core = Core(path)
    core.create_mission("mission", "durable system service backup contract")
    core.save_workflow_plan(
        "plan",
        WorkflowPlan("mission", (
            WorkflowTask("task", "unsupported.fixture", "192.0.2.10"),
        )),
    )
    return core


def _backup_database(source: Core, destination: Path):
    """Use SQLite's online backup API rather than unsafe live-file copying."""
    destination.mkdir(parents=True, exist_ok=True)
    with (
        closing(source.store._conn()) as existing,
        closing(sqlite3.connect(destination / "whaxon.db")) as snapshot,
    ):
        existing.backup(snapshot)


def test_e5_restored_queued_request_keeps_exact_mission_and_plan(tmp_path):
    source = _create_source(tmp_path / "original")
    queued = source.enqueue_workflow_run("plan")
    _backup_database(source, tmp_path / "restored")
    restored = Core(tmp_path / "restored")
    assert restored.workflow_run_request(queued["id"])["status"] == "queued"
    assert restored.workflow_run_request(queued["id"])["plan_digest"] == queued["plan_digest"]
    assert restored.store.verify_workflow_plan_integrity("plan")["digest"] == queued["plan_digest"]
    claim = restored.workflow_requests.claim("restarted-worker")
    assert claim is not None and claim["id"] == queued["id"]
    assert claim["limits"] == queued["limits"]
    assert "lease_token" in claim
    assert "lease_token" not in restored.workflow_run_request(queued["id"])
    # Backup is a snapshot: working on restored state did not change source.
    assert source.workflow_run_request(queued["id"])["status"] == "queued"


def test_e5_restored_dead_worker_request_remains_uncertain_without_replay(tmp_path):
    source = _create_source(tmp_path / "original")
    queued = source.enqueue_workflow_run("plan")
    original_claim = source.workflow_requests.claim("worker-before-backup")
    assert original_claim is not None
    conn = source.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=? WHERE id=?",
            (time.time() - 500, queued["id"]),
        )
    finally:
        conn.close()
    _backup_database(source, tmp_path / "restored")
    restored = Core(tmp_path / "restored")
    assert restored.workflow_requests.reconcile_stale(older_than_s=60) == 1
    status = restored.workflow_run_request(queued["id"])
    assert status["status"] == "uncertain"
    assert status["limits_integrity"] == "valid"
    assert "lease_token" not in status
    assert restored.workflow_requests.claim("new-worker") is None
    assert not restored.workflow_requests.heartbeat(
        queued["id"], original_claim["lease_token"],
    )
    events = [
        item for item in restored.store.list_workflow_events("plan")
        if item["event_type"] == "workflow_run_uncertain"
    ]
    assert len(events) == 1
    assert events[0]["detail"]["reason"] == "worker_lease_lost"
