"""E3 lifecycle snapshot digest: operator-controlled external anchor contract."""
from __future__ import annotations

import sqlite3

import pytest

from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _store(path):
    store = JobStore(path)
    store.create_mission("m", "E3 durable lifecycle digest")
    store.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask(
            "task", "fixture", "192.0.2.10",
        ),)),
    )
    return store


def test_lifecycle_audit_snapshot_is_restart_stable_and_privacy_minimal(tmp_path):
    db = tmp_path / "snapshot.db"
    store = _store(db)
    claim = store.claim_ready_workflow_task("p", "worker")
    store.mark_workflow_dispatch_started("p", claim["attempt_id"])
    store.finish_task_attempt(claim["attempt_id"], "succeeded",
                              result={"secret": "not in snapshot output"})
    snapshot = store.get_workflow_audit_snapshot("p")
    assert snapshot["schema_version"] == "whaxon.workflow-audit-snapshot.v1"
    assert snapshot["algorithm"] == "sha256"
    assert snapshot["task_count"] == 1
    assert snapshot["attempt_count"] == 1
    assert snapshot["event_count"] >= 3
    assert snapshot["independent_anchor_verified"] is False
    assert "secret" not in str(snapshot)
    assert JobStore(db).get_workflow_audit_snapshot("p") == snapshot
    assert JobStore(db).verify_workflow_audit_snapshot(
        "p", snapshot["digest"],
    )


@pytest.mark.parametrize(
    "changed", ["event", "attempt", "task", "plan_payload", "task_inputs"],
)
def test_externally_preserved_snapshot_detects_db_lifecycle_mutation(
    tmp_path, changed,
):
    db = tmp_path / "snapshot.db"
    store = _store(db)
    claim = store.claim_ready_workflow_task("p", "worker")
    store.finish_task_attempt(claim["attempt_id"], "succeeded")
    anchored = store.get_workflow_audit_snapshot("p")["digest"]
    with sqlite3.connect(db) as conn:
        if changed == "event":
            conn.execute(
                "UPDATE workflow_events SET event_type='forged_event' "
                "WHERE plan_id='p' AND event_type='task_succeeded'"
            )
        elif changed == "attempt":
            conn.execute(
                "UPDATE task_attempts SET status='failed' WHERE id=?",
                (claim["attempt_id"],),
            )
        elif changed == "plan_payload":
            conn.execute(
                "UPDATE workflow_plans SET plan_json=? WHERE id='p'",
                ('{"tampered": true}',),
            )
        elif changed == "task_inputs":
            conn.execute(
                "UPDATE workflow_tasks SET inputs_json=? WHERE plan_id='p'",
                ('{"tampered": true}',),
            )
        else:
            conn.execute(
                "UPDATE workflow_tasks SET status='failed' WHERE plan_id='p'"
            )
    assert JobStore(db).verify_workflow_audit_snapshot("p", anchored) is False
    assert JobStore(db).get_workflow_audit_snapshot("p")["digest"] != anchored


@pytest.mark.parametrize("bad", [None, 1, "", "A" * 64, "x" * 64, "a" * 63])
def test_audit_snapshot_verification_rejects_invalid_reference(tmp_path, bad):
    store = _store(tmp_path / "snapshot.db")
    with pytest.raises(ValueError, match="expected_digest"):
        store.verify_workflow_audit_snapshot("p", bad)


def test_snapshots_are_read_only_and_scoped_to_one_plan(tmp_path):
    store = _store(tmp_path / "snapshot.db")
    store.save_workflow_plan(
        "other", WorkflowPlan("m", (WorkflowTask(
            "unrelated", "fixture", "192.0.2.11",
        ),)),
    )
    original = store.get_workflow_audit_snapshot("p")
    other = store.claim_ready_workflow_task("other", "worker")
    store.finish_task_attempt(other["attempt_id"], "blocked")
    assert store.get_workflow_audit_snapshot("p") == original
    with pytest.raises(ValueError, match="unknown workflow plan"):
        store.get_workflow_audit_snapshot("missing")
