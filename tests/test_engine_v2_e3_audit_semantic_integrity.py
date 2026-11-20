"""E3 internal audit integrity and manual reconciliation readiness."""
from __future__ import annotations

import sqlite3

from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _store(tmp_path):
    store = JobStore(tmp_path / "integrity.db")
    store.create_mission("mission", "E3 audit integrity")
    store.save_workflow_plan(
        "plan", WorkflowPlan("mission", (
            WorkflowTask("task", "fixture", "192.0.2.10"),
        )),
    )
    return store


def test_healthy_pre_dispatch_running_attempt_needs_no_manual_reconciliation(tmp_path):
    store = _store(tmp_path)
    claim = store.claim_ready_workflow_task("plan", "worker")
    assert claim is not None
    info = store.get_workflow_readiness("plan")
    assert info["requires_manual_reconciliation"] is False
    assert info["ready_to_report_success"] is False
    store.mark_workflow_dispatch_started("plan", claim["attempt_id"])
    info = store.get_workflow_readiness("plan")
    assert info["requires_manual_reconciliation"] is True


def test_mismatched_terminal_event_fails_closed_on_audit_and_readiness(tmp_path):
    store = _store(tmp_path)
    claim = store.claim_ready_workflow_task("plan", "worker")
    store.finish_task_attempt(claim["attempt_id"], "succeeded")
    assert store.get_workflow_audit_integrity("plan")["consistent"] is True
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE workflow_events SET event_type='task_failed' "
            "WHERE attempt_id=? AND event_type='task_succeeded'",
            (claim["attempt_id"],),
        )
    audit = store.get_workflow_audit_integrity("plan")
    assert audit["consistent"] is False
    assert audit["mismatched_terminal_events"] == [claim["attempt_id"]]
    assert not store.get_workflow_readiness("plan")["ready_to_report_success"]


def test_duplicate_dispatch_events_fail_closed_without_fake_success(tmp_path):
    store = _store(tmp_path)
    claim = store.claim_ready_workflow_task("plan", "worker")
    store.mark_workflow_dispatch_started("plan", claim["attempt_id"])
    store.finish_task_attempt(claim["attempt_id"], "succeeded")
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "INSERT INTO workflow_events "
            "(plan_id,task_ref,attempt_id,event_type,at) VALUES (?,?,?,?,?)",
            ("plan", claim["task_ref"], claim["attempt_id"],
             "dispatch_started", 123456789.0),
        )
    audit = store.get_workflow_audit_integrity("plan")
    assert audit["consistent"] is False
    assert audit["duplicate_dispatch_events"] == [claim["attempt_id"]]
    assert not store.get_workflow_readiness("plan")["ready_to_report_success"]


def test_orphan_attempt_event_and_running_terminal_event_are_detected(tmp_path):
    store = _store(tmp_path)
    claim = store.claim_ready_workflow_task("plan", "worker")
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "INSERT INTO workflow_events "
            "(plan_id,task_ref,attempt_id,event_type,at) VALUES (?,?,?,?,?)",
            ("plan", claim["task_ref"], "unknown-attempt",
             "task_claimed", 123456789.0),
        )
        conn.execute(
            "INSERT INTO workflow_events "
            "(plan_id,task_ref,attempt_id,event_type,at) VALUES (?,?,?,?,?)",
            ("plan", claim["task_ref"], claim["attempt_id"],
             "task_succeeded", 123456790.0),
        )
    audit = store.get_workflow_audit_integrity("plan")
    assert audit["consistent"] is False
    assert audit["unknown_attempt_events"] == ["unknown-attempt"]
    assert audit["missing_or_duplicate_terminal_events"] == [claim["attempt_id"]]
