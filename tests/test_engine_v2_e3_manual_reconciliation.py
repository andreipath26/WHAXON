"""Engine V2 manual provider-effect reconciliation is explicit and non-replaying."""
from __future__ import annotations

import json
import sqlite3

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _uncertain_plan(tmp_path):
    core = Core(tmp_path)
    core.create_mission("m", "manual provider-effect reconciliation")
    core.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("t", "fixture", "192.0.2.10"),)),
    )
    request = core.enqueue_workflow_run("p")
    run_claim = core.workflow_requests.claim("run-worker")
    assert run_claim and run_claim["id"] == request["id"]
    task_claim = core.store.claim_ready_workflow_task(
        "p", "task-worker", max_attempts=3,
    )
    assert task_claim is not None
    attempt_id = task_claim["attempt_id"]
    assert core.store.mark_workflow_dispatch_started("p", attempt_id)
    core.store.finish_task_attempt(
        attempt_id, "uncertain", error="worker lost after dispatch",
    )
    assert core.workflow_requests.finish(
        request["id"], run_claim["lease_token"], status="uncertain",
        error="worker lost after claim",
    )
    return core, request, attempt_id


def _reconcile(core, attempt_id, disposition):
    return core.reconcile_workflow_attempt(
        "p", attempt_id, disposition=disposition, actor="operator",
        evidence_ref="case://reconciliation/17",
        note="Checked provider and target logs; recorded source evidence.",
    )


def test_verified_no_effect_closes_request_but_requires_new_run(tmp_path):
    core, request, attempt_id = _uncertain_plan(tmp_path)

    result = _reconcile(core, attempt_id, "no_effect_verified")

    assert result["task_status"] == "failed"
    assert result["task_retryable"] is True
    assert result["automatic_replay"] is False
    assert result["run_requests_closed"] == 1
    assert core.workflow_run_request(request["id"])["status"] == "incomplete"
    assert core.store.list_workflow_tasks("p")[0]["status"] == "failed"
    conn = core.store._conn()
    try:
        events = conn.execute(
            "SELECT detail_json FROM workflow_events WHERE plan_id=? "
            "AND event_type='workflow_run_reconciled'",
            ("p",),
        ).fetchall()
    finally:
        conn.close()
    assert len(events) == 1
    assert json.loads(events[0]["detail_json"]) == {
        "request_id": request["id"],
        "from_status": "uncertain",
        "to_status": "incomplete",
        "reason": "provider_effect_reconciled",
        "automatic_replay": False,
    }
    assert core.store.get_workflow_audit_integrity("p")["consistent"] is True

    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_events SET detail_json=? WHERE plan_id=? "
            "AND event_type='workflow_run_reconciled'",
            (json.dumps({
                "request_id": request["id"],
                "from_status": "uncertain",
                "to_status": "incomplete",
                "reason": "tampered",
                "automatic_replay": False,
            }, sort_keys=True), "p"),
        )
    finally:
        conn.close()
    audit = core.store.get_workflow_audit_integrity("p")
    assert audit["consistent"] is False
    assert audit["mismatched_run_request_reconciliation_events"] == [request["id"]]

    assert core.store.get_workflow_dispatch_reconciliation("p")[0][
        "manual_reconciliation_required"
    ] is False
    # No queued work resumes from the operator record.
    assert core.workflow_requests.claim("worker") is None

    next_request = core.enqueue_workflow_run("p")
    assert next_request["id"] != request["id"]
    assert core.workflow_requests.claim("worker")["id"] == next_request["id"]
    retry = core.store.claim_ready_workflow_task(
        "p", "retry-worker", max_attempts=3,
    )
    assert retry is not None and retry["attempt_id"] != attempt_id


def test_observed_effect_is_blocked_and_never_certified_as_success(tmp_path):
    core, request, attempt_id = _uncertain_plan(tmp_path)

    result = _reconcile(core, attempt_id, "effect_observed")

    assert result["task_status"] == "blocked"
    assert result["task_retryable"] is False
    assert result["automatic_replay"] is False
    assert result["run_requests_closed"] == 1
    assert core.workflow_run_request(request["id"])["status"] == "incomplete"
    assert core.store.get_workflow_attempt_status(attempt_id) == "uncertain"
    assert core.store.list_workflow_tasks("p")[0]["status"] == "blocked"
    conn = core.store._conn()
    try:
        seals = conn.execute(
            "SELECT COUNT(*) FROM workflow_evidence_seals WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()[0]
    finally:
        conn.close()
    assert seals == 0


def test_missing_run_request_reconciliation_event_fails_audit(tmp_path):
    core, request, attempt_id = _uncertain_plan(tmp_path)

    result = _reconcile(core, attempt_id, "no_effect_verified")
    assert result["run_requests_closed"] == 1

    conn = core.store._conn()
    try:
        conn.execute(
            "DELETE FROM workflow_events WHERE plan_id=? "
            "AND event_type='workflow_run_reconciled'",
            ("p",),
        )
    finally:
        conn.close()

    audit = core.store.get_workflow_audit_integrity("p")
    assert audit["consistent"] is False
    assert audit["missing_or_duplicate_run_request_reconciliation_events"] == [
        request["id"]
    ]


def test_attempt_reconciliation_and_run_request_closure_are_atomic(tmp_path):
    core, request, attempt_id = _uncertain_plan(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "CREATE TRIGGER reject_run_reconciliation_event "
            "BEFORE INSERT ON workflow_events "
            "WHEN NEW.event_type='workflow_run_reconciled' "
            "BEGIN SELECT RAISE(ABORT, 'injected audit write failure'); END",
        )
    finally:
        conn.close()

    try:
        _reconcile(core, attempt_id, "no_effect_verified")
    except sqlite3.IntegrityError as exc:
        assert "injected audit write failure" in str(exc)
    else:
        raise AssertionError("run reconciliation event failure was ignored")

    assert core.workflow_run_request(request["id"])["status"] == "uncertain"
    assert core.store.get_workflow_attempt_status(attempt_id) == "uncertain"
    assert core.store.list_workflow_tasks("p")[0]["status"] == "uncertain"
    conn = core.store._conn()
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM workflow_attempt_reconciliations "
            "WHERE attempt_id=?", (attempt_id,),
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM workflow_events WHERE plan_id=? "
            "AND event_type='workflow_attempt_reconciled'", ("p",),
        ).fetchone()[0] == 0
        conn.execute("DROP TRIGGER reject_run_reconciliation_event")
    finally:
        conn.close()

    result = _reconcile(core, attempt_id, "no_effect_verified")
    assert result["run_requests_closed"] == 1
    assert core.workflow_run_request(request["id"])["status"] == "incomplete"


def test_unresolved_effect_keeps_request_fenced_and_retry_disabled(tmp_path):
    core, request, attempt_id = _uncertain_plan(tmp_path)

    result = _reconcile(core, attempt_id, "unresolved")

    assert result["task_status"] == "uncertain"
    assert result["task_retryable"] is False
    assert result["run_requests_closed"] == 0
    assert core.workflow_run_request(request["id"])["status"] == "uncertain"
    conn = core.store._conn()
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM workflow_events WHERE plan_id=? "
            "AND event_type='workflow_run_reconciled'",
            ("p",),
        ).fetchone()[0] == 0
    finally:
        conn.close()
    assert core.workflow_requests.enqueue(
        "p", limits={"max_tasks": 100, "max_attempts": 2, "max_concurrency": 4},
    )["id"] == request["id"]
    assert core.workflow_requests.claim("worker") is None


def test_reconciliation_is_idempotent_but_cannot_be_rewritten(tmp_path):
    core, _, attempt_id = _uncertain_plan(tmp_path)

    first = _reconcile(core, attempt_id, "no_effect_verified")
    second = _reconcile(core, attempt_id, "no_effect_verified")
    assert first["idempotent"] is False
    assert second["idempotent"] is True
    try:
        _reconcile(core, attempt_id, "effect_observed")
    except ValueError as exc:
        assert "different reconciliation" in str(exc)
    else:
        raise AssertionError("reconciliation record was overwritten")


def test_reconciliation_requires_source_evidence_and_valid_outcome(tmp_path):
    core, _, attempt_id = _uncertain_plan(tmp_path)
    for values in (
        {"disposition": "success", "actor": "operator",
         "evidence_ref": "case://17", "note": "checked"},
        {"disposition": "no_effect_verified", "actor": "operator",
         "evidence_ref": "", "note": "checked"},
    ):
        try:
            core.reconcile_workflow_attempt("p", attempt_id, **values)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid reconciliation was accepted")



def test_reconciliation_record_and_audit_event_must_match(tmp_path):
    core, _, attempt_id = _uncertain_plan(tmp_path)
    _reconcile(core, attempt_id, "no_effect_verified")
    assert core.store.get_workflow_audit_integrity("p")["consistent"] is True

    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_events SET detail_json=?, task_ref='tampered-task' "
            "WHERE plan_id=? AND attempt_id=? "
            "AND event_type='workflow_attempt_reconciled'",
            ('{"actor_claimed":"operator","disposition":"effect_observed",'
             '"evidence_ref":"case://reconciliation/17",'
             '"note":"Checked provider and target logs; recorded source evidence."}',
             "p", attempt_id),
        )
    finally:
        conn.close()

    audit = core.store.get_workflow_audit_integrity("p")
    assert audit["consistent"] is False
    assert audit["mismatched_reconciliation_events"] == [attempt_id]


def test_reconciliation_without_audit_event_is_reported(tmp_path):
    core, _, attempt_id = _uncertain_plan(tmp_path)
    _reconcile(core, attempt_id, "effect_observed")

    conn = core.store._conn()
    try:
        conn.execute(
            "DELETE FROM workflow_events WHERE plan_id=? AND attempt_id=? "
            "AND event_type='workflow_attempt_reconciled'",
            ("p", attempt_id),
        )
    finally:
        conn.close()

    audit = core.store.get_workflow_audit_integrity("p")
    assert audit["consistent"] is False
    assert audit["missing_or_duplicate_reconciliation_events"] == [attempt_id]
