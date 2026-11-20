import threading
import time

import pytest

from whaxon.core.store import JobStore


@pytest.fixture
def store(tmp_path):
    return JobStore(tmp_path / "test.db")

def test_create_and_get(store):
    store.create("abc")
    assert store.get("abc")["status"] == "starting"

def test_full_lifecycle(store):
    store.create("j1")
    store.set_started("j1", "nmap", "127.0.0.1")
    store.append_line("j1", "stdout", "a")
    store.append_line("j1", "stderr", "b")
    store.set_finished("j1", 0, 1.5)
    j = store.get("j1")
    assert j["status"] == "finished"
    assert len(j["lines"]) == 2

def test_findings_roundtrip(store):
    store.create("f1")
    store.append_finding("f1", {"kind": "open_port", "severity": "high", "source": "nmap",
                                "data": {"port": 22}, "raw_line": "22/tcp"}, 0)
    out = store.get_findings("f1")
    assert out[0]["severity"] == "high"
    assert out[0]["data"]["port"] == 22

def test_history_ordering(store):
    for i in range(3):
        store.create(f"h{i}")
        store.set_finished(f"h{i}", 0, 0.1)
        time.sleep(0.01)
    assert store.history()[0]["id"] == "h2"

def test_history_includes_recorded_start_timestamp(store):
    store.create("history-timestamp")
    store.set_started("history-timestamp", "nmap", "127.0.0.1")
    store.set_finished("history-timestamp", 0, 0.1)

    entry = store.history()[0]

    assert isinstance(entry["started_at"], (int, float))
    assert entry["started_at"] > 0


def test_evidence_crud(store):
    store.create("e1")
    seq = store.add_evidence("e1", "note", "n", note="hi")
    store.add_evidence("e1", "file", "s.png", path="evidence/e1/s.png")
    assert len(store.list_evidence("e1")) == 2
    assert store.remove_evidence("e1", seq) is True

def test_concurrent_writes(store):
    def worker(jid):
        store.create(jid)
        for i in range(50):
            store.append_line(jid, "stdout", f"l{i}")
        store.set_finished(jid, 0, 1.0)
    ts = [threading.Thread(target=worker, args=(f"c{i}",)) for i in range(4)]
    for t in ts: t.start()
    for t in ts: t.join()
    for i in range(4):
        assert len(store.get(f"c{i}")["lines"]) == 50


def test_active_jobs_returns_only_running_jobs(store):
    store.create("active-running")
    store.set_started("active-running", "nmap", "127.0.0.1")
    store.create("active-finished")
    store.set_started("active-finished", "nikto", "127.0.0.1")
    store.set_finished("active-finished", 0, 1.0)
    store.create("active-starting")

    jobs = store.active_jobs()

    assert [job["id"] for job in jobs] == ["active-running"]
    assert jobs[0]["status"] == "running"
    assert jobs[0]["tool"] == "nmap"


def test_history_reports_finding_count_not_output_line_count(store):
    store.create("history-findings")
    store.set_started("history-findings", "nmap", "127.0.0.1")
    store.append_line("history-findings", "stdout", "tool output")
    store.append_finding(
        "history-findings",
        {"kind": "open_port", "severity": "medium", "source": "nmap",
         "data": {"port": 22}, "raw_line": "22/tcp open ssh"},
        0,
    )
    store.append_finding(
        "history-findings",
        {"kind": "open_port", "severity": "high", "source": "nmap",
         "data": {"port": 443}, "raw_line": "443/tcp open https"},
        1,
    )
    store.set_finished("history-findings", 0, 0.1)

    entry = next(row for row in store.history() if row["id"] == "history-findings")
    assert entry["line_count"] == 1
    assert entry["findings_count"] == 2

def test_findings_by_target_preserves_conflicting_path_observations(store):
    """Do not collapse different tools' status/size evidence into the first row."""
    target = "http://127.0.0.1:8080/"
    store.create("ffuf-job")
    store.set_started("ffuf-job", "ffuf", target)
    store.append_finding(
        "ffuf-job",
        {
            "kind": "found_path", "severity": "info", "source": "ffuf",
            "data": {"path": "/admin", "status": None, "size": None},
            "raw_line": "admin",
        },
        0,
    )
    store.create("gobuster-job")
    store.set_started("gobuster-job", "gobuster", target)
    store.append_finding(
        "gobuster-job",
        {
            "kind": "found_path", "severity": "info", "source": "gobuster",
            "data": {"path": "/admin", "status": 403, "size": 289},
            "raw_line": "/admin (Status: 403) [Size: 289]",
        },
        0,
    )

    grouped = store.findings_by_target()
    target_row = next(row for row in grouped if row["target"] == "127.0.0.1")
    observations = [f for f in target_row["findings"] if f["data"].get("path") == "/admin"]

    assert len(observations) == 2
    by_source = {finding["source"]: finding["data"] for finding in observations}
    assert by_source["ffuf"]["status"] is None
    assert by_source["gobuster"]["status"] == 403
    assert by_source["gobuster"]["size"] == 289


def test_worker_lease_heartbeat_prevents_stale_reconciliation(store):
    store.create_pending("leased", "nikto", "host:80")
    row = store.claim_pending(worker_id="worker-a")
    assert row is not None
    assert store.heartbeat_job("leased", row["lease_token"]) is True
    import sqlite3
    c = sqlite3.connect(store.path)
    c.execute("UPDATE jobs SET started_at=? WHERE id='leased'", (time.time() - 3600,))
    c.commit()
    c.close()
    assert store.reconcile_stale(older_than_s=60) == 0
    assert store.get("leased")["status"] == "running"


def test_worker_lease_fences_stale_completion(store):
    store.create_pending("fenced", "nikto", "host:80")
    first = store.claim_pending(worker_id="worker-a")
    assert first is not None
    # Simulate lease expiry and a recovery/administrative reset to pending.
    import sqlite3
    c = sqlite3.connect(store.path)
    c.execute("UPDATE jobs SET status='pending', lease_owner=NULL, lease_token=NULL, heartbeat_at=NULL WHERE id='fenced'")
    c.commit()
    c.close()
    second = store.claim_pending(worker_id="worker-b")
    assert second is not None
    assert second["lease_token"] != first["lease_token"]
    assert store.set_finished("fenced", 0, 1.0, lease_token=first["lease_token"]) is False
    assert store.get("fenced")["status"] == "running"
    assert store.owns_lease("fenced", second["lease_token"]) is True


def test_get_session_returns_dispatch_authorization_context(tmp_path):
    store = JobStore(tmp_path / "sessions.db")
    store.upsert_session("7", "10.0.0.7", "meterpreter", {"arch": "x64"})
    session = store.get_session("7")
    assert session is not None
    assert session["host"] == "10.0.0.7"
    assert session["status"] == "open"
    assert session["info"]["arch"] == "x64"
    assert store.get_session("missing") is None


def test_finished_job_retains_fencing_token_until_explicit_release(tmp_path):
    store = JobStore(tmp_path / "lease-finish.db")
    store.create_pending("job-1", "nmap", "127.0.0.1")
    lease = store.claim_pending(worker_id="test-worker")
    assert lease is not None
    token = lease["lease_token"]
    assert store.owns_lease("job-1", token)
    assert store.set_finished("job-1", 0, 0.1, lease_token=token)
    assert store.owns_lease("job-1", token)
    assert store.release_lease("job-1", token)
    assert not store.owns_lease("job-1", token)


def test_release_lease_rejects_wrong_token_and_nonterminal_job(tmp_path):
    store = JobStore(tmp_path / "lease-release.db")
    store.create_pending("job-2", "nmap", "127.0.0.1")
    lease = store.claim_pending(worker_id="test-worker")
    assert lease is not None
    token = lease["lease_token"]
    assert not store.release_lease("job-2", "wrong-token")
    assert not store.release_lease("job-2", token)
    assert store.owns_lease("job-2", token)


def test_workflow_plan_persistence_is_immutable_and_roundtrips(tmp_path):
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "workflow.db")
    store.create_mission("mission-1", "Assess the approved web target")
    plan = WorkflowPlan(
        mission_id="mission-1",
        tasks=(
            WorkflowTask("recon", "network.port_scan", "192.0.2.10"),
            WorkflowTask("web", "web.fingerprint", "192.0.2.10", depends_on=("recon",)),
        ),
    )
    assert store.save_workflow_plan("plan-1", plan) is True
    assert store.save_workflow_plan("plan-1", plan) is False
    saved = store.get_workflow_plan("plan-1")
    assert saved["digest"] == plan.digest
    assert saved["plan"] == plan.to_dict()
    tasks = store.list_workflow_tasks("plan-1")
    assert [task["id"] for task in tasks] == ["recon", "web"]
    assert tasks[1]["depends_on"] == ["recon"]


def test_workflow_plan_cannot_be_replaced_or_saved_without_mission(tmp_path):
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "workflow-immutable.db")
    plan = WorkflowPlan("missing", (WorkflowTask("a", "recon", "192.0.2.1"),))
    with pytest.raises(ValueError, match="unknown mission"):
        store.save_workflow_plan("plan", plan)
    store.create_mission("m", "objective")
    plan = WorkflowPlan("m", (WorkflowTask("a", "recon", "192.0.2.1"),))
    store.save_workflow_plan("plan", plan)
    changed = WorkflowPlan("m", (WorkflowTask("a", "recon", "192.0.2.2"),))
    with pytest.raises(ValueError, match="immutable"):
        store.save_workflow_plan("plan", changed)


def test_task_attempt_lifecycle_is_durable_and_atomic(tmp_path):
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "workflow-attempts.db")
    store.create_mission("m", "objective")
    plan = WorkflowPlan(
        "m",
        (WorkflowTask("scan", "network.port_scan", "192.0.2.10",
                      idempotency_key="scan-m-1"),),
    )
    store.save_workflow_plan("p", plan)
    assert store.start_task_attempt(
        "attempt-1", "scan", 1, worker_id="worker-a", idempotency_key="scan-m-1",
    )
    assert store.list_workflow_tasks("p")[0]["status"] == "running"
    assert store.finish_task_attempt(
        "attempt-1", "succeeded", result={"finding_count": 2},
    )
    task = store.list_workflow_tasks("p")[0]
    assert task["status"] == "succeeded"
    assert task["result"] == {"finding_count": 2}
    with pytest.raises(ValueError, match="already terminal"):
        store.finish_task_attempt("attempt-1", "failed")


def test_task_attempt_rejects_idempotency_mismatch(tmp_path):
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "workflow-idempotency.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan(
        "p", WorkflowPlan(
            "m", (WorkflowTask("scan", "network.port_scan", "192.0.2.10",
                               idempotency_key="expected"),),
        ),
    )
    with pytest.raises(ValueError, match="idempotency key mismatch"):
        store.start_task_attempt("a", "scan", 1, idempotency_key="other")


def test_reconcile_running_workflow_attempts_as_uncertain(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "workflow-recovery.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("scan", "network.port_scan", "192.0.2.10"),)),
    )
    row = store.claim_ready_workflow_task("p", "worker-a")
    assert row is not None
    assert store.reconcile_workflow_attempts() == 1
    assert store.list_workflow_tasks("p")[0]["status"] == "uncertain"
    conn = store._conn()
    try:
        attempt = conn.execute("SELECT status, error FROM task_attempts").fetchone()
        assert attempt["status"] == "uncertain"
        assert "reconcile before retry" in attempt["error"]
    finally:
        conn.close()
    assert store.reconcile_workflow_attempts() == 0


def test_task_attempt_is_fenced_and_cannot_be_started_twice(tmp_path):
    import pytest

    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "attempt-fencing.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("scan", "cap.scan", "192.0.2.10"),)),
    )
    assert store.start_task_attempt("attempt-one", "scan", 1, worker_id="worker-a")
    with pytest.raises(ValueError, match="active attempt"):
        store.start_task_attempt("attempt-two", "scan", 2, worker_id="worker-b")
    # Simulate recovery clearing the old task fence, then claim a new attempt.
    conn = store._conn()
    try:
        conn.execute(
            "UPDATE workflow_tasks SET status='pending', active_attempt_id=NULL WHERE plan_id='p'",
        )
    finally:
        conn.close()
    assert store.start_task_attempt("attempt-two", "scan", 2, worker_id="worker-b")
    with pytest.raises(ValueError, match="stale task attempt"):
        store.finish_task_attempt("attempt-one", "succeeded", result={"ok": True})
    assert store.finish_task_attempt("attempt-two", "succeeded", result={"ok": True})


def test_reconcile_clears_active_attempt_fence(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "attempt-reconcile-fence.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("scan", "cap.scan", "192.0.2.10"),)),
    )
    store.claim_ready_workflow_task("p", "worker-a")
    assert store.reconcile_workflow_attempts() == 1
    task = store.list_workflow_tasks("p")[0]
    assert task["status"] == "uncertain"
    assert task["active_attempt_id"] is None


def test_workflow_task_ids_are_scoped_to_their_plan(tmp_path):
    import pytest

    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "plan-local-task-ids.db")
    store.create_mission("m1", "first objective")
    store.create_mission("m2", "second objective")
    store.save_workflow_plan(
        "plan-one", WorkflowPlan("m1", (
            WorkflowTask("scan", "tool.nmap", "192.0.2.10"),
        )),
    )
    store.save_workflow_plan(
        "plan-two", WorkflowPlan("m2", (
            WorkflowTask("recon", "tool.whois", "example.org"),
            WorkflowTask("scan", "tool.nmap", "192.0.2.10", depends_on=("recon",)),
        )),
    )
    assert [row["id"] for row in store.list_workflow_tasks("plan-one")] == ["scan"]
    assert [row["id"] for row in store.list_workflow_tasks("plan-two")] == ["recon", "scan"]
    first = store.claim_ready_workflow_task("plan-one", "worker-one")
    second = store.claim_ready_workflow_task("plan-two", "worker-two")
    assert first["id"] == "scan"
    assert second["id"] == "recon"
    with pytest.raises(ValueError, match="ambiguous"):
        store.start_task_attempt("ambiguous", "scan", 1)


def test_reconcile_recovers_legacy_running_attempt_without_fence(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "legacy-running-attempt.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("scan", "tool.nmap", "192.0.2.10"),)),
    )
    store.claim_ready_workflow_task("p", "old-worker")
    conn = store._conn()
    try:
        conn.execute("UPDATE workflow_tasks SET active_attempt_id=NULL")
    finally:
        conn.close()
    assert store.reconcile_workflow_attempts() == 1
    assert store.list_workflow_tasks("p")[0]["status"] == "uncertain"



def test_workflow_lease_heartbeat_preserves_live_attempt_during_startup_recovery(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "workflow-live-lease.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("scan", "cap.scan", "192.0.2.10"),)),
    )
    row = store.claim_ready_workflow_task("p", "worker-live")
    assert row is not None
    assert store.heartbeat_workflow_attempt(row["attempt_id"]) is True
    assert store.reconcile_workflow_attempts(stale_after_s=60) == 0
    assert store.list_workflow_tasks("p")[0]["status"] == "running"


def test_workflow_recovery_only_marks_expired_leases_uncertain(tmp_path):
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "workflow-expired-lease.db")
    store.create_mission("m", "objective")
    store.save_workflow_plan(
        "p", WorkflowPlan("m", (WorkflowTask("scan", "cap.scan", "192.0.2.10"),)),
    )
    row = store.claim_ready_workflow_task("p", "worker-dead")
    assert row is not None
    conn = store._conn()
    try:
        conn.execute(
            "UPDATE task_attempts SET heartbeat_at=? WHERE id=?",
            (0, row["attempt_id"]),
        )
    finally:
        conn.close()
    assert store.reconcile_workflow_attempts(stale_after_s=60) == 1
    assert store.list_workflow_tasks("p")[0]["status"] == "uncertain"


def test_provider_capability_evidence_is_sealed_when_job_tool_matches_capability(tmp_path):
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    store = JobStore(tmp_path / "provider-evidence-seal.db")
    mission_id = "provider-mission"
    plan_id = "provider-plan"
    target = "172.28.0.10"
    capability_id = "lab.initial_access.samba_usermap"
    job_id = "provider-access-job"

    store.create_mission(mission_id, "controlled lab provider evidence")
    store.save_workflow_plan(
        plan_id,
        WorkflowPlan(
            mission_id,
            (WorkflowTask(
                "access", capability_id, target, idempotency_key="access-1",
            ),),
        ),
    )
    assert store.start_task_attempt(
        "provider-attempt", "access", 1,
        worker_id="provider-worker", idempotency_key="access-1",
    )

    store.create(job_id)
    store.set_started(job_id, capability_id, target)
    store.append_finding(
        job_id,
        {"kind": "msf_session", "severity": "critical", "source": capability_id,
         "data": {"session_id": "1"}, "raw_line": "controlled lab session"},
        0,
    )
    store.set_finished(job_id, 0, 0.1)
    assert store.finish_task_attempt(
        "provider-attempt", "succeeded",
        result={"job_id": job_id, "target": target, "tool_id": capability_id},
    )

    evidence = store.get_workflow_evidence(plan_id)
    assert evidence["all_evidence_recorded"] is True
    assert evidence["all_evidence_integrity_verified"] is True
    assert evidence["attempts"][0]["integrity_status"] == "verified"
