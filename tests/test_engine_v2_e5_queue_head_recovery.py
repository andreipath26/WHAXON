"""E5 recovery: obsolete queue heads must not block unrelated valid work."""
from concurrent.futures import ThreadPoolExecutor

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _queued_pair(tmp_path):
    core = Core(tmp_path)
    core.create_mission("mission", "bounded durable queue regression")
    for index in (1, 2):
        core.save_workflow_plan(
            f"plan-{index}",
            WorkflowPlan(
                "mission",
                (WorkflowTask(
                    f"task-{index}", "unsupported.fixture", f"192.0.2.{index}",
                ),),
            ),
        )
    first = core.enqueue_workflow_run("plan-1")
    second = core.enqueue_workflow_run("plan-2")
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET submitted_at=? WHERE id=?",
            (1.0, first["id"]),
        )
        conn.execute(
            "UPDATE workflow_run_requests SET submitted_at=? WHERE id=?",
            (2.0, second["id"]),
        )
    finally:
        conn.close()
    return core, first, second


def test_e5_corrupt_digest_is_quarantined_without_starving_valid_run(tmp_path):
    core, first, second = _queued_pair(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET plan_digest=? WHERE id=?",
            ("changed-digest", first["id"]),
        )
    finally:
        conn.close()

    restarted = Core(tmp_path)
    claimed = restarted.workflow_requests.claim("healthy-worker")
    assert claimed is not None
    assert claimed["id"] == second["id"]
    assert restarted.workflow_run_request(first["id"])["status"] == "uncertain"
    assert "digest changed" in restarted.workflow_run_request(first["id"])["error"]
    assert restarted.workflow_requests.claim("other-worker") is None


def test_e5_cancelled_head_is_closed_before_claiming_next_request(tmp_path):
    core, first, second = _queued_pair(tmp_path)
    # Simulate a stop barrier saved by another writer before the queue
    # cancellation bookkeeping. Claim must repair the state transactionally.
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_plans SET status='cancel_requested' WHERE id=?",
            ("plan-1",),
        )
    finally:
        conn.close()
    claimed = Core(tmp_path).workflow_requests.claim("healthy-worker")
    assert claimed is not None
    assert claimed["id"] == second["id"]
    first_state = core.workflow_run_request(first["id"])
    assert first_state["status"] == "cancelled"
    assert first_state["completed_at"] is not None


def test_e5_two_workers_cannot_duplicate_claim_after_poisoned_head(tmp_path):
    core, first, second = _queued_pair(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET plan_digest='invalid' WHERE id=?",
            (first["id"],),
        )
    finally:
        conn.close()

    def claim(index):
        return Core(tmp_path).workflow_requests.claim(f"worker-{index}")

    with ThreadPoolExecutor(max_workers=2) as executor:
        rows = list(executor.map(claim, (1, 2)))
    successful = [row for row in rows if row is not None]
    assert len(successful) == 1
    assert successful[0]["id"] == second["id"]
    assert core.workflow_run_request(first["id"])["status"] == "uncertain"


def test_e5_all_invalid_queued_requests_fail_without_fake_success(tmp_path):
    core, first, second = _queued_pair(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET plan_digest='invalid' "
            "WHERE id IN (?,?)",
            (first["id"], second["id"]),
        )
    finally:
        conn.close()
    assert core.workflow_requests.claim("worker") is None
    assert core.workflow_run_request(first["id"])["status"] == "uncertain"
    assert core.workflow_run_request(second["id"])["status"] == "uncertain"


def test_e5_stale_worker_fenced_after_reconciliation_and_next_job_survives(tmp_path):
    core, first, second = _queued_pair(tmp_path)
    claimed = core.workflow_requests.claim("lost-worker")
    assert claimed is not None and claimed["id"] == first["id"]
    token = claimed["lease_token"]

    # Simulate a crashed worker: a stale heartbeat must not authorize a
    # late completion after a separate Core instance reconciles the lease.
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=1 WHERE id=?",
            (first["id"],),
        )
    finally:
        conn.close()
    restarted = Core(tmp_path)
    assert restarted.workflow_requests.reconcile_stale(older_than_s=120) == 1
    assert restarted.workflow_run_request(first["id"])["status"] == "uncertain"
    assert not core.workflow_requests.heartbeat(first["id"], token)
    assert not core.workflow_requests.finish(
        first["id"], token, status="completed",
    )
    assert restarted.workflow_run_request(first["id"])["status"] == "uncertain"
    next_claim = restarted.workflow_requests.claim("replacement-worker")
    assert next_claim is not None and next_claim["id"] == second["id"]
    assert next_claim["lease_token"] != token
    assert "lease_token" not in restarted.workflow_run_request(first["id"])


def test_e5_stale_reconciliation_is_bounded_and_drains_all_batches(tmp_path):
    core = Core(tmp_path)
    core.create_mission("many", "bounded lease reconciliation")
    # Simulate persisted, already-claimed requests with lost worker heartbeats.
    # Every batch must make progress, and a late worker cannot finish a
    # reconciled request. No external tool is invoked.
    conn = core.store._conn()
    try:
        for index in range(133):
            plan_id = f"stale-plan-{index}"
            core.save_workflow_plan(
                plan_id,
                WorkflowPlan("many", (WorkflowTask(
                    f"task-{index}", "unsupported.fixture", "192.0.2.1",
                ),)),
            )
            req = core.enqueue_workflow_run(plan_id)
            claimed = core.workflow_requests.claim(f"worker-{index}")
            assert claimed is not None and claimed["id"] == req["id"]
            conn.execute(
                "UPDATE workflow_run_requests SET heartbeat_at=1 WHERE id=?",
                (req["id"],),
            )
    finally:
        conn.close()
    restarted = Core(tmp_path)
    assert restarted.workflow_requests.reconcile_stale(older_than_s=120) == 128
    assert restarted.workflow_requests.reconcile_stale(older_than_s=120) == 5
    assert restarted.workflow_requests.reconcile_stale(older_than_s=120) == 0
    summary = restarted.workflow_run_queue_summary()
    assert summary["uncertain_count"] == 133
    assert summary["stale_running_count"] == 0


def test_e5_poisoned_backlog_is_bounded_and_eventually_reaches_valid_tail(tmp_path):
    core = Core(tmp_path)
    core.create_mission("large", "bounded poisoned-head recovery")
    # More than the 64-entry quarantine bound: one claim may yield no work,
    # but subsequent polls must reach a valid tail without executing poison.
    conn = core.store._conn()
    try:
        for index in range(66):
            plan_id = f"backlog-{index:03d}"
            core.save_workflow_plan(
                plan_id, WorkflowPlan("large", (WorkflowTask(
                    f"task-{index}", "unsupported.fixture", "192.0.2.1",
                ),)),
            )
            req = core.enqueue_workflow_run(plan_id)
            conn.execute(
                "UPDATE workflow_run_requests SET submitted_at=? WHERE id=?",
                (float(index + 1), req["id"]),
            )
            if index < 65:
                conn.execute(
                    "UPDATE workflow_run_requests SET plan_digest='poison' "
                    "WHERE id=?",
                    (req["id"],),
                )
            else:
                valid_id = req["id"]
    finally:
        conn.close()

    worker = Core(tmp_path)
    assert worker.workflow_requests.claim("worker") is None
    summary = worker.workflow_run_queue_summary()
    assert summary["uncertain_count"] == 64
    assert summary["counts"]["queued"] == 2
    valid = worker.workflow_requests.claim("worker")
    assert valid is not None and valid["id"] == valid_id
    summary = worker.workflow_run_queue_summary()
    assert summary["uncertain_count"] == 65
    assert summary["counts"]["running"] == 1
    assert summary["counts"]["queued"] == 0
    assert worker.workflow_requests.claim("other") is None
    assert worker.workflow_requests.finish(
        valid_id, valid["lease_token"], status="completed",
    )
    assert worker.workflow_run_request(valid_id)["status"] == "completed"


def test_e5_one_shot_drain_reaches_valid_tail_beyond_poison_bound(
    tmp_path, monkeypatch,
):
    import asyncio
    core = Core(tmp_path)
    core.create_mission("many", "one-shot poison recovery")
    for index in range(67):
        plan_id = f"one-shot-{index:03d}"
        core.save_workflow_plan(
            plan_id, WorkflowPlan("many", (WorkflowTask(
                f"task-{index}", "unsupported.fixture", "192.0.2.1",
            ),)),
        )
        req = core.enqueue_workflow_run(plan_id)
        conn = core.store._conn()
        try:
            conn.execute(
                "UPDATE workflow_run_requests SET submitted_at=? WHERE id=?",
                (float(index + 1), req["id"]),
            )
            if index < 66:
                conn.execute(
                    "UPDATE workflow_run_requests SET plan_digest='poison' "
                    "WHERE id=?", (req["id"],),
                )
            else:
                valid_id = req["id"]
        finally:
            conn.close()
    async def incomplete(*args, **kwargs):
        return {"complete": False}
    monkeypatch.setattr(core, "run_workflow_plan", incomplete)
    assert asyncio.run(core.drain_workflow_run_requests(
        max_runs=1, initialized=True,
    )) == 1
    assert core.workflow_run_request(valid_id)["status"] == "incomplete"
    summary = core.workflow_run_queue_summary()
    assert summary["uncertain_count"] == 66
    assert summary["counts"]["queued"] == 0
