"""Real multi-process E3 run-queue adversarial and recovery regressions.

These checks do not execute external tools. They verify that SQLite claims
and uncertain-effect safeguards hold across real Python process boundaries.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _queue(tmp_path):
    core = Core(tmp_path)
    core.create_mission("mission", "controlled recovery regression")
    core.save_workflow_plan(
        "plan",
        WorkflowPlan("mission", (
            WorkflowTask("task", "unsupported.fixture", "192.0.2.10"),
        )),
    )
    return core, core.enqueue_workflow_run("plan")


_CLAIM_SCRIPT = """
import json
import sys
import time
from pathlib import Path
from whaxon.core import Core

directory = Path(sys.argv[1])
gate = Path(sys.argv[2])
worker_id = sys.argv[3]
deadline = time.monotonic() + 15
while not gate.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
if not gate.exists():
    raise SystemExit(4)
row = Core(directory).workflow_requests.claim(worker_id)
print(json.dumps({"id": row["id"] if row else None,
                  "token": row["lease_token"] if row else None}))
"""


def test_real_processes_racing_for_one_request_have_one_owner(tmp_path):
    """Independent processes must never both lease the same request."""
    core, request = _queue(tmp_path)
    gate = tmp_path / "release-workers"
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", _CLAIM_SCRIPT, str(tmp_path),
             str(gate), f"worker-{index}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for index in range(2)
    ]
    try:
        gate.touch()
        results = []
        for process in workers:
            output, errors = process.communicate(timeout=25)
            assert process.returncode == 0, errors
            results.append(json.loads(output.strip()))
        winners = [row for row in results if row["id"] is not None]
        assert len(winners) == 1
        assert winners[0]["id"] == request["id"]
        assert winners[0]["token"]
        assert core.workflow_run_request(request["id"])["status"] == "running"
        assert core.workflow_requests.claim("third-worker") is None
    finally:
        for process in workers:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)


def test_corrupted_request_digest_quarantined_without_dispatch(tmp_path):
    """A queue item cannot silently run after its plan binding changes."""
    core, request = _queue(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET plan_digest=? WHERE id=?",
            ("corrupted-digest", request["id"]),
        )
    finally:
        conn.close()

    fresh = Core(tmp_path)
    assert fresh.workflow_requests.claim("worker") is None
    status = fresh.workflow_run_request(request["id"])
    assert status["status"] == "uncertain"
    assert "digest" in status["error"]
    assert fresh.workflow_requests.claim("second-worker") is None


def test_recovered_uncertain_lease_rejects_original_worker_finish(tmp_path):
    """Recovery fencing survives a Core restart and prevents false success."""
    core, request = _queue(tmp_path)
    claimed = core.workflow_requests.claim("original")
    assert claimed is not None
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=? WHERE id=?",
            (time.time() - 3600, request["id"]),
        )
    finally:
        conn.close()

    recovered = Core(tmp_path)
    assert recovered.workflow_requests.reconcile_stale(
        older_than_s=60,
    ) == 1
    assert not core.workflow_requests.heartbeat(
        request["id"], claimed["lease_token"],
    )
    assert not core.workflow_requests.finish(
        request["id"], claimed["lease_token"], status="completed",
    )
    assert recovered.workflow_run_request(request["id"])["status"] == "uncertain"
    assert recovered.workflow_requests.claim("replacement") is None


def test_multi_client_enqueue_race_has_one_durable_intent(tmp_path):
    """Independent Core instances must deduplicate racing submissions."""
    core, initial = _queue(tmp_path)

    def enqueue(_):
        return Core(tmp_path).enqueue_workflow_run("plan")["id"]

    with ThreadPoolExecutor(max_workers=8) as executor:
        ids = list(executor.map(enqueue, range(16)))
    assert set(ids) == {initial["id"]}
    assert core.workflow_run_request(initial["id"])["status"] == "queued"
