"""Controlled E3 process-kill acceptance: a dispatch that may have effects.

A child executes a test callback, not an external scanner. The parent kills
the worker after the callback has started and verifies that stale execution
cannot be silently replayed by a new process.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from whaxon.core.scheduler import WorkflowScheduler
from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowPlan, WorkflowTask

_WORKER = """
import asyncio
import sys
import time
from pathlib import Path
from whaxon.core.scheduler import WorkflowScheduler
from whaxon.core.store import JobStore

store = JobStore(Path(sys.argv[1]))
marker = Path(sys.argv[2])

def may_have_effects(task):
    complete = marker.with_name(marker.name + ".writing")
    complete.write_text(task.id, encoding="utf-8")
    complete.replace(marker)
    time.sleep(60)
    return {"success": True}

asyncio.run(WorkflowScheduler(
    store, authorize=lambda task: True, dispatch=may_have_effects,
).run("plan", max_tasks=1, max_attempts=5))
"""


def test_hard_kill_after_dispatch_requires_manual_reconciliation(tmp_path):
    """Kill a real process after dispatch, then enforce no unsafe replay."""
    database = tmp_path / "process-crash.db"
    marker = tmp_path / "effect-started"
    store = JobStore(database)
    store.create_mission("mission", "controlled process-kill verification")
    store.save_workflow_plan(
        "plan", WorkflowPlan("mission", (
            WorkflowTask(
                "scan", "fixture", "192.0.2.10", timeout_s=120.0,
            ),
        )),
    )

    worker = subprocess.Popen(
        [sys.executable, "-c", _WORKER, str(database), str(marker)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        deadline = time.monotonic() + 15.0
        while not marker.exists() and worker.poll() is None and time.monotonic() < deadline:
            time.sleep(0.025)
        assert marker.exists(), "child never reached dispatch; inspect stderr"
        assert marker.read_text(encoding="utf-8") == "scan"
    finally:
        if worker.poll() is None:
            worker.kill()
        _, stderr = worker.communicate(timeout=10)
        assert worker.returncode is not None, stderr

    after = JobStore(database)
    running = after.list_workflow_attempts("plan")
    assert len(running) == 1
    assert running[0]["status"] == "running"

    # Advance the dead worker's heartbeat deterministically; the wall-clock
    # test must not wait for the production stale threshold to expire.
    conn = after._conn()
    try:
        conn.execute(
            "UPDATE task_attempts SET heartbeat_at=? WHERE id=?",
            (time.time() - 3600, running[0]["id"]),
        )
    finally:
        conn.close()

    assert after.reconcile_workflow_plan("plan", stale_after_s=60) == 1
    attempts = after.list_workflow_attempts("plan")
    assert attempts[0]["status"] == "uncertain"
    assert "uncertain" in attempts[0]["error"]
    assert after.get_workflow_readiness("plan")["ready_to_report_success"] is False

    unexpectedly_dispatched = []

    async def forbidden(_task):
        unexpectedly_dispatched.append(True)
        raise AssertionError("unknown outcome must never be replayed")

    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(
            lambda: asyncio.run(WorkflowScheduler(
                JobStore(database), authorize=lambda task: True,
                dispatch=forbidden,
            ).run("plan", max_tasks=5, max_attempts=5)),
        ).result(timeout=15)
    assert result["attempts"] == 0
    assert unexpectedly_dispatched == []
    assert result["tasks"][0]["status"] == "uncertain"
