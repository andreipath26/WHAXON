"""Continuous Engine V2 workflow-request worker regression coverage."""
from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.cli.workflow_cmd import _parser


def _core(tmp_path):
    core = Core(tmp_path)
    core.create_mission("m", "worker lifecycle")
    core.save_workflow_plan(
        "p", WorkflowPlan("m", (
            WorkflowTask("scan", "unsupported.fixture", "192.0.2.10"),
        )),
    )
    return core


def test_headless_worker_polls_for_later_arrivals(tmp_path):
    worker = _core(tmp_path)
    submitter = Core(tmp_path)
    stop = threading.Event()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(lambda: asyncio.run(
            worker.serve_workflow_run_requests(
                stop, poll_interval_s=0.05, max_runs_per_batch=1,
            ),
        ))
        # The service starts without work; a distinct Core can later enqueue.
        request = submitter.enqueue_workflow_run("p")
        import time

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if submitter.workflow_run_request(request["id"])["status"] == "completed":
                break
            time.sleep(0.025)
        stop.set()
        processed = future.result(timeout=10)

    assert processed == 1
    assert submitter.workflow_run_request(request["id"])["status"] == "completed"
    assert submitter.workflow_progress("p")["counts"]["blocked"] == 1
    assert not worker.workflow_requests.worker_is_ready()


def test_headless_worker_stops_before_claiming_when_signalled(tmp_path):
    core = _core(tmp_path)
    request = core.enqueue_workflow_run("p")
    stop = threading.Event()
    stop.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(lambda: asyncio.run(
            core.serve_workflow_run_requests(stop, poll_interval_s=0.05),
        )).result(timeout=5) == 0
    assert core.workflow_run_request(request["id"])["status"] == "queued"


def test_worker_recovery_failure_never_advertises_ready(tmp_path, monkeypatch):
    core = _core(tmp_path)

    async def fail_initialize(*, drain=False):
        raise RuntimeError("workflow recovery failed")

    monkeypatch.setattr(core, "initialize", fail_initialize)
    with ThreadPoolExecutor(max_workers=1) as pool, pytest.raises(
        RuntimeError, match="workflow recovery failed",
    ):
        pool.submit(lambda: asyncio.run(
            core.serve_workflow_run_requests(threading.Event()),
        )).result(timeout=5)
    assert not core.workflow_requests.worker_is_ready()


def test_worker_waits_for_run_queue_reconciliation_before_readiness(
    tmp_path, monkeypatch,
):
    core = _core(tmp_path)
    request = core.enqueue_workflow_run("p")
    claimed = core.workflow_requests.claim("crashed-worker")
    connection = core.store._conn()
    try:
        connection.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=? WHERE id=?",
            (time.time() - 1000, request["id"]),
        )
    finally:
        connection.close()

    reconciled = threading.Event()
    allow_startup = threading.Event()
    stop = threading.Event()
    reconcile = core.workflow_requests.reconcile_stale

    def pause_after_reconciliation(**kwargs):
        changed = reconcile(**kwargs)
        reconciled.set()
        assert allow_startup.wait(timeout=5)
        return changed

    monkeypatch.setattr(
        core.workflow_requests, "reconcile_stale", pause_after_reconciliation,
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(lambda: asyncio.run(
            core.serve_workflow_run_requests(stop, poll_interval_s=0.05),
        ))
        assert reconciled.wait(timeout=5)
        assert core.workflow_run_request(request["id"])["status"] == "uncertain"
        assert not core.workflow_requests.worker_is_ready()
        allow_startup.set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not core.workflow_requests.worker_is_ready():
            time.sleep(0.01)
        assert core.workflow_requests.worker_is_ready()
        stop.set()
        assert future.result(timeout=5) == 0

    assert claimed["id"] == request["id"]
    assert not core.workflow_requests.worker_is_ready()


@pytest.mark.parametrize("interval", [0, -1, float("nan"), float("inf"), True, 3601])
def test_headless_worker_rejects_invalid_poll_interval(tmp_path, interval):
    core = _core(tmp_path)
    with ThreadPoolExecutor(max_workers=1) as pool, pytest.raises(
        ValueError, match="poll interval",
    ):
        pool.submit(lambda: asyncio.run(
            core.serve_workflow_run_requests(
                threading.Event(), poll_interval_s=interval,
            ),
        )).result(timeout=5)


def test_headless_worker_cli_argument_contract():
    opts = _parser().parse_args([
        "plan", "serve-requests", "--poll-interval", "0.5",
        "--max-runs-per-batch", "3",
    ])
    assert opts.command == "plan"
    assert opts.plan_command == "serve-requests"
    assert opts.poll_interval == 0.5
    assert opts.max_runs_per_batch == 3


def test_continuous_worker_initializes_only_once(tmp_path, monkeypatch):
    core = _core(tmp_path)
    stop = threading.Event()
    original = core.initialize
    calls = []

    async def counted(*, drain=True):
        calls.append(drain)
        return await original(drain=drain)

    monkeypatch.setattr(core, "initialize", counted)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(lambda: asyncio.run(
            core.serve_workflow_run_requests(stop, poll_interval_s=0.05),
        ))
        import time

        time.sleep(0.22)
        stop.set()
        assert future.result(timeout=5) == 0
    assert calls == [False]


def test_continuous_worker_quickly_handles_stop_with_long_poll(tmp_path):
    core = _core(tmp_path)
    stop = threading.Event()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(lambda: asyncio.run(
            core.serve_workflow_run_requests(stop, poll_interval_s=60),
        ))
        import time

        time.sleep(0.1)
        stop.set()
        assert future.result(timeout=3) == 0



def test_killed_worker_request_requires_reconciliation_before_replay(tmp_path):
    """A real child-process termination cannot silently requeue an effect."""
    import subprocess
    import sys
    import time

    primary = _core(tmp_path)
    request = primary.enqueue_workflow_run("p")
    marker = tmp_path / "claimed.txt"
    program = """
import sys
import time
from pathlib import Path
from whaxon.core import Core
core = Core(Path(sys.argv[1]))
claim = core.workflow_requests.claim("separate-process")
if claim is None:
    raise SystemExit(3)
Path(sys.argv[2]).write_text(claim["id"], encoding="utf-8")
time.sleep(60)
"""
    proc = subprocess.Popen(
        [sys.executable, "-c", program, str(tmp_path), str(marker)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 15
        observed = ""
        # The child creates the marker before write_text finishes writing;
        # existence alone can race with an empty/partial file on CI.
        while proc.poll() is None and time.monotonic() < deadline:
            if marker.is_file():
                observed = marker.read_text(encoding="utf-8")
                if observed == request["id"]:
                    break
            time.sleep(0.05)
        assert observed == request["id"], (
            f"child did not publish the full claimed request ID: {observed!r}"
        )
        assert primary.workflow_run_request(request["id"])["status"] == "running"
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.communicate(timeout=10)

    restarted = Core(tmp_path)
    assert restarted.workflow_requests.claim("restarted-worker") is None
    # Advance the stale-lease clock instead of waiting out a real timeout.
    conn = restarted.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=? WHERE id=?",
            (time.time() - 500, request["id"]),
        )
    finally:
        conn.close()
    assert restarted.workflow_requests.reconcile_stale(older_than_s=60) == 1
    assert restarted.workflow_run_request(request["id"])["status"] == "uncertain"
    assert restarted.workflow_requests.claim("restarted-worker") is None



def test_graceful_stop_prevents_claiming_remainder_of_current_batch(tmp_path, monkeypatch):
    """A SIGTERM-like event stops NEW claims, not the current execution."""
    core = _core(tmp_path)
    core.save_workflow_plan(
        "p2", WorkflowPlan("m", (
            WorkflowTask("scan2", "unsupported.fixture", "192.0.2.11"),
        )),
    )
    first = core.enqueue_workflow_run("p")
    second = core.enqueue_workflow_run("p2")
    stop = threading.Event()
    called = []

    async def complete_one(plan_id, **_kwargs):
        called.append(plan_id)
        stop.set()
        return {"complete": True}

    monkeypatch.setattr(core, "run_workflow_plan", complete_one)
    with ThreadPoolExecutor(max_workers=1) as pool:
        total = pool.submit(lambda: asyncio.run(
            core.serve_workflow_run_requests(
                stop, poll_interval_s=0.05, max_runs_per_batch=20,
            ),
        )).result(timeout=10)

    assert total == 1
    assert called == ["p"]
    assert core.workflow_run_request(first["id"])["status"] == "completed"
    assert core.workflow_run_request(second["id"])["status"] == "queued"


def test_drain_refuses_new_claims_after_stop_without_changing_queue(tmp_path):
    core = _core(tmp_path)
    queued = core.enqueue_workflow_run("p")
    stop = threading.Event()
    stop.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        count = pool.submit(lambda: asyncio.run(
            core.drain_workflow_run_requests(stop_event=stop),
        )).result(timeout=10)

    assert count == 0
    assert core.workflow_run_request(queued["id"])["status"] == "queued"


def test_drain_rejects_invalid_stop_object(tmp_path):
    core = _core(tmp_path)
    with ThreadPoolExecutor(max_workers=1) as pool, pytest.raises(
        TypeError, match="stop_event",
    ):
        pool.submit(lambda: asyncio.run(
            core.drain_workflow_run_requests(stop_event=object()),
        )).result(timeout=10)


def test_e5_worker_poll_uses_monotonic_deadline(tmp_path, monkeypatch):
    """Scheduler delays must not accumulate into longer polling intervals."""
    core = _core(tmp_path)
    stop = threading.Event()
    observed = []
    original = core.drain_workflow_run_requests

    async def observe(**kwargs):
        observed.append(asyncio.get_running_loop().time())
        if len(observed) == 3:
            stop.set()
        return await original(**kwargs)

    monkeypatch.setattr(core, "drain_workflow_run_requests", observe)
    with ThreadPoolExecutor(max_workers=1) as pool:
        count = pool.submit(lambda: asyncio.run(
            core.serve_workflow_run_requests(
                stop, poll_interval_s=0.05, max_runs_per_batch=1,
            ),
        )).result(timeout=5)
    assert count == 0
    assert len(observed) == 3
    assert observed[1] >= observed[0]
    assert observed[2] >= observed[1]


def test_e5_headless_cli_exposes_shared_run_snapshot_contract():
    options = _parser().parse_args([
        "plan", "run-snapshot", "--id", "persisted-request",
    ])
    assert options.plan_command == "run-snapshot"
    assert options.id == "persisted-request"


def test_e5_drain_reconciles_all_stale_leases_before_new_claims(tmp_path, monkeypatch):
    core = _core(tmp_path)
    calls = []
    original = core.workflow_requests.reconcile_stale

    def reconcile(*args, **kwargs):
        calls.append("reconcile")
        # Simulate more than one bounded 128-row reconciliation pass.
        return 128 if len(calls) == 1 else 5 if len(calls) == 2 else original(
            *args, **kwargs,
        )

    monkeypatch.setattr(core.workflow_requests, "reconcile_stale", reconcile)
    queued = core.enqueue_workflow_run("p")
    stop = threading.Event()
    stop.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(lambda: asyncio.run(core.drain_workflow_run_requests(
            max_runs=1, initialized=True, stop_event=stop,
        ))).result(timeout=10) == 0
    assert calls == ["reconcile"]
    assert core.workflow_run_request(queued["id"])["status"] == "queued"

    stop.clear()
    original_claim = core.workflow_requests.claim
    def claim(owner):
        calls.append("claim")
        return original_claim(owner)
    monkeypatch.setattr(core.workflow_requests, "claim", claim)
    async def incomplete(*args, **kwargs):
        return {"complete": False}
    monkeypatch.setattr(core, "run_workflow_plan", incomplete)
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(lambda: asyncio.run(core.drain_workflow_run_requests(
            max_runs=1, initialized=True, stop_event=stop,
        ))).result(timeout=10) == 1
    assert calls[-3:] == ["reconcile", "reconcile", "claim"]
    assert core.workflow_run_request(queued["id"])["status"] == "incomplete"


def test_e5_one_shot_claim_retry_is_bounded_under_poisoned_producer(
    tmp_path, monkeypatch,
):
    core = _core(tmp_path)
    attempts = []
    monkeypatch.setattr(
        core.workflow_requests, "claim",
        lambda owner: attempts.append(owner) or None,
    )
    monkeypatch.setattr(
        core.workflow_requests, "queued_count", lambda: 1,
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(lambda: asyncio.run(core.drain_workflow_run_requests(
            max_runs=1, initialized=True,
        ))).result(timeout=10) == 0
    assert len(attempts) == 16
