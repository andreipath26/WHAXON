"""E5 process-boundary worker claim racing on a shared durable queue."""
from __future__ import annotations

import json
import subprocess
import sys
import time

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask

CHILD = """
import asyncio
import json
import sys
import time
from pathlib import Path
from whaxon.core import Core

state, ready, release = map(Path, sys.argv[1:4])
worker = Core(state)
ready.write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 15
while not release.exists():
    if time.monotonic() > deadline:
        raise SystemExit("worker start barrier timed out")
    time.sleep(0.01)
count = asyncio.run(worker.drain_workflow_run_requests(max_runs=1))
print(json.dumps({"processed": count}), flush=True)
"""


def test_e5_two_independent_workers_can_claim_each_request_only_once(tmp_path):
    source = Core(tmp_path)
    source.create_mission("m", "bounded multi-process claim proof")
    source.save_workflow_plan(
        "p", WorkflowPlan("m", (
            WorkflowTask("task", "unsupported.fixture", "192.0.2.10"),
        )),
    )
    request = source.enqueue_workflow_run("p")
    release = tmp_path / "release"
    workers = []
    try:
        for index in range(2):
            ready = tmp_path / f"ready-{index}"
            process = subprocess.Popen(
                [
                    sys.executable, "-c", CHILD,
                    str(tmp_path), str(ready), str(release),
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            workers.append((process, ready))
        deadline = time.monotonic() + 20
        while not all(ready.exists() for _, ready in workers):
            assert time.monotonic() < deadline, "workers failed to become ready"
            assert all(process.poll() is None for process, _ in workers)
            time.sleep(0.02)
        release.write_text("go", encoding="utf-8")
        counts = []
        for process, _ in workers:
            out, err = process.communicate(timeout=30)
            assert process.returncode == 0, err
            counts.append(json.loads(out.strip())["processed"])
        assert sorted(counts) == [0, 1]
        assert source.workflow_run_request(request["id"])["status"] == "completed"
        assert source.workflow_progress("p")["counts"]["blocked"] == 1
        assert source.workflow_requests.claim("unexpected-third-worker") is None
    finally:
        for process, _ in workers:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
