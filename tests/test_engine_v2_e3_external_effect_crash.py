"""E3 real loopback external-effect crash and uncertain-delivery regressions.

Only an in-process loopback HTTP fixture is contacted. This is controlled
network side-effect testing, not a real scanner or production deployment.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from whaxon.core.scheduler import WorkflowScheduler
from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


class _EffectReceiver(BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        self.server.received.append(body)
        self.server.observed.set()
        if self.path == "/disconnect":
            self.close_connection = True
            return
        self.send_response(204)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


class _Receiver:
    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _EffectReceiver)
        self.server.received = []
        self.server.observed = threading.Event()
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True,
        )
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.thread.join(timeout=10)
        self.server.server_close()

    def url(self, path="/accepted"):
        host, port = self.server.server_address
        return f"http://{host}:{port}{path}"


_WORKER = """
import asyncio
import sys
import time
import urllib.request
from pathlib import Path
from whaxon.core.scheduler import WorkflowScheduler
from whaxon.core.store import JobStore

store = JobStore(Path(sys.argv[1]))
marker = Path(sys.argv[2])
url = sys.argv[3]

def dispatch(task):
    request = urllib.request.Request(url, data=b"one-real-side-effect", method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 204
    marker.write_text("http-accepted", encoding="utf-8")
    time.sleep(60)
    return {"success": True}

asyncio.run(WorkflowScheduler(
    store, authorize=lambda task: True, dispatch=dispatch,
).run("plan", max_tasks=1, max_attempts=3))
"""


def _plan(store):
    store.create_mission("mission", "authorized local-only E3 HTTP fixture")
    store.save_workflow_plan(
        "plan", WorkflowPlan("mission", (
            WorkflowTask("task", "fixture", "127.0.0.1", timeout_s=120.0),
        )),
    )


def test_kill_worker_after_real_http_side_effect_never_replays(tmp_path):
    database = tmp_path / "effects.db"
    marker = tmp_path / "http-accepted"
    original = JobStore(database)
    _plan(original)
    with _Receiver() as receiver:
        process = subprocess.Popen(
            [sys.executable, "-c", _WORKER, str(database), str(marker),
             receiver.url()],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        try:
            deadline = time.monotonic() + 15
            while (
                not marker.exists()
                and process.poll() is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.02)
            assert marker.exists(), "HTTP dispatch did not finish before kill"
            assert marker.read_text(encoding="utf-8") == "http-accepted"
            assert receiver.server.observed.is_set()
            assert receiver.server.received == [b"one-real-side-effect"]
        finally:
            if process.poll() is None:
                process.kill()
            _, stderr = process.communicate(timeout=10)
            assert process.returncode is not None, stderr

        restored = JobStore(database)
        attempt = restored.list_workflow_attempts("plan")
        assert len(attempt) == 1 and attempt[0]["status"] == "running"
        conn = restored._conn()
        try:
            conn.execute(
                "UPDATE task_attempts SET heartbeat_at=? WHERE id=?",
                (time.time() - 3600, attempt[0]["id"]),
            )
        finally:
            conn.close()
        assert restored.reconcile_workflow_plan("plan", stale_after_s=60) == 1
        assert restored.get_workflow_readiness("plan")[
            "ready_to_report_success"
        ] is False
        dispatched_again = []

        def forbidden(_task):
            dispatched_again.append(True)
            raise AssertionError("uncertain HTTP effect cannot replay")

        result = asyncio.run(WorkflowScheduler(
            JobStore(database), authorize=lambda task: True, dispatch=forbidden,
        ).run("plan", max_tasks=3))
        assert result["attempts"] == 0
        assert result["tasks"][0]["status"] == "uncertain"
        assert dispatched_again == []
        assert receiver.server.received == [b"one-real-side-effect"]


def test_http_effect_followed_by_disconnected_response_is_uncertain(tmp_path):
    store = JobStore(tmp_path / "disconnect.db")
    _plan(store)
    with _Receiver() as receiver:
        url = receiver.url("/disconnect")

        def dispatch(_task):
            import urllib.request
            request = urllib.request.Request(
                url, data=b"effect-before-disconnect", method="POST",
            )
            with urllib.request.urlopen(request, timeout=5):
                return {"success": True}

        result = asyncio.run(WorkflowScheduler(
            store, authorize=lambda task: True, dispatch=dispatch,
        ).run("plan", max_tasks=3, max_attempts=3))
        assert receiver.server.observed.is_set()
        assert receiver.server.received == [b"effect-before-disconnect"]
        assert result["attempts"] == 1
        assert result["tasks"][0]["status"] == "uncertain"
        retried = asyncio.run(WorkflowScheduler(
            JobStore(store.path), authorize=lambda task: True, dispatch=dispatch,
        ).run("plan", max_tasks=3))
        assert retried["attempts"] == 0
        assert receiver.server.received == [b"effect-before-disconnect"]
