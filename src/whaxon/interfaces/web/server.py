"""Minimal Flask server for BACKFORGE. Stage 1: JSON API only."""
from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from whaxon.core import Core
from whaxon.core.events import (
    JobFailed, JobFinished, JobOutput, JobStarted,
)


class JobRegistry:
    """Thread-safe accumulator of job events for HTTP polling."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, dict] = {}

    def ensure(self, job_id: str) -> dict:
        with self._lock:
            return self._jobs.setdefault(job_id, {
                "id": job_id, "status": "starting", "tool": "", "target": "",
                "lines": [], "exit_code": None, "error": None,
            })

    def on_started(self, evt: JobStarted) -> None:
        import sys; print(f"[registry] on_started job_id={evt.job_id}", file=sys.stderr, flush=True)
        with self._lock:
            j = self.ensure(evt.job_id)
            j["status"] = "running"
            j["tool"] = evt.tool_id
            j["target"] = evt.target

    def on_output(self, evt: JobOutput) -> None:
        with self._lock:
            self.ensure(evt.job_id)["lines"].append(
                {"stream": evt.stream, "text": evt.line})

    def on_finished(self, evt: JobFinished) -> None:
        with self._lock:
            j = self.ensure(evt.job_id)
            j["status"] = "finished"
            j["exit_code"] = evt.exit_code

    def on_failed(self, evt: JobFailed) -> None:
        with self._lock:
            j = self.ensure(evt.job_id)
            j["status"] = "failed"
            j["error"] = evt.error

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            j = self._jobs.get(job_id)
            if j is None:
                return None
            return {**j, "lines": list(j["lines"])}


class AsyncRunner:
    """Run tools in background threads. Avoids asyncio subprocess issues on
    non-main-thread loops (Python 3.13). Publishes events to the core bus
    using the bus's own thread-safety."""

    def __init__(self, core: Core) -> None:
        self.core = core

    def submit(self, coro_factory) -> None:
        """Accept a zero-arg callable that runs the job and returns a job_id."""
        t = threading.Thread(target=self._wrap, args=(coro_factory,), daemon=True)
        t.start()

    def _wrap(self, coro_factory) -> None:
        import traceback
        try:
            coro_factory()
        except Exception:
            traceback.print_exc()


_PROCS: dict[str, "subprocess.Popen"] = {}
_PROCS_LOCK = threading.Lock()


def _run_job_blocking(core: Core, registry: JobRegistry, tool_id: str, target: str, job_id: str) -> None:
    """Run a tool synchronously in a thread. Publishes events to the bus."""
    import subprocess
    from whaxon.core.events import JobStarted, JobOutput, JobFinished, JobFailed

    tool = core.catalog.get(tool_id)
    if tool is None:
        core.bus.publish(JobFailed(job_id=job_id, error=f"unknown tool: {tool_id}"))
        return

    argv = core.runner.build_argv(tool_id, target)
    core.bus.publish(JobStarted(job_id=job_id, tool_id=tool_id, target=target))
    start = time.monotonic()

    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
    except FileNotFoundError as e:
        core.bus.publish(JobFailed(job_id=job_id, error=f"tool not found: {e}"))
        return

    with _PROCS_LOCK:
        _PROCS[job_id] = proc

    def pump(stream, name):
        if stream is None:
            return
        for line in iter(stream.readline, ""):
            core.bus.publish(JobOutput(job_id=job_id, stream=name, line=line.rstrip("\n")))

    t_out = threading.Thread(target=pump, args=(proc.stdout, "stdout"), daemon=True)
    t_err = threading.Thread(target=pump, args=(proc.stderr, "stderr"), daemon=True)
    t_out.start(); t_err.start()
    proc.wait()
    t_out.join(timeout=2); t_err.join(timeout=2)

    with _PROCS_LOCK:
        _PROCS.pop(job_id, None)

    core.bus.publish(JobFinished(
        job_id=job_id,
        exit_code=proc.returncode or 0,
        duration_s=time.monotonic() - start,
    ))


def _cancel_job_blocking(job_id: str) -> bool:
    with _PROCS_LOCK:
        proc = _PROCS.get(job_id)
    if proc and proc.poll() is None:
        proc.terminate()
        return True
    return False


def create_app(core: Core, registry: JobRegistry, runner: AsyncRunner) -> Flask:
    app = Flask(__name__)

    @app.get("/api/health")
    def health():
        return {"ok": True, "tools": len(core.catalog.list())}

    @app.get("/api/tools")
    def list_tools():
        return jsonify([
            {"id": t.id, "name": t.name, "category": t.category,
             "binary": t.binary, "description": t.description}
            for t in core.catalog.list()
        ])

    @app.post("/api/run")
    def run_tool():
        data = request.get_json(silent=True) or {}
        tool_id = data.get("tool_id")
        target = data.get("target")
        if not tool_id or not target:
            return {"error": "tool_id and target required"}, 400
        if core.catalog.get(tool_id) is None:
            return {"error": f"unknown tool: {tool_id}"}, 404
        job_id = uuid.uuid4().hex[:12]
        registry.ensure(job_id)
        runner.submit(lambda: _run_job_blocking(core, registry, tool_id, target, job_id))
        return {"job_id": job_id}, 202

    @app.get("/api/jobs/<job_id>")
    def get_job(job_id: str):
        job = registry.get(job_id)
        if job is None:
            return {"error": "unknown job"}, 404
        return jsonify(job)

    @app.get("/ui")
    def ui():
        return render_template("index.html")

    @app.post("/api/jobs/<job_id>/cancel")
    def cancel_job(job_id: str):
        ok = _cancel_job_blocking(job_id)
        return {"ok": ok, "job_id": job_id}

    @app.get("/")
    def index():
        tools = [{"id": t.id, "name": t.name, "category": t.category}
                 for t in core.catalog.list()]
        return {"service": "BACKFORGE", "stage": 2, "ui": "/ui", "tools": tools}

    return app


def main(args: list[str] | None = None) -> None:
    host = os.environ.get("BACKFORGE_HOST", "127.0.0.1")
    port = int(os.environ.get("BACKFORGE_PORT", "5001"))
    data_dir = Path(os.environ.get("BACKFORGE_DATA", "data"))

    core = Core(data_dir=data_dir)
    registry = JobRegistry()
    core.bus.subscribe(JobStarted, registry.on_started)
    core.bus.subscribe(JobOutput, registry.on_output)
    core.bus.subscribe(JobFinished, registry.on_finished)
    core.bus.subscribe(JobFailed, registry.on_failed)
    runner = AsyncRunner(core)

    app = create_app(core, registry, runner)
    print(f"BACKFORGE web on http://{host}:{port}/  (data: {data_dir})")
    app.run(host=host, port=port, debug=False, threaded=True)
