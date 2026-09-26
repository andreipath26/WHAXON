"""Minimal Flask server for BACKFORGE. Stage 1: JSON API only."""
from __future__ import annotations

import asyncio
import os
import threading
import uuid
from pathlib import Path

from flask import Flask, jsonify, request

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
    """Runs the core's asyncio loop in a background thread."""

    def __init__(self, core: Core) -> None:
        self.core = core
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.core.bus.bind_loop(self.loop)
        self.loop.run_forever()

    def submit(self, coro) -> "asyncio.Future":
        return asyncio.run_coroutine_threadsafe(coro, self.loop)


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
        runner.submit(core.runner.run_tool(tool_id=tool_id, target=target, job_id=job_id))
        return {"job_id": job_id}, 202

    @app.get("/api/jobs/<job_id>")
    def get_job(job_id: str):
        job = registry.get(job_id)
        if job is None:
            return {"error": "unknown job"}, 404
        return jsonify(job)

    @app.get("/")
    def index():
        tools = [{"id": t.id, "name": t.name, "category": t.category}
                 for t in core.catalog.list()]
        return {"service": "BACKFORGE", "stage": 1, "tools": tools}

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
