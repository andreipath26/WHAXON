"""Minimal Flask server for WHAXON. Stage 1: JSON API only."""
from __future__ import annotations

import asyncio
import os
import queue
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from whaxon.core import Core
from whaxon.core.store import JobStore
from whaxon.core.events import (
    JobFailed, JobFinished, JobFindings, JobOutput, JobStarted,
)


class JobRegistry:
    """Thin wrapper over JobStore. Handles SSE subscribers in-worker."""

    def __init__(self, db_path) -> None:
        self.store = JobStore(db_path)
        self._subs: dict[str, list] = {}
        self._lock = threading.RLock()

    def ensure(self, job_id: str) -> None:
        self.store.create(job_id)

    def on_started(self, evt) -> None:
        self.store.set_started(evt.job_id, evt.tool_id, evt.target)
        self._notify(evt.job_id, {"type": "status", "status": "running",
                                   "tool": evt.tool_id, "target": evt.target})

    def on_output(self, evt) -> None:
        self.store.append_line(evt.job_id, evt.stream, evt.line)
        self._notify(evt.job_id, {"type": "line", "stream": evt.stream, "text": evt.line})

    def on_finished(self, evt) -> None:
        self.store.set_finished(evt.job_id, evt.exit_code, evt.duration_s)
        self._notify(evt.job_id, {"type": "finished", "exit_code": evt.exit_code,
                                   "duration_s": evt.duration_s})
        self._notify(evt.job_id, None)

    def on_failed(self, evt) -> None:
        self.store.set_failed(evt.job_id, evt.error)
        self._notify(evt.job_id, {"type": "failed", "error": evt.error})
        self._notify(evt.job_id, None)

    def on_findings(self, evt) -> None:
        for i, f in enumerate(evt.findings):
            self.store.append_finding(evt.job_id, f, i)

    def get(self, job_id: str):
        return self.store.get(job_id)

    def get_findings(self, job_id: str):
        return self.store.get_findings(job_id)

    def history(self, limit: int = 50):
        return self.store.history(limit)

    def subscribe(self, job_id: str):
        import queue as _q
        q = _q.Queue()
        with self._lock:
            self._subs.setdefault(job_id, []).append(q)
        return q

    def unsubscribe(self, job_id: str, q) -> None:
        with self._lock:
            subs = self._subs.get(job_id, [])
            if q in subs:
                subs.remove(q)

    def _notify(self, job_id: str, message) -> None:
        with self._lock:
            subs = list(self._subs.get(job_id, []))
        for q in subs:
            q.put_nowait(message)



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


def _run_job_blocking(core: Core, registry: JobRegistry, tool_id: str, target: str, job_id: str, extra_args: str = "") -> None:
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

    collected: list[tuple[str, str]] = []

    def pump(stream, name):
        if stream is None:
            return
        for line in iter(stream.readline, ""):
            text = line.rstrip("\n")
            collected.append((name, text))
            core.bus.publish(JobOutput(job_id=job_id, stream=name, line=text))

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

    # Parse output into structured findings
    try:
        from whaxon.core.findings import parse_findings as _pf
        from whaxon.core.events import JobFindings as _JF
        _findings = _pf(tool_id, collected)
        if _findings:
            core.bus.publish(_JF(
                job_id=job_id,
                findings=tuple(f.to_dict() for f in _findings),
            ))
    except Exception:
        import traceback
        traceback.print_exc()



def _cancel_job_blocking(job_id: str) -> bool:
    with _PROCS_LOCK:
        proc = _PROCS.get(job_id)
    if proc and proc.poll() is None:
        proc.terminate()
        return True
    return False


import base64 as _b64
import hashlib as _hashlib

try:
    import bcrypt as _bcrypt
except ImportError:
    _bcrypt = None
import os as _os


def _get_credentials() -> tuple[str, str] | None:
    user = _os.environ.get("WHAXON_AUTH_USER", "").strip()
    pw_hash = _os.environ.get("WHAXON_AUTH_PASS_HASH", "").strip()
    if not user or not pw_hash:
        return None
    return user, pw_hash


def _hash_pw(pw: str) -> str:
    """Hash a password. Uses bcrypt if available, otherwise SHA-256."""
    if _bcrypt is not None:
        return _bcrypt.hashpw(pw.encode("utf-8"), _bcrypt.gensalt(rounds=12)).decode("utf-8")
    return _hashlib.sha256(pw.encode("utf-8")).hexdigest()


def _check_auth(header: str | None) -> bool:
    creds = _get_credentials()
    if creds is None:
        return True
    if not header or not header.startswith("Basic "):
        return False
    try:
        decoded = _b64.b64decode(header[6:]).decode("utf-8")
        user, _, pw = decoded.partition(":")
    except Exception:
        return False
    want_user, want_hash = creds
    if user != want_user:
        return False
    # bcrypt hashes start with $2b$ / $2a$ / $2y$
    if want_hash.startswith("$2"):
        if _bcrypt is None:
            return False
        try:
            return _bcrypt.checkpw(pw.encode("utf-8"), want_hash.encode("utf-8"))
        except Exception:
            return False
    # Legacy SHA-256 fallback
    return _hashlib.sha256(pw.encode("utf-8")).hexdigest() == want_hash


def _unauthorized():
    from flask import Response
    return Response(
        "Authentication required.",
        401,
        {"WWW-Authenticate": "Basic realm=\"WHAXON\""},
    )


def create_app(core: Core, registry: JobRegistry, runner: AsyncRunner) -> Flask:
    app = Flask(__name__)
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[],
        storage_uri="memory://",
    )
    app.config["RATELIMIT_STORAGE_URI"] = "memory://"

    @app.before_request
    def _auth_gate():
        from flask import request as _req
        if not _check_auth(_req.headers.get("Authorization")):
            return _unauthorized()

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
    @limiter.limit("30 per minute")
    def run_tool():
        data = request.get_json(silent=True) or {}
        tool_id = data.get("tool_id")
        target = data.get("target")
        extra_args = data.get("extra_args", "") or ""
        if not tool_id or not target:
            return {"error": "tool_id and target required"}, 400
        if core.catalog.get(tool_id) is None:
            return {"error": f"unknown tool: {tool_id}"}, 404
        job_id = uuid.uuid4().hex[:12]
        registry.ensure(job_id)
        runner.submit(lambda: _run_job_blocking(core, registry, tool_id, target, job_id, extra_args))
        return {"job_id": job_id}, 202


    @app.get("/api/jobs/<job_id>/stream")
    def stream_job(job_id: str):
        import json as _json
        from flask import Response

        if registry.get(job_id) is None:
            return {"error": "unknown job"}, 404

        def generate():
            q = registry.subscribe(job_id)
            try:
                current = registry.get(job_id)
                if current:
                    yield f"data: {_json.dumps({'type': 'status', 'status': current['status']})}\n\n"
                    for line in current["lines"]:
                        yield f"data: {_json.dumps({'type': 'line', **line})}\n\n"
                    if current["status"] == "finished":
                        yield f"data: {_json.dumps({'type': 'finished', 'exit_code': current['exit_code']})}\n\n"
                        return
                    if current["status"] == "failed":
                        yield f"data: {_json.dumps({'type': 'failed', 'error': current['error']})}\n\n"
                        return
                while True:
                    try:
                        item = q.get(timeout=30)
                    except queue.Empty:
                        yield ": ping\n\n"
                        continue
                    if item is None:
                        return
                    yield f"data: {_json.dumps(item)}\n\n"
            finally:
                registry.unsubscribe(job_id, q)

        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/history")
    def list_history():
        return jsonify(registry.history())

    @app.get("/api/jobs/<job_id>/findings")
    def get_job_findings(job_id: str):
        findings = registry.get_findings(job_id)
        if findings is None:
            return {"error": "unknown job"}, 404
        return jsonify(findings)

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
        from flask import redirect
        return redirect("/ui")

    return app


def create_app_factory():
    """Gunicorn entry point. No-args factory that reads env vars."""
    os.environ.setdefault("WHAXON_AUTH_USER", "whaxon")
    if "WHAXON_AUTH_PASS_HASH" not in os.environ:
        os.environ["WHAXON_AUTH_PASS_HASH"] = _hash_pw(
            os.environ.get("WHAXON_AUTH_PASS", "whaxon")
        )
    data_dir = Path(os.environ.get("WHAXON_DATA", "data"))
    core = Core(data_dir=data_dir)
    state_path = os.environ.get("WHAXON_STATE", str(data_dir / "whaxon.db"))
    registry = JobRegistry(state_path)
    core.bus.subscribe(JobStarted, registry.on_started)
    core.bus.subscribe(JobOutput, registry.on_output)
    core.bus.subscribe(JobFinished, registry.on_finished)
    core.bus.subscribe(JobFailed, registry.on_failed)
    core.bus.subscribe(JobFindings, registry.on_findings)
    runner = AsyncRunner(core)
    return create_app(core, registry, runner)


def main(args: list[str] | None = None) -> None:
    # Default credentials. Override via env before launch.
    os.environ.setdefault("WHAXON_AUTH_USER", "whaxon")
    if "WHAXON_AUTH_PASS_HASH" not in os.environ:
        os.environ["WHAXON_AUTH_PASS_HASH"] = _hash_pw(
            os.environ.get("WHAXON_AUTH_PASS", "whaxon")
        )
    host = os.environ.get("WHAXON_HOST", "127.0.0.1")
    port = int(os.environ.get("WHAXON_PORT", "5001"))
    data_dir = Path(os.environ.get("WHAXON_DATA", "data"))

    core = Core(data_dir=data_dir)
    state_path = os.environ.get("WHAXON_STATE", str(data_dir / "whaxon.db"))
    registry = JobRegistry(state_path)
    core.bus.subscribe(JobStarted, registry.on_started)
    core.bus.subscribe(JobOutput, registry.on_output)
    core.bus.subscribe(JobFinished, registry.on_finished)
    core.bus.subscribe(JobFailed, registry.on_failed)
    core.bus.subscribe(JobFindings, registry.on_findings)
    runner = AsyncRunner(core)

    app = create_app(core, registry, runner)
    auth_user = os.environ.get("WHAXON_AUTH_USER", "")
    auth_on = "enabled" if auth_user else "DISABLED"
    print()
    print(f"  WHAXON web interface")
    print(f"  → http://{host}:{port}/ui")
    print(f"  → data directory: {data_dir}")
    print(f"  → authentication: {auth_on}" + (f" (user: {auth_user})" if auth_user else ""))
    print()
    if auth_user == "whaxon":
        print("  WARNING: default credentials (whaxon/whaxon) are in use.")
        print("  Change WHAXON_AUTH_USER / WHAXON_AUTH_PASS before exposing on a network.")
        print()
    print(f"  API root: http://{host}:{port}/api/health (requires auth)")
    print()
    app.run(host=host, port=port, debug=False, threaded=True)
