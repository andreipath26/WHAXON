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
    """SSE-only wrapper. Persistence lives in core.store; this class
    keeps the per-worker subscribe queues for Server-Sent Events."""

    def __init__(self, core: Core) -> None:
        self.core = core
        self.store = core.store
        self._subs: dict[str, list] = {}
        self._lock = threading.RLock()
        self._wire_sse_bridge()

    def _wire_sse_bridge(self) -> None:
        """Bridge core events into SSE subscriber queues. Persistence
        is handled by Core._wire_store, so we only notify subscribers here."""
        def _on_started(e):
            self._notify(e.job_id, {"type": "status", "status": "running",
                                     "tool": e.tool_id, "target": e.target})
        def _on_output(e):
            self._notify(e.job_id, {"type": "line", "stream": e.stream, "text": e.line})
        def _on_finished(e):
            self._notify(e.job_id, {"type": "finished", "exit_code": e.exit_code,
                                     "duration_s": e.duration_s})
            self._notify(e.job_id, None)
        def _on_failed(e):
            self._notify(e.job_id, {"type": "failed", "error": e.error})
            self._notify(e.job_id, None)
        self.core.bus.subscribe(JobStarted, _on_started)
        self.core.bus.subscribe(JobOutput, _on_output)
        self.core.bus.subscribe(JobFinished, _on_finished)
        self.core.bus.subscribe(JobFailed, _on_failed)

    def ensure(self, job_id: str) -> None:
        self.store.create(job_id)

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
        from whaxon.core.events import JobFindings as _JF
        _findings = []
        # Try the adapter layer first (produces enriched findings)
        try:
            from whaxon.adapters import get_adapter as _get_adapter
            _adapter = _get_adapter(tool_id)
            if _adapter is not None:
                _findings = _adapter.parse(collected, ctx={"tool_id": tool_id})
        except Exception as _e:
            import sys
            print(f"[web] adapter error for {tool_id}: {_e!r}", file=sys.stderr)
            _findings = []
        # Fall back to the legacy parser if the adapter gave nothing
        if not _findings:
            from whaxon.core.findings import parse_findings as _pf
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


import shutil as _shutil

def _evidence_dir(core, job_id):
    d = core.data_dir / "evidence" / job_id
    d.mkdir(parents=True, exist_ok=True)
    return d

def create_app(core: Core, registry: JobRegistry, runner: AsyncRunner) -> Flask:
    import os as _os
    _host = _os.environ.get("WHAXON_HOST", "127.0.0.1")
    if _host not in ("127.0.0.1", "::1", "localhost"):
        import sys as _sys
        print(f"  [!] WHAXON_HOST={_host} — server is exposed on a network.\n"
              f"      Basic auth is enforced for non-loopback requests.\n"
              f"      Change WHAXON_AUTH_USER / WHAXON_AUTH_PASS before exposing.",
              file=_sys.stderr)

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
        """Loopback requests are trusted; anything else must authenticate.

        Rationale: a server bound to 127.0.0.1 is only reachable by processes
        on this machine. Requiring basic auth there adds friction (browser
        retry loops in embedded views, GUI shells, curl one-liners) without
        meaningfully improving security. When WHAXON_HOST is set to a
        non-loopback address, the startup warning below tells the operator
        that credentials are the only gate.
        """
        if request.remote_addr in ("127.0.0.1", "::1", "localhost", None):
            return None
        if not _check_auth(request.headers.get("Authorization")):
            return _unauthorized()

    @app.get("/api/health")
    def health_probe():
        """Readiness probe: returns 200 when OK, 503 when MSF is down."""
        import time
        checks = {}
        try:
            checks["msf"] = "up" if registry.core.msf.is_up() else "down"
        except Exception as e:
            checks["msf"] = f"error: {e}"
        try:
            data_dir = Path(os.environ.get("WHAXON_DATA", "data"))
            data_dir.mkdir(parents=True, exist_ok=True)
            probe = data_dir / ".healthz"
            probe.write_text(str(time.time()))
            probe.unlink()
            checks["data"] = "writable"
        except Exception as e:
            checks["data"] = f"error: {e}"
        ok = checks.get("msf") == "up" and checks.get("data") == "writable"
        return jsonify({"status": "ok" if ok else "degraded", "checks": checks}), (200 if ok else 503)

    @app.get("/api/health")
    def health():
        return {"ok": True, "tools": len(core.catalog.list())}

    @app.get("/api/tools")
    def list_tools():
        return jsonify([
            {"id": t.id, "name": t.name, "category": t.category,
             "binary": t.binary, "description": t.description,
             "available": bool(t.available), "package": t.package or ""}
            for t in core.catalog.list()
        ])

    @app.post("/api/run")
    @limiter.limit("30 per minute")
    def run_tool():
        data = request.get_json(silent=True) or {}
        tool_id = data.get("tool_id")
        target = data.get("target")
        extra_args = data.get("extra_args", "") or ""
        allow_override = bool(data.get("allow_out_of_scope", False))
        if not tool_id or not target:
            return {"error": "tool_id and target required"}, 400

        # Scope enforcement
        if not allow_override:
            try:
                match = registry.core.scope.check(target)
            except Exception:
                match = None
            if match is not None and not match.allowed:
                return {"error": f"target out of scope: {match.reason}",
                        "matched_rule": match.matched_rule}, 403
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

    @app.get("/api/jobs/<job_id>/evidence")
    def list_evidence(job_id: str):
        items = registry.core.store.list_evidence(job_id)
        return jsonify(items)

    @app.post("/api/jobs/<job_id>/evidence")
    def add_evidence(job_id: str):
        data = request.get_json(silent=True)
        if data and (data.get("note") or data.get("kind") == "note"):
            seq = registry.core.store.add_evidence(
                job_id, "note", data.get("name", "note"), note=data.get("note", ""))
            return {"seq": seq}, 201
        f = request.files.get("file")
        if f is None:
            return {"error": "provide file (multipart) or {note: ...} JSON"}, 400
        target_dir = _evidence_dir(registry.core, job_id)
        safe_name = Path(f.filename).name
        dest = target_dir / safe_name
        f.save(str(dest))
        seq = registry.core.store.add_evidence(
            job_id, "file", safe_name,
            path=str(dest.relative_to(registry.core.data_dir)),
            note=request.form.get("note", ""))
        return {"seq": seq, "name": safe_name}, 201

    @app.delete("/api/jobs/<job_id>/evidence/<int:seq>")
    def delete_evidence(job_id: str, seq: int):
        ok = registry.core.store.remove_evidence(job_id, seq)
        return {"ok": ok}, (200 if ok else 404)

    @app.get("/api/jobs/<job_id>/evidence/<int:seq>/download")
    def download_evidence(job_id: str, seq: int):
        from flask import send_file
        items = registry.core.store.list_evidence(job_id)
        item = next((x for x in items if x["seq"] == seq), None)
        if not item or not item.get("path"):
            return {"error": "not a file"}, 404
        full = registry.core.data_dir / item["path"]
        if not full.exists():
            return {"error": "file missing"}, 404
        return send_file(str(full), as_attachment=True, download_name=item["name"])

    @app.get("/api/msf/status")
    def msf_status():
        client = registry.core.msf
        up = client.is_up()
        payload = {"up": up, "config": client.config.display()}
        if up:
            try:
                payload["version"] = client.version()
                payload["modules"] = client.module_counts()
            except Exception as e:
                payload["error"] = str(e)
        return jsonify(payload)

    @app.get("/api/msf/sessions")
    def msf_sessions():
        from datetime import datetime
        client = registry.core.msf
        stored = registry.core.store.list_sessions(include_closed=True)
        live = client.sessions() if client.is_up() else {}
        return jsonify({
            "stored": stored,
            "live": live,
            "live_count": len(live),
        })

    @app.post("/api/msf/run")
    def msf_run():
        import uuid as _uuid
        data = request.get_json(silent=True) or {}
        module_type = (data.get("module_type") or "exploit").strip()
        module_path = (data.get("module_path") or "").strip()
        options = data.get("options") or {}
        target = (data.get("target") or options.get("RHOSTS") or "").strip()

        if not module_path:
            return {"error": "module_path required"}, 400
        if module_type not in ("exploit", "auxiliary", "post"):
            return {"error": f"bad module_type: {module_type}"}, 400

        # Scope check — every RHOSTS entry must be in scope
        if not data.get("allow_out_of_scope"):
            candidates = []
            if target:
                candidates.append(target)
            rhosts = options.get("RHOSTS") or options.get("RHOST") or ""
            if rhosts:
                for h in str(rhosts).split(","):
                    h = h.strip()
                    if h and h not in candidates:
                        candidates.append(h)
            for cand in candidates:
                match = registry.core.scope.check(cand)
                if not match.allowed:
                    return {"error": f"target out of scope: {match.reason}",
                            "matched_rule": match.matched_rule,
                            "target": cand}, 403

        # Build the extra args
        extra_parts = [f"{k}={v}" for k, v in options.items()]
        extra_args = " ".join(extra_parts)

        from whaxon.adapters import get_adapter
        adapter = get_adapter("msf")
        if adapter is None:
            return {"error": "msf adapter not registered"}, 500

        job_id = _uuid.uuid4().hex[:12]
        registry.core.store.create(job_id)
        registry.core.store.set_started(job_id, "msf", target or "?")

        # Run in a thread, publish findings like the runner does
        def _do_run():
            import traceback
            from whaxon.core.events import JobFindings, JobFinished, JobFailed, JobOutput
            try:
                tool_id = f"msf:{module_type}:{module_path}"
                registry.core.store.append_line(job_id, "stdout",
                    f"running {tool_id} with {extra_args}")
                findings = adapter.run_module(tool_id, extra_args, ctx={"target": target, "store": registry.core.store, "job_id": job_id})
                for f in findings:
                    if f.kind == "msf_module_started":
                        registry.core.store.append_line(job_id, "stdout", f.raw_line)
                    elif f.kind == "msf_session":
                        registry.core.store.append_line(job_id, "stdout", f.raw_line)
                    elif f.kind == "msf_error":
                        registry.core.store.append_line(job_id, "stderr", f.raw_line)
                if findings:
                    registry.core.store.set_finished(job_id, 0, 0.0)
                    registry.core.bus.publish(JobFindings(
                        job_id=job_id,
                        findings=tuple(f.to_dict() for f in findings),
                    ))
                else:
                    registry.core.store.set_finished(job_id, 0, 0.0)
                registry.core.bus.publish(JobFinished(
                    job_id=job_id, exit_code=0, duration_s=0.0,
                ))
            except Exception as e:
                traceback.print_exc()
                registry.core.store.set_failed(job_id, str(e))
                registry.core.bus.publish(JobFailed(job_id=job_id, error=str(e)))

        import threading as _t
        _t.Thread(target=_do_run, daemon=True).start()

        return {"job_id": job_id}, 202

    @app.post("/api/msf/sessions/<session_id>/exec")
    def msf_session_exec(session_id: str):
        data = request.get_json(silent=True) or {}
        command = (data.get("command") or "").strip()
        if not command:
            return {"error": "command required"}, 400

        client = registry.core.msf
        if not client.is_up():
            return {"error": "msf not reachable"}, 503

        try:
            output = client.session_exec(session_id, command, timeout=15.0)
        except Exception as e:
            return {"error": str(e)}, 500

        return jsonify({
            "session_id": session_id,
            "command": command,
            "output": output,
        })

    @app.get("/api/msf/sessions/<session_id>")
    def msf_session_info(session_id: str):
        client = registry.core.msf
        if not client.is_up():
            return {"error": "msf not reachable"}, 503
        try:
            live = client.sessions()
            info = live.get(str(session_id))
            if info is None:
                return {"error": "session not found"}, 404
            return jsonify({"id": session_id, "info": info})
        except Exception as e:
            return {"error": str(e)}, 500

    @app.get("/api/msf/modules/<module_type>")
    def msf_list_modules(module_type: str):
        client = registry.core.msf
        if not client.is_up():
            return {"error": "msf not reachable"}, 503
        try:
            c = client.connect()
            if module_type == "exploit":
                return jsonify(c.modules.exploits[:200])
            if module_type == "auxiliary":
                return jsonify(c.modules.auxiliary[:200])
            if module_type == "post":
                return jsonify(c.modules.post[:200])
            return {"error": f"bad type: {module_type}"}, 400
        except Exception as e:
            return {"error": str(e)}, 500

    @app.get("/api/tree")
    def get_tree():
        limit = request.args.get("limit", type=int) or 50
        return jsonify({"targets": registry.core.store.findings_by_target(limit=limit)})

    @app.get("/api/scope")
    def get_scope():
        return jsonify(registry.core.scope.summary())

    @app.post("/api/scope/check")
    def check_scope():
        data = request.get_json(silent=True) or {}
        target = (data.get("target") or "").strip()
        if not target:
            return {"error": "target required"}, 400
        match = registry.core.scope.check(target)
        return jsonify(match.to_dict())

    @app.post("/api/scope/override")
    def log_override():
        data = request.get_json(silent=True) or {}
        target = (data.get("target") or "").strip()
        tool = (data.get("tool") or "").strip()
        if not target:
            return {"error": "target required"}, 400
        from datetime import datetime, timezone
        log_path = registry.core.data_dir / "scope_overrides.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()
        with log_path.open("a", encoding="utf-8") as f:
            f.write(f"{ts}\t{tool}\t{target}\n")
        return {"logged": True}

    @app.post("/api/import/burp")
    def import_burp():
        import uuid as _uuid
        f = request.files.get("file")
        if f is None:
            return {"error": "no file provided"}, 400
        if not f.filename.lower().endswith(".xml"):
            return {"error": "expects .xml"}, 400

        # Save to a temp file so the adapter can parse it
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            f.save(tmp.name)
            tmp_path = Path(tmp.name)

        try:
            from whaxon.adapters import get_adapter
            adapter = get_adapter("burp")
            if adapter is None:
                return {"error": "burp adapter not registered"}, 500
            findings = adapter.parse_file(tmp_path)
        finally:
            try: tmp_path.unlink()
            except Exception: pass

        if not findings:
            return {"error": "no findings parsed"}, 400

        job_id = _uuid.uuid4().hex[:12]
        registry.core.store.create(job_id)
        target = findings[0].data.get("host") or "imported"
        registry.core.store.set_started(job_id, "burp", target)
        registry.core.store.append_line(job_id, "stdout",
            f"Imported {len(findings)} finding(s) from {f.filename}")
        for x in findings:
            loc = x.data.get("location") or x.data.get("path") or ""
            registry.core.store.append_line(job_id, "stdout",
                f"  [{x.severity}] {x.data.get('name', '')} {loc}")
        for i, x in enumerate(findings):
            registry.core.store.append_finding(job_id, x.to_dict(), i)
        registry.core.store.set_finished(job_id, 0, 0.0)

        return {"job_id": job_id, "target": target, "count": len(findings)}, 201

    @app.get("/api/jobs/<job_id>/report")
    def get_report(job_id: str):
        from flask import Response
        from whaxon.core.report import render_markdown, render_html
        job = registry.get(job_id)
        if job is None:
            return {"error": "unknown job"}, 404
        findings = registry.get_findings(job_id) or []
        fmt = request.args.get("format", "md")
        if fmt == "html":
            return Response(render_html(job, findings), mimetype="text/html")
        return Response(render_markdown(job, findings), mimetype="text/markdown")

    @app.get("/api/jobs/<job_id>/findings")
    def get_job_findings(job_id: str):
        findings = registry.get_findings(job_id)
        if findings is None:
            return {"error": "unknown job"}, 404
        return jsonify(findings)

    @app.get("/api/status")
    def api_status():
        """Platform-wide safety + capability flags."""
        import os
        scope_enabled = False
        engagement = "default"
        try:
            scope = registry.core.scope
            scope_enabled = bool(scope.enabled)
            engagement = str(scope.engagement or "default")
        except Exception:
            pass
        default_creds = (
            os.environ.get("WHAXON_AUTH_USER", "whaxon") == "whaxon"
            and os.environ.get("WHAXON_AUTH_PASS", "whaxon") == "whaxon"
        )
        autochain = os.environ.get("WHAXON_MSF_AUTOCHAIN", "").strip() in ("1", "true", "yes")
        msf_up = False
        try:
            msf_up = registry.core.msf.is_up()
        except Exception:
            pass
        return jsonify({
            "scope_enabled": scope_enabled,
            "engagement": engagement,
            "default_creds": default_creds,
            "autochain": autochain,
            "msf_up": msf_up,
        })

    # ---------- port forwards ----------

    @app.get("/api/msf/sessions/<session_id>/portfwd")
    def pf_list(session_id: str):
        from whaxon.core import portfwd as _pf
        try:
            live = _pf.list_live(registry.core.msf, session_id)
        except Exception as e:
            return jsonify({"session_id": session_id, "error": str(e), "live": []})
        return jsonify({"session_id": session_id, "live": live})

    @app.post("/api/msf/sessions/<session_id>/portfwd")
    def pf_add(session_id: str):
        from whaxon.core import portfwd as _pf
        data = request.get_json(silent=True) or {}
        lport = data.get("lport"); rhost = data.get("rhost"); rport = data.get("rport")
        label = (data.get("label") or "").strip()
        if lport is None or not rhost or rport is None:
            return {"error": "lport, rhost, rport required"}, 400
        try:
            fwd = _pf.add_forward(registry.core.msf, session_id,
                                  int(lport), str(rhost), int(rport), label)
        except Exception as e:
            return {"error": str(e)}, 500
        try:
            from whaxon.core import pivot as _pivot
            conn = getattr(registry.core.store, "_conn", None)
            if conn is not None:
                _pivot.add_edge(conn,
                                parent_kind="session", parent_id=str(session_id),
                                child_kind="forward", child_id=str(lport),
                                relation="tunnels_via",
                                evidence=f"{rhost}:{rport}")
        except Exception:
            pass
        return jsonify(fwd.to_dict())

    @app.delete("/api/msf/sessions/<session_id>/portfwd")
    def pf_del(session_id: str):
        from whaxon.core import portfwd as _pf
        data = request.get_json(silent=True) or {}
        lport = data.get("lport")
        if lport is None:
            return {"error": "lport required"}, 400
        fwd = _pf.Forward(session_id=session_id, lport=int(lport), rhost="", rport=0)
        return jsonify(_pf.remove_forward(registry.core.msf, fwd))

    @app.get("/api/settings")
    def api_settings_get():
        try:
            return jsonify(registry.core.settings.get())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/settings")
    def api_settings_post():
        data = request.get_json(silent=True) or {}
        try:
            updated = registry.core.settings.save(data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        return jsonify(updated)

    @app.get("/api/pivot/graph")
    def api_pivot_graph():
        from whaxon.core import pivot as _pivot
        try:
            conn = registry.core.store._conn()
        except Exception:
            conn = None
        if conn is None:
            return jsonify({"edges": [], "count": 0})
        try:
            return jsonify(_pivot.graph(conn))
        finally:
            try: conn.close()
            except Exception: pass

    @app.get("/api/pivot/sessions/<session_id>/chain")
    def api_pivot_chain(session_id: str):
        from whaxon.core import pivot as _pivot
        conn = getattr(registry.core.store, "_conn", None)
        if conn is None:
            return jsonify({"session_id": session_id, "root_exploits": [], "descendants": []})
        return jsonify(_pivot.chain_for_session(conn, session_id))

    @app.get("/api/report")
    def api_report():
        """Generate an engagement report.

        Query params:
          engagement=<name>   default: 'default'
          format=md|json      default: 'md'
        """
        from whaxon.core import report as _report
        eng = request.args.get("engagement") or "default"
        fmt = (request.args.get("format") or "md").lower()
        data = _report._load(registry.core.store, eng)
        if fmt == "json":
            return jsonify(data)
        if fmt in ("html", "htm"):
            return render_template("report.html", r=data)
        md = _report.to_markdown(data)
        return app.response_class(md, mimetype="text/markdown")

    @app.get("/api/loot")
    def api_loot():
        """Aggregate loot-kind findings across all jobs, deduped."""
        loot_kinds = {"env_var", "sysinfo", "platform", "ntlm_hash",
                      "service", "msf_session", "msf_loot", "msf_loot_file",
                      "sqlmap_database", "sqlmap_table", "sqlmap_row",
                      "nuclei_finding", "cve", "exploit_suggestion",
                      "network_iface", "system_section"}
        limit = int(request.args.get("limit", 500))
        seen = set()
        out = []
        for job in registry.history(limit=200):
            try:
                findings = registry.get_findings(job["id"]) or []
            except Exception:
                continue
            for f in findings:
                kind = f.get("kind")
                if kind not in loot_kinds:
                    continue
                # dedupe key: (kind, canonical payload)
                d = f.get("data") or {}
                key_parts = [kind]
                for k in ("name", "value", "user", "port", "proto",
                          "session_id", "path", "field", "platform"):
                    if k in d:
                        key_parts.append(str(d[k]))
                key = tuple(key_parts)
                if key in seen:
                    continue
                seen.add(key)
                out.append({**f, "_job_id": job["id"]})
                if len(out) >= limit:
                    break
            if len(out) >= limit:
                break
        return jsonify({"count": len(out), "loot": out})

    @app.get("/api/jobs/<job_id>")
    def get_job(job_id: str):
        job = registry.get(job_id)
        if job is None:
            return {"error": "unknown job"}, 404
        return jsonify(job)

    @app.get("/settings")
    def settings_page():
        from flask import render_template as _rt
        return _rt("settings.html")

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
    registry = JobRegistry(core)
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
    registry = JobRegistry(core)
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
