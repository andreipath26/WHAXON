"""Minimal Flask server for WHAXON. Stage 1: JSON API only."""
from __future__ import annotations

import asyncio
import os
import queue
import re
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import ValidationError

from whaxon.core import Core
from whaxon.core.events import (
    JobFailed,
    JobFindings,
    JobFinished,
    JobOutput,
    JobStarted,
)
from whaxon.interfaces.web.api_contracts import (
    DeadlineRequest,
    ExecutionLimitsRequest,
    MissionCostLimitRequest,
    RateLimitRequest,
    WorkflowApprovalGrantRequest,
    WorkflowAttemptReconciliationRequest,
    WorkflowEventAcknowledgement,
    WorkflowEventAcknowledgementResult,
    WorkflowFindingProposalRequest,
    WorkflowPlanReconciliationRequest,
    WorkflowRunAccepted,
    WorkflowRunRequest,
    WorkflowToolProposalRequest,
)


def _v2_worker_externally_supervised() -> bool:
    """Do not drain durable V2 work from web when a service worker is active."""
    return os.environ.get("WHAXON_V2_EXTERNAL_WORKER", "").strip() == "1"


def _check_execution_scope(scope, target):
    """Use the scope manager's DNS-safe execution gate when available."""
    checker = getattr(scope, "check_for_execution", None)
    return checker(target) if callable(checker) else scope.check(target)


def _request_actor() -> str:
    """Resolve audit identity from the authenticated request, never its body."""
    if request.remote_addr in ("127.0.0.1", "::1"):
        return "local"
    auth = request.authorization
    return auth.username if auth and auth.username else "authenticated-operator"


def _legacy_ai_execution_enabled() -> bool:
    return os.environ.get(
        "WHAXON_LEGACY_AI_EXECUTION_ENABLED", "false",
    ).strip().lower() in ("1", "true", "yes")


def _legacy_msf_execution_enabled() -> bool:
    return os.environ.get(
        "WHAXON_LEGACY_MSF_EXECUTION_ENABLED", "false",
    ).strip().lower() in ("1", "true", "yes")


def _legacy_validation_enabled() -> bool:
    return os.environ.get(
        "WHAXON_LEGACY_VALIDATION_ENABLED", "false",
    ).strip().lower() in ("1", "true", "yes")


def _redact_sensitive_settings(value: Any) -> Any:
    """Return a JSON-safe settings view without disclosing secret values."""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if re.search(
                r"secret|token|password|passwd|passphrase|credential|private.?key|api.?key|authorization|bearer|access.?key|client.?secret|cookie|session.?key",
                str(key),
                re.IGNORECASE,
            ):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_sensitive_settings(item)
        return redacted
    if isinstance(value, (list, tuple)):
        return [_redact_sensitive_settings(item) for item in value]
    return value


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
        q: _q.Queue = _q.Queue()
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


_PROCS: dict[str, subprocess.Popen] = {}
_RUN_LOOPS: dict[str, asyncio.AbstractEventLoop] = {}
_PROCS_LOCK = threading.Lock()


def _ai_run_blocking(core, executor_factory, run_id, goal, store):
    """Run the AI executor in a background thread, recording steps."""
    import asyncio as _aio
    import traceback as _tb
    provider_name = "null"
    try:
        ex = executor_factory()
        provider_name = getattr(getattr(ex, "agent", None), "provider", None)
        provider_name = getattr(provider_name, "name", "null") or "null"
        seq = {"n": 0}
        def on_action(a):
            pass
        def on_result(r):
            seq["n"] += 1
            store.append_ai_run_step(run_id, seq["n"], r.action.to_dict(), r.to_dict())
        ex.on_result = on_result
        history = _aio.run(ex.run(goal, job_id_prefix=run_id))
        last_err = ""
        if history and not history[-1].ok:
            last_err = history[-1].error or ""
        store.set_ai_run_finished(run_id, status="done" if not last_err else "failed", error=last_err)
    except Exception as e:
        _tb.print_exc()
        store.set_ai_run_finished(run_id, status="error", error=repr(e))

def _run_job_blocking(
    core: Core, registry: JobRegistry, tool_id: str, target: str,
    job_id: str, extra_args: str = "",
) -> None:
    """Execute web-submitted jobs through the same guarded core runner as the CLI."""
    import asyncio

    from whaxon.core.events import JobFailed
    from whaxon.core.scope import OutOfScopeError

    loop = asyncio.new_event_loop()
    try:
        try:
            timeout_s = float(_os.environ.get("WHAXON_JOB_TIMEOUT_S", "900"))
        except (TypeError, ValueError):
            timeout_s = 900.0
        if timeout_s <= 0:
            timeout_s = 900.0
        with _PROCS_LOCK:
            _RUN_LOOPS[job_id] = loop
        asyncio.set_event_loop(loop)
        loop.run_until_complete(core.runner.run_tool(
            tool_id=tool_id,
            target=target,
            job_id=job_id,
            extra_args=extra_args,
            timeout_s=timeout_s,
            phase="web",
        ))
    except OutOfScopeError as exc:
        core.bus.publish(JobFailed(job_id=job_id, error=f"target blocked by scope: {exc}"))
    except FileNotFoundError:
        # ToolRunner already publishes JobFailed for missing executables.
        return
    except Exception as exc:
        import traceback
        traceback.print_exc()
        core.bus.publish(JobFailed(job_id=job_id, error=f"job execution failed: {exc}"))
    finally:
        with _PROCS_LOCK:
            _RUN_LOOPS.pop(job_id, None)
        asyncio.set_event_loop(None)
        loop.close()



def _cancel_job_blocking(core: Core, job_id: str) -> bool:
    """Cancel through the job's owning event loop to clean up its process tree."""
    import asyncio

    with _PROCS_LOCK:
        loop = _RUN_LOOPS.get(job_id)
    proc = core.runner._procs.get(job_id)
    if loop is None or proc is None:
        return False
    if not getattr(loop, "is_running", lambda: False)():
        return False
    future = asyncio.run_coroutine_threadsafe(core.runner.cancel(job_id), loop)
    try:
        future.result(timeout=5)
        return True
    except Exception:
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


def _remote_auth_ready(user: str, password: str, password_hash: str) -> bool:
    """Require non-default credentials and bcrypt for network-facing deployments."""
    if not user or user == "whaxon":
        return False
    if password_hash:
        if _bcrypt is None:
            return False
        parts = password_hash.split("$")
        if len(parts) != 4:
            return False
        if parts[1] not in {"2a", "2b", "2y"}:
            return False
        if not parts[2].isdigit() or int(parts[2]) < 12:
            return False
        return len(password_hash) == 60
    return bool(password and password != "whaxon" and _bcrypt is not None)


def _check_auth(header: str | None) -> bool:
    creds = _get_credentials()
    # Missing credentials must never disable authentication implicitly.
    if creds is None:
        return False
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



_FAIL_COUNTS: dict[str, tuple[int, float]] = {}
_TOO_MANY_FAILURES = 5
_TOO_MANY_WINDOW_S = 60.0


def _too_many_requests():
    from flask import Response
    return Response(
        "Too many failed authentication attempts.",
        429,
        {"Retry-After": str(int(_TOO_MANY_WINDOW_S))},
    )


def _record_auth_failure(peer: str) -> None:
    import time
    now = time.time()
    count, first = _FAIL_COUNTS.get(peer, (0, now))
    if now - first > _TOO_MANY_WINDOW_S:
        count, first = 0, now
    _FAIL_COUNTS[peer] = (count + 1, first)


def _auth_failures_exceeded(peer: str) -> bool:
    import time
    now = time.time()
    count, first = _FAIL_COUNTS.get(peer, (0, now))
    if now - first > _TOO_MANY_WINDOW_S:
        return False
    return count >= _TOO_MANY_FAILURES


def _unauthorized():
    from flask import Response
    return Response(
        "Authentication required.",
        401,
        {"WWW-Authenticate": "Basic realm=\"WHAXON\""},
    )



def _evidence_dir(core, job_id):
    """Return a job-specific evidence directory contained inside data/evidence."""
    import re

    if not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", job_id):
        raise ValueError("invalid job id for evidence storage")
    data_root = Path(core.data_dir).resolve()
    evidence_root = data_root / "evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    evidence_root = evidence_root.resolve()
    if not evidence_root.is_relative_to(data_root):
        raise ValueError("evidence directory resolves outside the data directory")
    job_dir = evidence_root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    job_dir = job_dir.resolve()
    if not job_dir.is_relative_to(evidence_root):
        raise ValueError("job evidence directory resolves outside the evidence directory")
    return job_dir


def _resolve_evidence_path(core, relative_path):
    """Resolve a stored evidence path and reject traversal or symlink escapes."""
    if not isinstance(relative_path, str) or not relative_path:
        raise ValueError("evidence path is missing")
    data_root = Path(core.data_dir).resolve()
    full_path = (data_root / relative_path).resolve()
    if not full_path.is_relative_to(data_root):
        raise ValueError("evidence path resolves outside the data directory")
    return full_path

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
    # Only trust forwarded client metadata when an operator explicitly enables
    # it for a known reverse proxy. This lets Origin validation work correctly
    # behind HTTPS without trusting spoofable headers on direct deployments.
    if _os.environ.get("WHAXON_TRUST_PROXY", "").strip().lower() in {"1", "true", "yes"}:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    try:
        max_upload_mb = int(_os.environ.get("WHAXON_MAX_UPLOAD_MB", "25"))
    except ValueError:
        max_upload_mb = 25
    if not 1 <= max_upload_mb <= 1024:
        max_upload_mb = 25
    app.config["MAX_CONTENT_LENGTH"] = max_upload_mb * 1024 * 1024
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per minute"],
        storage_uri="memory://",
    )
    app.config["RATELIMIT_STORAGE_URI"] = "memory://"

    @app.before_request
    def _auth_gate():
        """Protect state-changing routes from cross-origin browser requests.

        Loopback is a useful local-development trust boundary, but browsers can
        be induced by an unrelated website to send requests to localhost. Check
        the Host header to resist DNS-rebinding and validate browser Origin /
        Fetch Metadata before applying the local-peer authentication shortcut.
        """
        import ipaddress as _ipaddress
        from urllib.parse import urlsplit as _urlsplit

        configured_host = _os.environ.get("WHAXON_HOST", "127.0.0.1")
        try:
            loopback_listener = _ipaddress.ip_address(configured_host.strip("[]")).is_loopback
        except ValueError:
            loopback_listener = configured_host.lower() == "localhost"

        # Also apply the host check to loopback clients when the server is
        # bound to 0.0.0.0/::; otherwise a local browser can reach that listener
        # through an attacker-controlled DNS-rebinding hostname.
        if loopback_listener or request.remote_addr in ("127.0.0.1", "::1"):
            request_host = request.host
            if request_host.startswith("[") and "]" in request_host:
                request_hostname = request_host[1:request_host.index("]")]
            elif request_host.count(":") == 1:
                request_hostname = request_host.rsplit(":", 1)[0]
            else:
                request_hostname = request_host
            allowed_hosts = {"localhost", "127.0.0.1", "::1"}
            allowed_hosts.update(
                item.strip().lower().rstrip(".")
                for item in _os.environ.get("WHAXON_ALLOWED_HOSTS", "").split(",")
                if item.strip()
            )
            if request_hostname.lower().rstrip(".") not in allowed_hosts:
                return {"error": "invalid Host for local request"}, 403

        fetch_site = request.headers.get("Sec-Fetch-Site", "").lower()
        if fetch_site in {"cross-site", "same-site"}:
            return {"error": "cross-origin browser request rejected"}, 403
        origin = request.headers.get("Origin")
        if origin:
            supplied = _urlsplit(origin)
            current = _urlsplit(request.host_url)
            if (
                supplied.scheme.lower() != current.scheme.lower()
                or (supplied.hostname or "").lower() != (current.hostname or "").lower()
                or supplied.port != current.port
            ):
                return {"error": "cross-origin browser request rejected"}, 403

        if request.remote_addr in ("127.0.0.1", "::1"):
            return None
        if _auth_failures_exceeded(request.remote_addr):
            return _too_many_requests()
        if not _check_auth(request.headers.get("Authorization")):
            _record_auth_failure(request.remote_addr)
            return _unauthorized()

    @app.errorhandler(413)
    def upload_too_large(_error):
        return {"error": f"request exceeds the configured {max_upload_mb} MiB limit"}, 413

    @app.get("/favicon.ico")
    def favicon():
        return "", 204

    @app.get("/api/health")
    def health_probe():
        """Core readiness is independent of optional Metasploit availability."""
        from tempfile import NamedTemporaryFile

        checks = {}
        try:
            conn = core.store._conn()
            try:
                conn.execute("SELECT 1").fetchone()
            finally:
                conn.close()
            checks["database"] = "ready"
        except Exception:
            checks["database"] = "unavailable"
        try:
            data_dir = Path(core.data_dir)
            with NamedTemporaryFile(prefix=".healthz-", dir=data_dir) as probe:
                probe.write(b"1")
                probe.flush()
            checks["data"] = "writable"
        except OSError:
            checks["data"] = "unavailable"
        try:
            checks["msf"] = "up" if core.msf.is_up() else "down"
        except Exception:
            checks["msf"] = "unavailable"

        ready = checks["database"] == "ready" and checks["data"] == "writable"
        if _v2_worker_externally_supervised():
            try:
                checks["v2_worker"] = (
                    "ready" if core.workflow_requests.worker_is_ready()
                    else "unavailable"
                )
            except Exception:
                checks["v2_worker"] = "unavailable"
            ready = ready and checks["v2_worker"] == "ready"
        optional_degraded = ["msf"] if checks["msf"] != "up" else []
        return jsonify({
            "status": "ok" if ready else "degraded",
            "core_ready": ready,
            "optional_degraded": optional_degraded,
            "checks": checks,
        }), (200 if ready else 503)

    @app.get("/api/health/simple")
    def health_simple():
        """Do not advertise a healthy service when durable state is unavailable.

        The lightweight endpoint shares the full probe's authoritative
        database/data-dir readiness decision. Optional tools are not gates.
        """
        full_response, status = health_probe()
        return jsonify({
            "ok": status == 200,
            "tools": len(core.catalog.list()),
            "core_ready": full_response.get_json()["core_ready"],
        }), status

    # Engine V2 read-only API. All operations use the same Core contracts
    # consumed by the CLI; inherited application auth/rate gates apply.
    @app.get("/api/v2/capabilities")
    def workflow_v2_capabilities():
        return jsonify([item.to_dict() for item in core.capabilities.list()])

    @app.get("/api/v2/providers")
    def workflow_v2_providers():
        return jsonify(core.capability_inventory())

    @app.get("/api/v2/providers/portfolio-audit")
    def workflow_v2_portfolio_audit():
        return jsonify(core.capability_portfolio_audit())

    @app.post("/api/v2/ai/proposals")
    @limiter.limit("10 per minute")
    def workflow_v2_ai_proposal():
        """Compile one bounded AI action into a reviewable V2 workflow plan."""
        from whaxon.core.ai_bridge import propose_v2_workflow_plan
        from whaxon.core.workflow import WorkflowPlan

        payload = request.get_json(silent=True)
        required = ("mission_id", "id", "goal", "target")
        if not isinstance(payload, dict) or any(
            not isinstance(payload.get(key), str) or not payload[key].strip()
            for key in required
        ):
            return jsonify({
                "error": "mission_id, id, goal and target strings are required",
                "execution_submitted": False,
            }), 400
        if len(payload["goal"]) > 10000 or len(payload["target"]) > 2048:
            return jsonify({
                "error": "goal or target exceeds allowed limits",
                "execution_submitted": False,
            }), 400
        save = payload.get("save", False)
        if type(save) is not bool:
            return jsonify({"error": "save must be a boolean"}), 400
        history = payload.get("history", [])
        step = payload.get("step", 1)
        try:
            proposal = propose_v2_workflow_plan(
                core,
                mission_id=payload["mission_id"],
                plan_id=payload["id"],
                goal=payload["goal"],
                target=payload["target"],
                history=history,
                step=step,
            )
            created = False
            if save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    payload["id"], WorkflowPlan.from_dict(proposal["plan"]),
                )
            return jsonify({
                **proposal,
                "execution_submitted": bool(proposal.get("execution_submitted", False)),
                "approval_granted": bool(proposal.get("approval_granted", False)),
                "created": bool(created),
            }), 200
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            message = str(exc)
            return jsonify({"error": message}), (
                404 if message.startswith("unknown mission:") else 400
            )

    @app.post("/api/v2/workflow-proposals")
    @limiter.limit("20 per minute")
    def workflow_v2_workflow_proposal():
        """Prepare a fixed tool or evidence-bound verification plan for review."""
        from whaxon.core.workflow import WorkflowPlan
        from whaxon.core.workflow_proposals import (
            propose_finding_verification_plan,
            propose_tool_workflow_plan,
        )

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        kind = payload.get("kind")
        save = payload.get("save", False)
        if type(save) is not bool:
            return jsonify({"error": "save must be a boolean"}), 400

        if kind == "tool":
            try:
                tool_request = WorkflowToolProposalRequest.model_validate(payload)
            except ValidationError:
                return jsonify({
                    "error": "tool proposal requires mission_id, id, tool and target",
                }), 400
            if any(not value.strip() for value in (
                tool_request.mission_id, tool_request.id,
                tool_request.tool, tool_request.target,
            )):
                return jsonify({
                    "error": "tool proposal requires mission_id, id, tool and target",
                }), 400
            if len(tool_request.target) > 2048:
                return jsonify({"error": "target exceeds allowed limits"}), 400
            plan_id = tool_request.id
            proposal_args = {
                "mission_id": tool_request.mission_id,
                "plan_id": tool_request.id,
                "tool_id": tool_request.tool,
                "target": tool_request.target,
            }
        elif kind == "verification":
            try:
                finding_request = WorkflowFindingProposalRequest.model_validate(payload)
            except ValidationError:
                return jsonify({
                    "error": "verification proposal requires mission_id, id, source_job_id, non-negative finding_seq and mode",
                }), 400
            if any(not value.strip() for value in (
                finding_request.mission_id, finding_request.id,
                finding_request.source_job_id, finding_request.mode,
            )) or finding_request.finding_seq < 0:
                return jsonify({
                    "error": "verification proposal requires mission_id, id, source_job_id, non-negative finding_seq and mode",
                }), 400
            if finding_request.mode not in {"verify", "retest"}:
                return jsonify({"error": "mode must be verify or retest"}), 400
            plan_id = finding_request.id
            proposal_args = {
                "mission_id": finding_request.mission_id,
                "plan_id": finding_request.id,
                "source_job_id": finding_request.source_job_id,
                "finding_seq": finding_request.finding_seq,
                "mode": finding_request.mode,
            }
        else:
            return jsonify({"error": "kind must be tool or verification"}), 400

        try:
            proposal = (
                propose_tool_workflow_plan(core, **proposal_args)
                if kind == "tool"
                else propose_finding_verification_plan(core, **proposal_args)
            )
            created = False
            if save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    plan_id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            return jsonify({
                **proposal,
                "created": bool(created),
                "execution_submitted": False,
                "approval_granted": False,
            }), 200
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            message = str(exc)
            return jsonify({"error": message}), (
                404 if message.startswith("unknown mission:") else 400
            )

    @app.post("/api/v2/workflows/<plan_id>/followups")
    @limiter.limit("10 per minute")
    def workflow_v2_followups(plan_id):
        """Compile reviewable follow-ups from verified persisted evidence only.

        Persistence is optional. Neither an empty nor a saved proposal grants
        approval, submits a run request, or starts any external operation.
        """
        payload = request.get_json(silent=True)
        if payload is None:
            payload = {}
        if not isinstance(payload, dict) or set(payload) - {"max_tasks", "save"}:
            return jsonify({"error": "max_tasks and save are the only supported fields"}), 400
        max_tasks = payload.get("max_tasks", 16)
        save = payload.get("save", False)
        if type(max_tasks) is not int or not 1 <= max_tasks <= 100:
            return jsonify({"error": "max_tasks must be an integer in 1..100"}), 400
        if type(save) is not bool:
            return jsonify({"error": "save must be a boolean"}), 400
        try:
            proposal = core.propose_workflow_followups(plan_id, max_tasks=max_tasks)
            created = False
            if save and proposal.plan is not None and proposal.plan_id is not None:
                created = core.save_workflow_plan(proposal.plan_id, proposal.plan)
            return jsonify({
                **proposal.to_dict(), "created": bool(created),
                "execution_started": False, "approval_granted": False,
            }), 200
        except ValueError as exc:
            return jsonify({"error": str(exc)}), (
                404 if "unknown source workflow plan" in str(exc) else 409
            )

    @app.route("/api/v2/missions", methods=["GET", "POST"])
    def workflow_v2_missions():
        if request.method == "POST":
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict) or not isinstance(payload.get("id"), str) or (
                not isinstance(payload.get("objective"), str)
            ):
                return jsonify({"error": "id and objective strings required"}), 400
            try:
                created = core.create_mission(payload["id"], payload["objective"])
                return jsonify({"mission_id": payload["id"], "created": bool(created)}), 201
            except (ValueError, TypeError) as exc:
                return jsonify({"error": str(exc)}), 400
        try:
            limit = int(request.args.get("limit", "100"))
            return jsonify(core.missions(limit=limit))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/v2/missions/<mission_id>/rate-limit", methods=["GET", "POST"])
    def workflow_v2_mission_rate_limit(mission_id):
        try:
            if request.method == "POST":
                payload = request.get_json(silent=True)
                if not isinstance(payload, dict):
                    return jsonify({"error": "min_spacing_s required"}), 400
                try:
                    rate_limit = RateLimitRequest.model_validate(payload)
                except ValidationError as exc:
                    missing = any(error["type"] == "missing" for error in exc.errors())
                    message = (
                        "min_spacing_s required" if missing
                        else "mission min_spacing_s must be finite and positive"
                    )
                    return jsonify({"error": message}), 400
                core.configure_mission_rate_limit(
                    mission_id, min_spacing_s=rate_limit.min_spacing_s,
                )
            return jsonify(core.mission_rate_limit(mission_id))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 404 if "unknown mission" in str(exc) else 400

    @app.post("/api/v2/workflows/<plan_id>/run")
    def workflow_v2_run(plan_id):
        """Persist a bounded run request before returning 202.

        Process-local wakeup is only an optimization. Another worker or a
        restarted service can claim the persisted request. Interrupted
        requests remain uncertain until explicitly reconciled.
        """
        payload = request.get_json(silent=True)
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        try:
            run_request = WorkflowRunRequest.model_validate(payload)
        except ValidationError:
            return jsonify({"error": "execution limits must be positive and bounded"}), 400
        try:
            queued = core.enqueue_workflow_run(plan_id, **run_request.model_dump())
        except ValueError as exc:
            return jsonify({"error": str(exc)}), (
                404 if "unknown workflow plan" in str(exc) else 409
            )
        # The request persists even if web exits. Only the supervised worker
        # drains it in paired E5 deployments, never another web process.
        if not _v2_worker_externally_supervised():
            try:
                runner.submit(lambda: asyncio.run(core.drain_workflow_run_requests()))
            except Exception:
                # An accepted durable request must not become a false 500.
                pass
        accepted = WorkflowRunAccepted.model_validate({
            "plan_id": plan_id,
            "run_request_id": queued["id"],
            "request_status": queued["status"],
            "execution_submitted": True,
            "execution_completed": False,
            "durable_progress_url": f"/api/v2/workflows/{plan_id}/progress",
            "run_request_url": f"/api/v2/workflow-runs/{queued['id']}",
            "run_snapshot_url": f"/api/v2/workflow-runs/{queued['id']}/snapshot",
        })
        return jsonify(accepted.model_dump(mode="json")), 202

    @app.get("/api/v2/workflow-runs/summary")
    def workflow_v2_run_queue_summary():
        return jsonify(core.workflow_run_queue_summary())

    @app.get("/api/v2/workflow-runs/<request_id>")
    def workflow_v2_run_request_status(request_id):
        row = core.workflow_run_request(request_id)
        return (jsonify(row), 200) if row else (
            jsonify({"error": "unknown workflow run request"}), 404
        )

    @app.post("/api/v2/workflow-runs/<request_id>/cancel")
    def workflow_v2_cancel_run_request(request_id):
        """Cancel by durable request identity through the plan stop barrier."""
        try:
            return jsonify(core.cancel_workflow_run_request(request_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.get("/api/v2/workflow-runs/<request_id>/snapshot")
    def workflow_v2_run_snapshot(request_id):
        """Reconnect to one durable request and its persisted task progress."""
        row = core.workflow_run_snapshot(request_id)
        return (jsonify(row), 200) if row else (
            jsonify({"error": "unknown workflow run request"}), 404
        )

    @app.get("/api/v2/workflows/<plan_id>")
    def workflow_v2_plan_details(plan_id):
        try:
            return jsonify(core.workflow_plan_details(plan_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.post("/api/v2/workflows")
    def workflow_v2_save_plan():
        from whaxon.core.workflow import WorkflowPlan

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get("id"), str) or (
            not isinstance(payload.get("plan"), dict)
        ):
            return jsonify({"error": "id string and plan object required"}), 400
        try:
            plan = WorkflowPlan.from_dict(payload["plan"])
            created = core.save_workflow_plan(payload["id"], plan)
            return jsonify({
                "plan_id": payload["id"], "mission_id": plan.mission_id,
                "digest": plan.digest, "created": bool(created),
            }), 201
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/v2/missions/<mission_id>/cost", methods=["GET", "POST"])
    def workflow_v2_mission_cost(mission_id):
        try:
            if request.method == "POST":
                payload = request.get_json(silent=True)
                if not isinstance(payload, dict):
                    return jsonify({"error": "max_cost_microusd required"}), 400
                try:
                    cost_limit = MissionCostLimitRequest.model_validate(payload)
                except ValidationError as exc:
                    missing = any(error["type"] == "missing" for error in exc.errors())
                    message = (
                        "max_cost_microusd required" if missing
                        else "max_cost_microusd must be a nonnegative integer"
                    )
                    return jsonify({"error": message}), 400
                core.configure_mission_cost_limit(
                    mission_id, max_cost_microusd=cost_limit.max_cost_microusd,
                )
            return jsonify(core.mission_cost_summary(mission_id))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 404 if "unknown mission" in str(exc) else 400

    @app.post("/api/v2/workflows/attempts/<attempt_id>/cost")
    def workflow_v2_attempt_cost(attempt_id):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or (
            "cost_microusd" not in payload or "source" not in payload
        ):
            return jsonify({"error": "cost_microusd and source required"}), 400
        try:
            amount = core.record_workflow_attempt_cost(
                attempt_id, cost_microusd=payload["cost_microusd"],
                source=payload["source"],
            )
            return jsonify({"attempt_id": attempt_id, "cost_microusd": amount})
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v2/missions/<mission_id>/deadline")
    def workflow_v2_mission_deadline(mission_id):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "deadline_at required"}), 400
        try:
            deadline = DeadlineRequest.model_validate(payload)
        except ValidationError as exc:
            missing = any(error["type"] == "missing" for error in exc.errors())
            message = (
                "deadline_at required" if missing
                else "mission deadline_at must be a finite positive unix timestamp"
            )
            return jsonify({"error": message}), 400
        try:
            core.configure_mission_deadline(
                mission_id, deadline_at=deadline.deadline_at,
            )
            return jsonify({
                "mission_id": mission_id, "deadline_at": core.mission_deadline(mission_id),
            })
        except (ValueError, TypeError) as exc:
            status = 404 if "unknown mission" in str(exc) else 400
            return jsonify({"error": str(exc)}), status

    @app.route("/api/v2/missions/<mission_id>/budget", methods=["GET", "POST"])
    def workflow_v2_mission_budget(mission_id):
        try:
            if request.method == "POST":
                payload = request.get_json(silent=True)
                if not isinstance(payload, dict):
                    return jsonify({"error": "JSON object required"}), 400
                try:
                    limits = ExecutionLimitsRequest.model_validate(payload)
                except ValidationError as exc:
                    missing = any(error["type"] == "missing" for error in exc.errors())
                    message = (
                        "both mission limits required" if missing
                        else "mission limits must be positive integers"
                    )
                    return jsonify({"error": message}), 400
                core.configure_mission_execution_limits(
                    mission_id,
                    max_total_attempts=limits.max_total_attempts,
                    max_concurrency=limits.max_concurrency,
                )
            return jsonify(core.mission_execution_limits(mission_id))
        except (ValueError, TypeError) as exc:
            status = 404 if "unknown mission" in str(exc) else 400
            return jsonify({"error": str(exc)}), status

    @app.get("/api/v2/missions/<mission_id>/plans")
    def workflow_v2_mission_plans(mission_id):
        try:
            return jsonify(core.mission_workflow_plans(mission_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.get("/api/v2/missions/<mission_id>/report")
    def workflow_v2_mission_report(mission_id):
        """Return the Core's evidence-bound ordered mission report.

        A partial report must remain partial; this endpoint never infers
        assessment success from a completed HTTP request.
        """
        requested_ids = request.args.getlist("plan_id")
        raw_limit = request.args.get("limit", "100")
        if (
            len(raw_limit) > 4 or not raw_limit.isascii()
            or not raw_limit.isdecimal() or not 1 <= int(raw_limit) <= 1000
            or len(requested_ids) > 100
            or any(not plan_id or len(plan_id) > 256 for plan_id in requested_ids)
        ):
            return jsonify({"error": "invalid report limit or plan identifiers"}), 400
        if core.store.get_mission(mission_id) is None:
            return jsonify({"error": "unknown mission"}), 404
        try:
            return jsonify(core.workflow_mission_report(
                mission_id,
                plan_ids=requested_ids if requested_ids else None,
                limit=int(raw_limit),
            ))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v2/workflows/<plan_id>/cancel")
    def workflow_v2_cancel(plan_id):
        """Persist stop intent; never imply already executing providers stopped."""
        try:
            cancelled = core.cancel_workflow_plan(plan_id)
            return jsonify({
                "plan_id": plan_id, "cancellation_requested": True,
                "tasks_cancelled": cancelled,
                "external_effects_stopped": False,
            })
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.route("/api/v2/workflows/<plan_id>/approvals", methods=["GET", "POST"])
    def workflow_v2_approvals(plan_id):
        if request.method == "POST":
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict) or any(
                name not in payload
                for name in ("task_key", "approval_id", "expires_at")
            ):
                return jsonify({"error": "task_key, approval_id and expires_at required"}), 400
            try:
                approval = WorkflowApprovalGrantRequest.model_validate(payload)
            except ValidationError as exc:
                missing = any(error["type"] == "missing" for error in exc.errors())
                if missing:
                    return jsonify({
                        "error": "task_key, approval_id and expires_at required",
                    }), 400
                invalid_expiry = any(
                    error["loc"] == ("expires_at",) for error in exc.errors()
                )
                if invalid_expiry:
                    return jsonify({
                        "error": "approval expiry must be finite and in the future",
                    }), 400
                field = exc.errors()[0]["loc"][0]
                return jsonify({"error": f"{field} must be a nonempty string"}), 400
            try:
                granted = core.grant_workflow_approval(
                    plan_id, approval.task_key, approval.approval_id,
                    _request_actor(), expires_at=approval.expires_at,
                )
                return jsonify({"plan_id": plan_id, "granted": bool(granted)}), 200
            except (ValueError, TypeError, KeyError) as exc:
                return jsonify({"error": str(exc)}), 400
        try:
            return jsonify(core.workflow_approvals(plan_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.get("/api/v2/approval-queue")
    def workflow_v2_approval_queue():
        raw_limit = request.args.get("limit", "100")
        if (
            len(raw_limit) > 4 or not raw_limit.isascii()
            or not raw_limit.isdecimal() or not 1 <= int(raw_limit) <= 1000
        ):
            return jsonify({"error": "approval queue limit must be between 1 and 1000"}), 400
        try:
            return jsonify({
                "items": core.workflow_approval_queue(limit=int(raw_limit)),
            })
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v2/workflows/<plan_id>/approvals/<approval_id>/revoke")
    def workflow_v2_revoke_approval(plan_id, approval_id):
        payload = request.get_json(silent=True)
        if payload is not None and (
            not isinstance(payload, dict) or set(payload) - {"actor"}
        ):
            return jsonify({"error": "only legacy actor metadata is accepted"}), 400
        try:
            revoked = core.revoke_workflow_approval(
                plan_id, approval_id, actor=_request_actor(),
            )
            return jsonify({"plan_id": plan_id, "approval_id": approval_id, "revoked": bool(revoked)})
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v2/workflows/<plan_id>/reconcile")
    def workflow_v2_reconcile(plan_id):
        payload = request.get_json(silent=True)
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        if "attempt_id" in payload:
            required = {"attempt_id", "disposition", "evidence_ref", "note"}
            if not required.issubset(payload) or set(payload) - required - {"actor"}:
                return jsonify({"error": "exact attempt reconciliation fields are required"}), 400
            try:
                reconciliation = WorkflowAttemptReconciliationRequest.model_validate(payload)
            except ValidationError as exc:
                messages = {
                    "attempt_id": "unknown workflow attempt for this plan",
                    "disposition": "unsupported reconciliation disposition",
                    "evidence_ref": (
                        "evidence_ref must be normalized non-empty text within its limit"
                    ),
                    "note": "note must be normalized non-empty text within its limit",
                }
                field = exc.errors()[0]["loc"][0]
                return jsonify({"error": messages[field]}), 400
            try:
                result = core.reconcile_workflow_attempt(
                    plan_id, reconciliation.attempt_id,
                    disposition=reconciliation.disposition, actor=_request_actor(),
                    evidence_ref=reconciliation.evidence_ref, note=reconciliation.note,
                )
                return jsonify(result)
            except (ValueError, TypeError) as exc:
                return jsonify({"error": str(exc)}), 400
        try:
            reconciliation = WorkflowPlanReconciliationRequest.model_validate(payload)
        except ValidationError:
            return jsonify({"error": "stale_after_s must be positive and finite"}), 400
        try:
            changed = core.reconcile_workflow_plan(
                plan_id, stale_after_s=reconciliation.stale_after_s,
            )
            return jsonify({"plan_id": plan_id, "attempts_marked_uncertain": changed})
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/v2/workflows/<plan_id>/event-inbox")
    def workflow_v2_event_inbox(plan_id):
        consumer = request.args.get("consumer", "")
        if not consumer:
            return jsonify({"error": "consumer required"}), 400
        try:
            limit = int(request.args.get("limit", "100"))
            return jsonify(core.workflow_event_inbox(plan_id, consumer, limit=limit))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v2/workflows/<plan_id>/event-ack")
    def workflow_v2_event_ack(plan_id):
        payload = request.get_json(silent=True)
        try:
            acknowledgement = WorkflowEventAcknowledgement.model_validate(payload)
        except ValidationError:
            return jsonify({"error": "consumer and integer event_id required"}), 400
        if not acknowledgement.consumer:
            return jsonify({"error": "consumer and integer event_id required"}), 400
        try:
            checkpoint = core.acknowledge_workflow_event(
                plan_id, acknowledgement.consumer, acknowledgement.event_id,
            )
            result = WorkflowEventAcknowledgementResult.model_validate({
                "plan_id": plan_id,
                "consumer_id": acknowledgement.consumer,
                "last_event_id": checkpoint,
            })
            return jsonify(result.model_dump(mode="json"))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/v2/workflows/<plan_id>/attempts")
    def workflow_v2_attempts(plan_id):
        try:
            limit = int(request.args.get("limit", "100"))
            after_started = float(request.args.get("after_started", "0"))
            return jsonify(core.workflow_attempts(
                plan_id, limit=limit, after_started=after_started,
            ))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/v2/workflows/<plan_id>/audit")
    def workflow_v2_audit(plan_id):
        try:
            return jsonify(core.workflow_audit_integrity(plan_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.get("/api/v2/workflows/<plan_id>/evidence")
    def workflow_v2_evidence(plan_id):
        try:
            limit = int(request.args.get("limit", "100"))
            return jsonify(core.workflow_evidence(plan_id, limit=limit))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), (
                404 if "unknown workflow plan" in str(exc) else 400
            )

    @app.get("/api/v2/workflows/<plan_id>/resources")
    def workflow_v2_resources(plan_id):
        try:
            return jsonify(core.workflow_resource_summary(plan_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.get("/api/v2/workflows/<plan_id>/limits")
    def workflow_v2_limits(plan_id):
        try:
            return jsonify({
                "plan_id": plan_id,
                "limits": core.store.get_workflow_limits(plan_id),
                "deadline_at": core.store.get_workflow_deadline(plan_id),
            })
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.post("/api/v2/workflows/<plan_id>/limits")
    def workflow_v2_set_limits(plan_id):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        try:
            limits = ExecutionLimitsRequest.model_validate(payload)
        except ValidationError as exc:
            missing = any(error["type"] == "missing" for error in exc.errors())
            message = (
                "both limits are required" if missing
                else "workflow limits must be positive integers"
            )
            return jsonify({"error": message}), 400
        try:
            core.configure_workflow_limits(
                plan_id,
                max_total_attempts=limits.max_total_attempts,
                max_concurrency=limits.max_concurrency,
            )
            return jsonify({"plan_id": plan_id, "limits": core.store.get_workflow_limits(plan_id)})
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v2/workflows/<plan_id>/deadline")
    def workflow_v2_set_deadline(plan_id):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "deadline_at required"}), 400
        try:
            deadline = DeadlineRequest.model_validate(payload)
        except ValidationError as exc:
            missing = any(error["type"] == "missing" for error in exc.errors())
            message = (
                "deadline_at required" if missing
                else "deadline_at must be a finite positive unix timestamp"
            )
            return jsonify({"error": message}), 400
        try:
            core.configure_workflow_deadline(plan_id, deadline_at=deadline.deadline_at)
            return jsonify({
                "plan_id": plan_id, "deadline_at": core.store.get_workflow_deadline(plan_id),
            })
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v2/workflows/<plan_id>/rate-limit")
    def workflow_v2_set_rate_limit(plan_id):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "min_spacing_s required"}), 400
        try:
            rate_limit = RateLimitRequest.model_validate(payload)
        except ValidationError as exc:
            missing = any(error["type"] == "missing" for error in exc.errors())
            message = (
                "min_spacing_s required" if missing
                else "min_spacing_s must be finite and positive"
            )
            return jsonify({"error": message}), 400
        try:
            core.configure_workflow_rate_limit(
                plan_id, min_spacing_s=rate_limit.min_spacing_s,
            )
            return jsonify({"plan_id": plan_id, "rate_limit_configured": True})
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/v2/workflows/<plan_id>/progress")
    def workflow_v2_progress(plan_id):
        try:
            return jsonify(core.workflow_progress(plan_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.get("/api/v2/workflows/<plan_id>/events")
    def workflow_v2_events(plan_id):
        try:
            after_id = int(request.args.get("after_id", "0"))
            limit = int(request.args.get("limit", "100"))
            return jsonify(core.workflow_events(plan_id, after_id=after_id, limit=limit))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/v2/workflows/<plan_id>/report")
    def workflow_v2_plan_report(plan_id):
        """Return persisted, evidence-scoped workflow report without side effects."""
        raw_limit = request.args.get("limit", "100")
        if (
            len(raw_limit) > 4 or not raw_limit.isascii()
            or not raw_limit.isdecimal() or not 1 <= int(raw_limit) <= 1000
        ):
            return jsonify({"error": "limit must be an integer in 1..1000"}), 400
        try:
            return jsonify(core.workflow_report(plan_id, limit=int(raw_limit)))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404 if "unknown" in str(exc) else 400

    @app.get("/api/v2/workflows/<plan_id>/audit-snapshot")
    def workflow_v2_audit_snapshot(plan_id):
        """Expose a digest for an external operator-held integrity anchor."""
        try:
            return jsonify(core.workflow_audit_snapshot(plan_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.post("/api/v2/workflows/<plan_id>/audit-verify")
    def workflow_v2_audit_verify(plan_id):
        """Compare against a caller-held digest; never claim third-party anchoring."""
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {"expected_digest"}:
            return jsonify({"error": "expected_digest is required"}), 400
        try:
            matched = core.verify_workflow_audit_snapshot(
                plan_id, payload["expected_digest"],
            )
            return jsonify({
                "plan_id": plan_id,
                "digest_matches": bool(matched),
                "independent_anchor_verified": False,
            })
        except ValueError as exc:
            return jsonify({"error": str(exc)}), (
                404 if "unknown workflow plan" in str(exc) else 400
            )

    @app.get("/api/v2/workflows/<plan_id>/readiness")
    def workflow_v2_readiness(plan_id):
        try:
            return jsonify(core.workflow_readiness(plan_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.get("/api/v2/workflows/<plan_id>/reconciliation")
    def workflow_v2_reconciliation(plan_id):
        try:
            return jsonify(core.workflow_dispatch_reconciliation(plan_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.get("/api/tools")
    def list_tools():
        import shutil

        from whaxon.adapters import get_adapter

        result = []
        for tool in core.catalog.list():
            try:
                adapter_available = get_adapter(tool.id) is not None
            except Exception:
                app.logger.exception("Adapter lookup failed for catalog tool %s", tool.id)
                adapter_available = False
            binary_available = bool(
                tool.binary
                and (
                    shutil.which(tool.binary)
                    or (
                        os.path.isabs(tool.binary)
                        and os.path.isfile(tool.binary)
                        and os.access(tool.binary, os.X_OK)
                    )
                )
            )
            result.append({
                "binary_available": binary_available,
                "transport": tool.transport,
                "id": tool.id,
                "name": tool.name,
                "category": tool.category,
                "binary": tool.binary,
                "description": tool.description,
                "available": bool(tool.available),
                "package": tool.package or "",
                "adapter_available": adapter_available,
            })
        return jsonify(result)

    @app.post("/api/run")
    @limiter.limit("30 per minute")
    def run_tool():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {"error": "request body must be a JSON object"}, 400
        tool_id = data.get("tool_id")
        target = data.get("target")
        extra_args = data.get("extra_args", "")
        if not isinstance(tool_id, str) or not tool_id.strip():
            return {"error": "tool_id must be a non-empty string"}, 400
        if not isinstance(target, str) or not target.strip():
            return {"error": "target must be a non-empty string"}, 400
        tool_id = tool_id.strip()
        target = target.strip()
        if len(tool_id) > 128 or len(target) > 2048 or "\x00" in target:
            return {"error": "tool_id or target exceeds allowed limits"}, 400
        if extra_args is None:
            extra_args = ""
        # The web runner intentionally does not accept arbitrary command-line
        # arguments from clients. The current runner path does not implement a
        # safe per-tool argument allowlist, so reject rather than silently ignore.
        if not isinstance(extra_args, str) or extra_args.strip():
            return {"error": "extra_args are not supported by the web runner"}, 400

        # Scope enforcement is mandatory. Web out-of-scope overrides are
        # disabled until an operator-confirmed, target-bound audit flow exists.
        try:
            match = _check_execution_scope(registry.core.scope, target)
        except Exception:
            # Authorization must fail closed: a broken scope engine must never
            # turn a target into an implicitly authorized one.
            app.logger.exception("Scope evaluation failed for tool run")
            return {"error": "scope evaluation failed; no job was started"}, 503
        if match is None:
            return {"error": "target could not be confirmed in scope; no job was started"}, 403
        if not match.allowed:
            # Do not accept a client-supplied flag as authorization. A safe,
            # auditable, operator-confirmed override flow must be implemented
            # before web requests can run out-of-scope targets.
            return {"error": f"target out of scope: {match.reason}",
                    "matched_rule": match.matched_rule}, 403
        if core.catalog.get(tool_id) is None:
            return {"error": f"unknown tool: {tool_id}"}, 404

        legacy_tool_execution_enabled = os.environ.get(
            "WHAXON_LEGACY_TOOL_EXECUTION_ENABLED", "false",
        ).strip().lower() in ("1", "true", "yes")
        if not legacy_tool_execution_enabled:
            return {
                "error": (
                    "Legacy direct tool execution is disabled. Use the Engine V2 "
                    "workflow UI or POST /api/v2/workflows to save a reviewable "
                    "plan, then separately approve its exact task and submit it "
                    "through POST /api/v2/workflows/<plan_id>/run."
                ),
                "legacy_execution_enabled": False,
                "v2_plan_endpoint": "/api/v2/workflows",
                "v2_run_endpoint": "/api/v2/workflows/<plan_id>/run",
                "approval_granted": False,
                "execution_submitted": False,
            }, 410

        job_id = uuid.uuid4().hex[:12]
        registry.ensure(job_id)
        runner.submit(lambda: _run_job_blocking(core, registry, tool_id, target, job_id, extra_args))
        return {"job_id": job_id}, 202



    @app.post("/api/ai/run")
    @limiter.limit("10 per minute")
    def ai_run():
        import json as _json
        import time as _time

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {"error": "request body must be a JSON object; AI run was not started"}, 400
        goal_value = data.get("goal")
        if not isinstance(goal_value, str) or not goal_value.strip():
            return {"error": "goal required; AI run was not started"}, 400
        goal = goal_value.strip()
        target_value = data.get("target", "")
        if target_value is None:
            target_value = ""
        if not isinstance(target_value, str):
            return {"error": "target must be a string; AI run was not started"}, 400
        target = target_value.strip() or None
        if len(goal) > 10000 or (target is not None and (len(target) > 2048 or "\x00" in target)):
            return {"error": "goal or target exceeds allowed limits; AI run was not started"}, 400
        if target is None:
            try:
                from whaxon.core.targets import extract_target
                target = extract_target(goal)
            except Exception:
                target = None
        if not target:
            return {"error": "target required; AI run was not started"}, 400
        try:
            match = _check_execution_scope(registry.core.scope, target)
        except Exception:
            app.logger.exception("Scope evaluation failed before AI run")
            return {"error": "scope evaluation failed; AI run was not started"}, 503
        if match is None or not getattr(match, "allowed", False):
            reason = getattr(match, "reason", "target could not be confirmed in scope")
            return {
                "error": f"target out of scope: {reason}; AI run was not started",
                "matched_rule": getattr(match, "matched_rule", None),
            }, 403

        if not _legacy_ai_execution_enabled():
            return {
                "error": (
                    "Legacy AI execution is disabled. Use the V2 AI proposal "
                    "flow at POST /api/v2/ai/proposals; proposals require an "
                    "operator-supplied mission_id, plan id, goal, and exact target, "
                    "then separate review, task approval, and durable submission."
                ),
                "legacy_execution_enabled": False,
                "v2_proposal_endpoint": "/api/v2/ai/proposals",
                "approval_granted": False,
                "execution_submitted": False,
            }, 410

        run_id = "ai-" + uuid.uuid4().hex[:12]
        core.store.create_ai_run(run_id, goal)

        async def ask_human(action):
            # Persist the exact pending action and pause until the operator
            # answers through /api/ai/runs/<run_id>/answer.
            question = {
                "run_id": run_id,
                "kind": action.kind,
                "rationale": action.rationale,
                "tool_id": action.tool_id,
                "target": action.target or target,
                "extra_args": action.extra_args,
                "confidence": action.confidence,
                "proposed_phase": action.proposed_phase,
            }
            store = registry.core.store
            store.set_ai_run_waiting(run_id, _json.dumps(question))
            current = store.get_ai_run(run_id) or {}
            answer_seq = len(current.get("steps") or []) + 1
            deadline = _time.monotonic() + 1800
            while _time.monotonic() < deadline:
                for approval in store.list_approvals(run_id):
                    if int(approval.get("seq", -1)) == answer_seq:
                        return str(approval.get("answer") or "")
                await asyncio.sleep(0.25)
            raise TimeoutError("operator approval timed out; AI run stopped")

        def _factory():
            from whaxon.core.ai_bridge import build_executor
            return build_executor(
                core,
                target_lock=target,
                ai_run_id=run_id,
                ask_human=ask_human,
            )

        runner.submit(lambda: _ai_run_blocking(core, _factory, run_id, goal, core.store))
        return {"run_id": run_id}, 202

    @app.get("/api/ai/runs")
    def ai_runs_list():
        limit = int(request.args.get("limit", "50"))
        return core.store.list_ai_runs(limit=limit)

    @app.get("/api/ai/pending")
    def ai_pending_list():
        owner = request.args.get("owner") or None
        return core.store.list_pending_runs(owner=owner)

    @app.post("/api/ai/runs/<run_id>/answer")
    def ai_run_answer(run_id: str):
        if not _legacy_ai_execution_enabled():
            return {
                "error": (
                    "Legacy AI execution is disabled. Pending legacy runs are "
                    "read-only; use the V2 proposal, approval, and durable run flow."
                ),
                "legacy_execution_enabled": False,
                "v2_proposal_endpoint": "/api/v2/ai/proposals",
                "approval_granted": False,
                "execution_submitted": False,
            }, 410
        data = request.get_json(silent=True) or {}
        answer = (data.get("answer") or "").strip()
        if not answer:
            return {"error": "answer required"}, 400
        # Never trust an operator identity supplied in the JSON body or
        # an unvalidated Basic header on the loopback bypass path. Remote
        # requests have passed _auth_gate before this handler runs.
        user = _request_actor()
        note = (data.get("note") or "")
        run = core.store.get_ai_run(run_id)
        if run is None:
            return {"error": "run not found"}, 404
        if run.get("status") != "waiting":
            return {"error": "run is not waiting"}, 409
        next_seq = len(run.get("steps") or []) + 1
        core.store.add_approval(run_id, next_seq, user, answer, note)
        return {"ok": True, "run_id": run_id, "seq": next_seq}

    @app.get("/api/ai/runs/<run_id>")
    def ai_run_get(run_id: str):
        run = core.store.get_ai_run(run_id)
        if run is None:
            return {"error": "run not found"}, 404
        return run

    @app.get("/api/ai/runs/<run_id>/stream")
    def ai_run_stream(run_id: str):
        import json as _json
        import time as _t

        from flask import Response

        if core.store.get_ai_run(run_id) is None:
            return {"error": "run not found"}, 404

        def generate():
            last_seq = 0
            deadline = _t.monotonic() + 600.0
            while _t.monotonic() < deadline:
                run = core.store.get_ai_run(run_id)
                if run is None:
                    return
                for step in run.get("steps", []):
                    seq = step.get("seq", 0)
                    if seq <= last_seq:
                        continue
                    last_seq = seq
                    payload = {"type": "step", "seq": seq,
                               "action": step.get("action"),
                               "result": step.get("result")}
                    yield "data: %s\n\n" % _json.dumps(payload)
                if run.get("status") in ("done", "failed", "error"):
                    yield "data: %s\n\n" % _json.dumps(
                        {"type": "finished", "status": run.get("status"),
                         "error": run.get("error", "")})
                    return
                _t.sleep(1.0)
                yield ": ping\n\n"

        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

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

    @app.get("/api/jobs/active")
    def list_active_jobs():
        """Return currently running jobs for operational status and cancellation."""
        return jsonify(registry.core.store.active_jobs())

    @app.get("/api/jobs/<job_id>/evidence")
    def list_evidence(job_id: str):
        if not registry.core.store.get(job_id):
            return {"error": "job not found"}, 404
        items = registry.core.store.list_evidence(job_id)
        return jsonify(items)

    @app.post("/api/jobs/<job_id>/evidence")
    def add_evidence(job_id: str):
        if not registry.core.store.get(job_id):
            return {"error": "job not found"}, 404
        data = request.get_json(silent=True)
        if data and (data.get("note") or data.get("kind") == "note"):
            note = data.get("note", "")
            name = data.get("name", "note")
            if not isinstance(note, str) or len(note) > 10000:
                return {"error": "note must be a string of at most 10000 characters"}, 400
            if not isinstance(name, str) or len(name) > 200:
                return {"error": "name must be a string of at most 200 characters"}, 400
            seq = registry.core.store.add_evidence(
                job_id, "note", name, note=note)
            return {"seq": seq}, 201
        f = request.files.get("file")
        if f is None:
            return {"error": "provide file (multipart) or {note: ...} JSON"}, 400
        from werkzeug.utils import secure_filename
        safe_name = secure_filename(f.filename or "")
        if not safe_name:
            return {"error": "filename is empty or invalid"}, 400
        try:
            target_dir = _evidence_dir(registry.core, job_id)
        except ValueError as exc:
            return {"error": str(exc)}, 400
        import uuid as _uuid
        disk_name = f"{_uuid.uuid4().hex[:12]}-{safe_name}"
        dest = target_dir / disk_name
        try:
            f.save(str(dest))
            relative_path = str(dest.resolve().relative_to(Path(registry.core.data_dir).resolve()))
            seq = registry.core.store.add_evidence(
                job_id, "file", safe_name,
                path=relative_path,
                note=request.form.get("note", "")[:10000])
        except Exception:
            try:
                dest.unlink(missing_ok=True)
            except OSError:
                app.logger.exception("Failed to clean up partial evidence upload")
            app.logger.exception("Evidence upload failed for job %s", job_id)
            return {"error": "evidence upload failed"}, 500
        return {"seq": seq, "name": safe_name}, 201

    @app.delete("/api/jobs/<job_id>/evidence/<int:seq>")
    def delete_evidence(job_id: str, seq: int):
        if not registry.core.store.get(job_id):
            return {"error": "job not found"}, 404
        items = registry.core.store.list_evidence(job_id)
        item = next((x for x in items if x["seq"] == seq), None)
        if item is None:
            return {"ok": False}, 404
        if item.get("path"):
            try:
                full = _resolve_evidence_path(registry.core, item["path"])
            except ValueError:
                app.logger.error("Refusing to delete evidence with unsafe path for job %s", job_id)
                return {"error": "unsafe evidence path"}, 403
            try:
                full.unlink(missing_ok=True)
            except OSError:
                app.logger.exception("Failed to remove evidence file for job %s", job_id)
                return {"error": "failed to remove evidence file"}, 500
        ok = registry.core.store.remove_evidence(job_id, seq)
        return {"ok": ok}, (200 if ok else 404)

    @app.get("/api/jobs/<job_id>/evidence/<int:seq>/download")
    def download_evidence(job_id: str, seq: int):
        from flask import send_file
        if not registry.core.store.get(job_id):
            return {"error": "job not found"}, 404
        items = registry.core.store.list_evidence(job_id)
        item = next((x for x in items if x["seq"] == seq), None)
        if not item or not item.get("path"):
            return {"error": "not a file"}, 404
        try:
            full = _resolve_evidence_path(registry.core, item["path"])
        except ValueError:
            app.logger.error("Refusing to download evidence with unsafe path for job %s", job_id)
            return {"error": "unsafe evidence path"}, 403
        if not full.is_file():
            return {"error": "file missing"}, 404
        return send_file(str(full), as_attachment=True, download_name=item["name"])

    def _msf_session_scope_error(session_id: str):
        """Require a live, persisted-identity-matching session in current scope."""
        client = registry.core.msf
        if not client.is_up():
            return {"error": "msf not reachable; session scope cannot be verified"}, 503
        try:
            live = client.sessions()
        except Exception:
            app.logger.exception("Could not read Metasploit sessions for scope check")
            return {"error": "could not verify session scope"}, 503
        info = live.get(str(session_id))
        if info is None:
            return {"error": "session not found"}, 404
        if not isinstance(info, dict):
            return {"error": "session details are invalid; refusing to act"}, 503
        host = (
            info.get("target_host") or info.get("session_host")
            or info.get("tunnel_peer") or info.get("peer_host") or info.get("host")
        )
        if not host:
            return {"error": "session host is unknown; refusing out-of-scope-capable action"}, 403

        # Session IDs are reusable by Metasploit. Never authorize a live session
        # solely from its current host: bind it to the identity first persisted
        # by the tracker, and reject missing/closed records or host drift.
        try:
            stored = registry.core.store.get_session(str(session_id))
        except Exception:
            app.logger.exception("Could not read persisted Metasploit session identity")
            return {"error": "could not verify persisted session identity"}, 503
        if not isinstance(stored, dict) or stored.get("status") != "open":
            return {"error": "session has no active persisted identity; refusing to act"}, 403
        stored_host = stored.get("host")
        if not stored_host or str(stored_host).strip() in {"", "?"}:
            return {"error": "persisted session host is unknown; refusing to act"}, 403
        from whaxon.core.runner import ToolRunner
        live_identity = ToolRunner._canonical_session_host(host)
        stored_identity = ToolRunner._canonical_session_host(stored_host)
        if not live_identity or live_identity != stored_identity:
            return {
                "error": "Metasploit session identity changed since it was persisted; refusing to act",
                "persisted_host": str(stored_host),
                "live_host": str(host),
            }, 409
        stored_type = str(stored.get("type") or "").strip().lower()
        live_type = str(info.get("type") or "").strip().lower()
        if stored_type and live_type and stored_type != live_type:
            return {
                "error": "Metasploit session type changed since it was persisted; refusing to act",
                "persisted_type": stored_type,
                "live_type": live_type,
            }, 409

        try:
            match = _check_execution_scope(registry.core.scope, str(host))
        except Exception:
            app.logger.exception("Scope evaluation failed for Metasploit session host")
            return {"error": "scope evaluation failed; action was not performed"}, 503
        if match is None or not getattr(match, "allowed", False):
            reason = getattr(match, "reason", "target could not be confirmed in scope")
            return {
                "error": f"session host out of scope: {reason}",
                "target": str(host),
                "matched_rule": getattr(match, "matched_rule", None),
            }, 403
        return None

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
        if not _legacy_msf_execution_enabled():
            return {
                "error": (
                    "Legacy Metasploit execution is disabled. Supported lab operations "
                    "must use an approved Engine V2 plan."
                ),
                "legacy_execution_enabled": False,
                "approval_granted": False,
                "execution_submitted": False,
            }, 410
        import re as _re
        import uuid as _uuid
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {"error": "request body must be a JSON object"}, 400
        module_type = data.get("module_type", "exploit")
        module_path = data.get("module_path", "")
        options = data.get("options") or {}
        target_value = data.get("target") or ""
        if not isinstance(module_type, str) or not isinstance(module_path, str):
            return {"error": "module_type and module_path must be strings"}, 400
        if not isinstance(options, dict):
            return {"error": "options must be a JSON object"}, 400
        module_type = module_type.strip()
        module_path = module_path.strip()
        if not module_path:
            return {"error": "module_path required"}, 400
        if module_type not in ("exploit", "auxiliary", "post"):
            return {"error": f"bad module_type: {module_type}"}, 400
        if (
            module_path.startswith("/")
            or any(part in {"", ".", ".."} for part in module_path.split("/"))
            or not _re.fullmatch(r"[A-Za-z0-9_/-]+", module_path)
        ):
            return {"error": "invalid Metasploit module path"}, 400
        if not isinstance(target_value, str):
            return {"error": "target must be a string"}, 400
        for key, value in options.items():
            if not isinstance(key, str) or not _re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", key):
                return {"error": "invalid Metasploit option name"}, 400
            if value is None or isinstance(value, (dict, list, tuple)):
                return {"error": f"option {key} must be a scalar value"}, 400
            value_text = str(value)
            if len(value_text) > 2048 or any(ch in value_text for ch in ("\r", "\n", "\x00")):
                return {"error": f"option {key} contains invalid or oversized data"}, 400
        for key in ("RHOSTS", "RHOST"):
            if options.get(key) is not None and not isinstance(options[key], str):
                return {"error": f"{key} must be a string"}, 400

        target = target_value.strip() or str(options.get("RHOSTS") or options.get("RHOST") or "").strip()
        session_host = ""
        if module_type == "post":
            session_id = options.get("SESSION")
            if session_id is None or not str(session_id).strip():
                return {"error": "post modules require a SESSION option"}, 400
            session_error = _msf_session_scope_error(str(session_id).strip())
            if session_error:
                return session_error
            try:
                session_info = registry.core.msf.sessions().get(str(session_id).strip()) or {}
            except Exception:
                app.logger.exception("Could not read Metasploit session for post module")
                return {"error": "could not verify post-module session"}, 503
            session_host = str(session_info.get("target_host") or session_info.get("tunnel_peer") or "").strip()
            if not session_host:
                return {"error": "post-module session host is unknown"}, 403
            if not target:
                target = session_host

        # Scope enforcement is server-side and cannot be disabled by request data.
        candidates = []
        if target:
            candidates.extend(h.strip() for h in target.split(",") if h.strip())
        rhosts = options.get("RHOSTS") or options.get("RHOST") or ""
        if rhosts:
            for host in rhosts.split(","):
                host = host.strip()
                if host and host not in candidates:
                    candidates.append(host)
        if not candidates:
            return {"error": "an explicit in-scope target (RHOST/RHOSTS) is required"}, 400
        for cand in candidates:
            try:
                match = _check_execution_scope(registry.core.scope, cand)
            except Exception:
                app.logger.exception("Scope evaluation failed for Metasploit target")
                return {"error": "scope evaluation failed; no job was started"}, 503
            if match is None or not getattr(match, "allowed", False):
                reason = getattr(match, "reason", "target could not be confirmed in scope")
                matched_rule = getattr(match, "matched_rule", None)
                return {"error": f"target out of scope: {reason}",
                        "matched_rule": matched_rule,
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

            from whaxon.core.events import JobFailed, JobFinished
            try:
                tool_id = f"msf:{module_type}:{module_path}"
                registry.core.store.append_line(job_id, "stdout",
                    f"running {tool_id} with {extra_args}")
                findings = adapter.run_module(tool_id, extra_args, ctx={"target": target, "store": registry.core.store, "job_id": job_id})
                for f in findings:
                    if f.kind == "msf_module_started" or f.kind == "msf_session":
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
        if not _legacy_msf_execution_enabled():
            return {
                "error": "Legacy Metasploit session command execution is disabled.",
                "legacy_execution_enabled": False,
                "approval_granted": False,
                "execution_submitted": False,
            }, 410
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {"error": "request body must be a JSON object"}, 400
        command = data.get("command", "")
        if not isinstance(command, str) or not command.strip():
            return {"error": "command required"}, 400
        command = command.strip()
        if len(command) > 4096 or "\x00" in command:
            return {"error": "command must be at most 4096 characters and contain no NUL"}, 400
        session_error = _msf_session_scope_error(session_id)
        if session_error:
            return session_error

        client = registry.core.msf
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
        session_error = _msf_session_scope_error(session_id)
        if session_error:
            return session_error
        client = registry.core.msf
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

    @app.post("/api/bounty/import")
    @limiter.limit("10 per minute")
    def import_bounty_program():
        """Return an unapproved YesWeHack policy draft; never persist or execute it."""
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {"error": "JSON object required"}, 400
        url = data.get("url")
        pasted_text = data.get("text")
        source_url = data.get("source_url", "")
        if url is not None and pasted_text is not None:
            return {"error": "provide either url or text, not both"}, 400
        if url is None and pasted_text is None:
            return {"error": "provide a public YesWeHack url or pasted program text"}, 400
        if url is not None and (not isinstance(url, str) or not url.strip()):
            return {"error": "url must be a non-empty string"}, 400
        if pasted_text is not None and not isinstance(pasted_text, str):
            return {"error": "text must be a string"}, 400
        if not isinstance(source_url, str):
            return {"error": "source_url must be a string"}, 400
        from whaxon.core.bounty_ingest import (
            IngestionError,
            ingest_yeswehack_text,
            ingest_yeswehack_url,
        )
        try:
            if url is not None:
                result = ingest_yeswehack_url(url.strip())
            else:
                result = ingest_yeswehack_text(pasted_text, source_url=source_url.strip())
        except IngestionError as exc:
            return {"error": str(exc)}, 400
        return jsonify(result), 200

    @app.post("/api/scope")
    def save_scope():
        """Validate and persist an operator-edited scope definition."""
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {"error": "JSON object required"}, 400
        enabled = data.get("enabled", True)
        if type(enabled) is not bool:
            return {"error": "'enabled' must be a JSON boolean"}, 400
        current_scope = registry.core.scope.summary()
        if (
            enabled is False
            and current_scope.get("enabled", True) is not False
            and data.get("confirm_disable") is not True
        ):
            return {"error": "confirm_disable=true is required to disable scope enforcement"}, 400
        engagement = data.get("engagement", "")
        notes = data.get("notes", "")
        if not isinstance(engagement, str) or len(engagement) > 200:
            return {"error": "engagement must be a string of at most 200 characters"}, 400
        if not isinstance(notes, str) or len(notes) > 5000:
            return {"error": "notes must be a string of at most 5000 characters"}, 400
        from whaxon.core.scope import _validate_scope_rule
        rules = {}
        for key in ("in_scope", "out_of_scope"):
            value = data.get(key, [])
            if not isinstance(value, list) or len(value) > 500:
                return {"error": f"'{key}' must be a list with at most 500 rules"}, 400
            normalized = []
            for item in value:
                if not isinstance(item, str) or not item.strip() or len(item.strip()) > 253:
                    return {"error": f"invalid rule in '{key}'"}, 400
                rule = item.strip()
                if not _validate_scope_rule(rule):
                    return {"error": f"invalid scope rule: {rule}"}, 400
                if rule not in normalized:
                    normalized.append(rule)
            rules[key] = normalized
        try:
            registry.core.scope.save({
                "engagement": engagement.strip(),
                "enabled": enabled,
                "in_scope": rules["in_scope"],
                "out_of_scope": rules["out_of_scope"],
                "notes": notes.strip(),
            })
        except (OSError, RuntimeError, ValueError) as exc:
            return {"error": f"scope was not saved: {exc}"}, 400
        return jsonify(registry.core.scope.summary())

    @app.post("/api/scope/check")
    def check_scope():
        data = request.get_json(silent=True) or {}
        target = (data.get("target") or "").strip()
        if not target:
            return {"error": "target required"}, 400
        match = _check_execution_scope(registry.core.scope, target)
        return jsonify(match.to_dict())

    @app.post("/api/v2/scope/check")
    def check_v2_authoring_scope():
        """Preview the target scope gate used by a selected V2 capability."""
        data = request.get_json(silent=True) or {}
        target = data.get("target")
        capability_id = data.get("capability_id")
        if not isinstance(target, str) or not target.strip():
            return {"error": "target required"}, 400
        if not isinstance(capability_id, str) or not capability_id.strip():
            return {"error": "capability_id required"}, 400
        try:
            core.capabilities.resolve(capability_id)
        except Exception:
            return {"error": "unknown V2 capability"}, 404
        if capability_id == "dns.recon.passive":
            from whaxon.core.recon_v2 import _valid_hostname

            if not _valid_hostname(target):
                return jsonify({
                    "allowed": False,
                    "reason": "passive DNS requires a normalized ASCII hostname",
                })
            reload_scope = getattr(core.scope, "load", None)
            if callable(reload_scope):
                reload_scope()
            match = core.scope.check_for_dns_query(target)
        else:
            match = _check_execution_scope(core.scope, target)
        return jsonify(match.to_dict())

    @app.post("/api/scope/override")
    def log_override():
        data = request.get_json(silent=True) or {}
        target = (data.get("target") or "").strip()
        tool = (data.get("tool") or "").strip()
        if not target:
            return {"error": "target required"}, 400
        from whaxon.core.override_log import log_override
        log_override(registry.core.data_dir, tool, target)
        return {"logged": True}

    def _validation_scope_error(target_url: str | None):
        """Re-check current scope before any validator network replay."""
        if not target_url:
            return {"error": "finding has no target URL; replay was not attempted"}, 400
        try:
            match = _check_execution_scope(registry.core.scope, target_url)
        except Exception:
            app.logger.exception("Scope evaluation failed before validation replay")
            return {"error": "scope evaluation failed; replay was not attempted"}, 503
        if match is None or not getattr(match, "allowed", False):
            reason = getattr(match, "reason", "target could not be confirmed in scope")
            return {
                "error": f"target out of scope: {reason}; replay was not attempted",
                "matched_rule": getattr(match, "matched_rule", None),
            }, 403
        return None

    def _legacy_validation_v2_error(job_id: str):
        """Keep legacy validators from mutating sealed V2 evidence."""
        checker = getattr(registry.core.store, "is_engine_v2_execution_job", None)
        if not callable(checker):
            return {"error": "could not confirm evidence ownership; replay was not attempted"}, 503
        try:
            is_v2_job = checker(job_id)
        except Exception:
            app.logger.exception("Could not confirm evidence ownership before validation replay")
            return {"error": "could not confirm evidence ownership; replay was not attempted"}, 503
        if is_v2_job:
            return {
                "error": "Engine V2 evidence requires a plan-bound verification or retest workflow",
                "workflow": "whaxon workflow plan propose-verification",
            }, 409
        return None

    @app.post("/api/validate/<job_id>/<int:seq>")
    def api_validate(job_id: str, seq: int):
        if not _legacy_validation_enabled():
            return {
                "error": (
                    "Legacy finding validation is disabled. Use the Engine V2 "
                    "plan-bound verification workflow for V2 evidence."
                ),
                "legacy_validation_enabled": False,
                "approval_granted": False,
                "replay_attempted": False,
            }, 410
        from whaxon.core.findings import Finding
        from whaxon.core.validator import Validator
        findings = registry.core.store.get_findings(job_id) or []
        target_f = next((f for f in findings if f["seq"] == seq), None)
        if not target_f:
            return {"error": "finding not found"}, 404
        evidence_error = _legacy_validation_v2_error(job_id)
        if evidence_error:
            return evidence_error
        job = registry.core.store.get(job_id) or {}
        raw_target = job.get("target", "")
        if raw_target.startswith(("http://", "https://")):
            target_url = raw_target
        elif raw_target:
            target_url = f"http://{raw_target}"
        else:
            target_url = None
        scope_error = _validation_scope_error(target_url)
        if scope_error:
            return scope_error
        f_obj = Finding(
            kind=target_f["kind"], severity=target_f["severity"],
            source=target_f["source"], data=target_f["data"],
            raw_line=target_f["raw_line"],
            request_context=target_f.get("request_context") or {},
        )
        pkg_payloads = Path(__file__).resolve().parent.parent / "data" / "payloads"
        v = Validator(pkg_payloads)
        status, reason = v.validate(f_obj, target_url=target_url)
        registry.core.store.update_verification(job_id, seq, status, by="engine", reason=reason)
        return {"status": status, "reason": reason}

    @app.post("/api/retest/<job_id>/<int:seq>")
    def api_retest(job_id: str, seq: int):
        if not _legacy_validation_enabled():
            return {
                "error": (
                    "Legacy finding retest is disabled. Use the Engine V2 "
                    "plan-bound retest workflow for V2 evidence."
                ),
                "legacy_validation_enabled": False,
                "approval_granted": False,
                "replay_attempted": False,
            }, 410
        from whaxon.core.findings import Finding
        from whaxon.core.validator import Validator
        findings = registry.core.store.get_findings(job_id) or []
        target_f = next((f for f in findings if f["seq"] == seq), None)
        if not target_f:
            return {"error": "finding not found"}, 404
        evidence_error = _legacy_validation_v2_error(job_id)
        if evidence_error:
            return evidence_error
        if target_f.get("verification_status") != "verified":
            return {
                "error": "not verified",
                "verification_status": target_f.get("verification_status"),
            }, 400
        job = registry.core.store.get(job_id) or {}
        raw_target = job.get("target", "")
        if raw_target.startswith(("http://", "https://")):
            target_url = raw_target
        elif raw_target:
            target_url = f"http://{raw_target}"
        else:
            target_url = None
        scope_error = _validation_scope_error(target_url)
        if scope_error:
            return scope_error
        f_obj = Finding(
            kind=target_f["kind"], severity=target_f["severity"],
            source=target_f["source"], data=target_f["data"],
            raw_line=target_f["raw_line"],
            request_context=target_f.get("request_context") or {},
        )
        pkg_payloads = Path(__file__).resolve().parent.parent / "data" / "payloads"
        v = Validator(pkg_payloads)
        status, reason = v.revalidate(f_obj, target_url=target_url)
        registry.core.store.update_verification(job_id, seq, status, by="engine", reason=reason)
        return {"status": status, "reason": reason}

    @app.get("/api/coverage/<job_id>")
    def api_coverage(job_id: str):
        rows = registry.core.store.list_coverage(job_id)
        return jsonify({"job_id": job_id, "gaps": rows, "count": len(rows)})

    @app.post("/api/approvals/<job_id>/<int:seq>/resolve")
    def api_approval_resolve(job_id: str, seq: int):
        data = request.get_json(silent=True) or {}
        status = data.get("status", "").strip().lower()
        if status not in ("verified", "refuted"):
            return {"error": "status must be verified or refuted"}, 400
        findings = registry.core.store.get_findings(job_id) or []
        target_f = next((f for f in findings if f["seq"] == seq), None)
        if not target_f:
            return {"error": "finding not found"}, 404
        user = data.get("user") or "human"
        registry.core.store.update_verification(job_id, seq, status, by=f"human:{user}", reason=f"human review by {user}")
        return {"ok": True, "status": status, "by": f"human:{user}"}

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

        from whaxon.core.report import render_html, render_markdown
        job = registry.get(job_id)
        if job is None:
            return {"error": "unknown job"}, 404
        findings = registry.get_findings(job_id) or []
        fmt = request.args.get("format") or request.args.get("fmt") or "md"
        if fmt == "html":
            return Response(render_html(job, findings), mimetype="text/html")
        if fmt == "pdf":
            from whaxon.core.report import render_pdf
            try:
                pdf = render_pdf(job, findings)
            except Exception as e:
                return {"error": f"pdf render failed: {e}"}, 500
            return Response(pdf, mimetype="application/pdf",
                            headers={"Content-Disposition": f"attachment; filename=job-{job_id}.pdf"})
        return Response(render_markdown(job, findings), mimetype="text/markdown")

    @app.get("/api/jobs/<job_id>/findings")
    def get_job_findings(job_id: str):
        findings = registry.get_findings(job_id)
        if findings is None:
            return {"error": "unknown job"}, 404
        return jsonify(findings)

    @app.get("/api/jobs/<job_id>/output.txt")
    def download_output_txt(job_id: str):
        from flask import Response
        job = registry.get(job_id)
        if job is None:
            return {"error": "unknown job"}, 404
        lines = job.get("lines") or []
        body = chr(10).join((l.get("text") or "") for l in lines)
        return Response(body, mimetype="text/plain",
            headers={"Content-Disposition": f"attachment; filename=job-{job_id}.txt"})

    @app.get("/api/jobs/<job_id>/findings.csv")
    def download_findings_csv(job_id: str):
        import csv
        import io

        from flask import Response
        findings = registry.get_findings(job_id)
        if findings is None:
            return {"error": "unknown job"}, 404
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["kind", "severity", "source", "cvss", "cwe", "raw_line"])
        for f in findings:
            w.writerow([f.get("kind",""), f.get("severity",""), f.get("source",""),
                        f.get("cvss") or "", f.get("cwe",""),
                        (f.get("raw_line") or "").replace(chr(10), " ")])
        return Response(buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=job-{job_id}.csv"})

    @app.get("/api/jobs/<job_id>/findings.json")
    def download_findings_json(job_id: str):
        import json as _json

        from flask import Response
        findings = registry.get_findings(job_id)
        if findings is None:
            return {"error": "unknown job"}, 404
        body = _json.dumps(findings, indent=2)
        return Response(body, mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=job-{job_id}.json"})

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
        session_error = _msf_session_scope_error(session_id)
        if session_error:
            return session_error
        try:
            live = _pf.list_live(registry.core.msf, session_id)
        except Exception as e:
            return jsonify({"session_id": session_id, "error": str(e), "live": []})
        return jsonify({"session_id": session_id, "live": live})

    @app.post("/api/msf/sessions/<session_id>/portfwd")
    def pf_add(session_id: str):
        if not _legacy_msf_execution_enabled():
            return {
                "error": "Legacy Metasploit port-forward creation is disabled.",
                "legacy_execution_enabled": False,
                "approval_granted": False,
                "execution_submitted": False,
            }, 410
        from whaxon.core import portfwd as _pf
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {"error": "request body must be a JSON object"}, 400
        lport = data.get("lport")
        rhost = data.get("rhost")
        rport = data.get("rport")
        label = data.get("label", "")
        if not isinstance(rhost, str) or not rhost.strip() or lport is None or rport is None:
            return {"error": "lport, rhost, rport required"}, 400
        if not isinstance(label, str) or len(label) > 200:
            return {"error": "label must be a string of at most 200 characters"}, 400
        try:
            if isinstance(lport, bool) or isinstance(rport, bool):
                raise ValueError
            local_port = int(lport)
            remote_port = int(rport)
            if not 1 <= local_port <= 65535 or not 1 <= remote_port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            return {"error": "lport and rport must be integers between 1 and 65535"}, 400
        rhost = rhost.strip()
        session_error = _msf_session_scope_error(session_id)
        if session_error:
            return session_error
        try:
            match = _check_execution_scope(registry.core.scope, rhost)
        except Exception:
            app.logger.exception("Scope evaluation failed for port-forward destination")
            return {"error": "scope evaluation failed; port forward was not created"}, 503
        if match is None or not getattr(match, "allowed", False):
            reason = getattr(match, "reason", "target could not be confirmed in scope")
            return {"error": f"port-forward destination out of scope: {reason}",
                    "target": rhost, "matched_rule": getattr(match, "matched_rule", None)}, 403
        try:
            fwd = _pf.add_forward(registry.core.msf, session_id,
                                  local_port, rhost, remote_port, label.strip())
        except Exception as e:
            return {"error": str(e)}, 500
        try:
            from whaxon.core import pivot as _pivot
            conn = registry.core.store._conn()
            try:
                _pivot.add_edge(conn,
                                parent_kind="session", parent_id=str(session_id),
                                child_kind="forward", child_id=str(lport),
                                relation="tunnels_via",
                                evidence=f"{rhost}:{rport}")
                print(f"[pivot] wrote session={session_id} -> forward={lport} -> {rhost}:{rport}", flush=True)
            finally:
                try: conn.close()
                except Exception: pass
        except Exception as e:
            import traceback as _tb
            print(f"[pivot] WRITE FAILED: {type(e).__name__}: {e}", flush=True)
            _tb.print_exc()
        return jsonify(fwd.to_dict())

    @app.delete("/api/msf/sessions/<session_id>/portfwd")
    def pf_del(session_id: str):
        from whaxon.core import portfwd as _pf
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {"error": "request body must be a JSON object"}, 400
        lport = data.get("lport")
        if lport is None:
            return {"error": "lport required"}, 400
        try:
            if isinstance(lport, bool) or not isinstance(lport, (int, str)):
                raise ValueError
            if isinstance(lport, str) and not lport.strip().isdigit():
                raise ValueError
            local_port = int(lport)
            if not 1 <= local_port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            return {"error": "lport must be an integer between 1 and 65535"}, 400
        session_error = _msf_session_scope_error(session_id)
        if session_error:
            return session_error
        fwd = _pf.Forward(session_id=session_id, lport=local_port, rhost="", rport=0)
        return jsonify(_pf.remove_forward(registry.core.msf, fwd))

    @app.get("/api/dependencies")
    def api_dependencies_get():
        """Read-only dependency/environment diagnostics for the approved UI."""
        from whaxon.core.dependencies import collect_dependency_report

        try:
            report = collect_dependency_report(
                data_dir=Path(core.data_dir),
                include_optional=True,
                include_external=True,
            )
        except Exception as exc:
            app.logger.exception("Dependency diagnostics failed")
            return jsonify({"error": f"dependency diagnostics failed ({type(exc).__name__})"}), 500
        return jsonify(report)

    @app.post("/api/dependencies/verify")
    @limiter.limit("10 per minute")
    def api_dependencies_verify_post():
        """Run curated, bounded external-tool version probes without installing anything."""
        from whaxon.core.dependencies import collect_dependency_report

        try:
            report = collect_dependency_report(
                data_dir=Path(core.data_dir),
                include_optional=True,
                include_external=True,
                verify_external=True,
            )
        except Exception as exc:
            app.logger.exception("Dependency verification failed")
            return jsonify({"error": f"dependency verification failed ({type(exc).__name__})"}), 500
        return jsonify(report)

    @app.get("/api/dependencies/audit")
    def api_dependencies_audit_get():
        """Verify the local dependency-install audit chain without exposing event contents."""
        from whaxon.core.installer import verify_dependency_audit

        try:
            result = verify_dependency_audit()
        except OSError as exc:
            return jsonify({"valid": False, "reason": type(exc).__name__}), 500
        return jsonify(result), (200 if result.get("valid") else 409)
    @app.get("/api/dependencies/history")
    def api_dependencies_history_get():
        """Return recent locally persisted dependency readiness snapshots."""
        from whaxon.core.dependency_history import read_snapshots

        try:
            limit = int(request.args.get("limit", "20"))
            snapshots = read_snapshots(Path(core.data_dir), limit=limit)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except (OSError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify({"schema_version": 1, "snapshots": snapshots})

    @app.get("/api/dependencies/drift")
    def api_dependencies_drift_get():
        """Compare current read-only diagnostics with the latest saved snapshot."""
        from whaxon.core.dependencies import collect_dependency_report
        from whaxon.core.dependency_history import compare_with_latest

        try:
            report = collect_dependency_report(
                data_dir=Path(core.data_dir),
                include_optional=True,
                include_external=True,
            )
            drift = compare_with_latest(report, Path(core.data_dir))
        except Exception as exc:
            app.logger.exception("Dependency drift comparison failed")
            return jsonify({"error": f"dependency drift comparison failed ({type(exc).__name__})"}), 500
        return jsonify(drift)

    @app.post("/api/dependencies/snapshots")
    @limiter.limit("10 per minute")
    def api_dependencies_snapshot_post():
        """Explicitly save a bounded local readiness snapshot."""
        from whaxon.core.dependencies import collect_dependency_report
        from whaxon.core.dependency_history import record_snapshot

        try:
            report = collect_dependency_report(
                data_dir=Path(core.data_dir),
                include_optional=True,
                include_external=True,
            )
            snapshot = record_snapshot(report, Path(core.data_dir))
        except Exception as exc:
            app.logger.exception("Dependency snapshot could not be saved")
            return jsonify({"error": f"dependency snapshot failed ({type(exc).__name__})"}), 500
        return jsonify(snapshot), 201

    @app.post("/api/dependencies/plan")
    @limiter.limit("20 per minute")
    def api_dependencies_plan():
        """Create a read-only remediation preview; never executes its commands."""
        from whaxon.core.remediation import build_remediation_plan

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400
        dependency_ids = data.get("dependency_ids")
        if dependency_ids is not None and (
            not isinstance(dependency_ids, list)
            or len(dependency_ids) > 100
            or any(not isinstance(item, str) or not item or len(item) > 128
                   for item in dependency_ids)
        ):
            return jsonify({"error": "dependency_ids must be a list of valid dependency IDs"}), 400
        try:
            plan = build_remediation_plan(
                dependency_ids=dependency_ids,
                data_dir=Path(core.data_dir),
            )
        except Exception as exc:
            app.logger.exception("Dependency remediation planning failed")
            return jsonify({"error": f"dependency planning failed ({type(exc).__name__})"}), 500
        if plan["unknown_dependency_ids"]:
            return jsonify(plan), 400
        return jsonify(plan)

    @app.post("/api/dependencies/install")
    @limiter.limit("5 per minute")
    def api_dependencies_install():
        """Queue one allowlisted install after exact plan-ID approval."""
        from whaxon.core.dependency_jobs import start_install_operation

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400
        dependency_id = data.get("dependency_id")
        approved_plan_id = data.get("approved_plan_id")
        if (
            not isinstance(dependency_id, str)
            or not dependency_id
            or len(dependency_id) > 128
            or not isinstance(approved_plan_id, str)
            or not re.fullmatch(r"plan-[a-f0-9]{16}", approved_plan_id)
        ):
            return jsonify({"error": "dependency_id and a valid approved_plan_id are required"}), 400
        try:
            operation = start_install_operation(
                dependency_id, approved_plan_id, Path(core.data_dir)
            )
        except ValueError as exc:
            return jsonify({"error": str(exc), "installation_started": False}), 409
        except RuntimeError as exc:
            return jsonify({"error": str(exc), "installation_started": False}), 409
        except OSError as exc:
            app.logger.exception("Dependency installation could not be queued")
            return jsonify({
                "error": f"installation could not be queued ({type(exc).__name__})",
                "installation_started": False,
            }), 500
        return jsonify(operation), 202

    @app.post("/api/dependencies/install-batch")
    @limiter.limit("5 per minute")
    def api_dependencies_install_batch():
        """Queue a profile batch only after exact plan-ID approval."""
        from whaxon.core.dependency_jobs import start_install_batch_operation

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400
        dependency_ids = data.get("dependency_ids")
        approved_plan_id = data.get("approved_plan_id")
        if (
            not isinstance(dependency_ids, list)
            or not dependency_ids
            or len(dependency_ids) > 64
            or any(not isinstance(item, str) for item in dependency_ids)
            or not isinstance(approved_plan_id, str)
            or not re.fullmatch(r"plan-[a-f0-9]{16}", approved_plan_id)
        ):
            return jsonify({"error": "dependency_ids and a valid approved_plan_id are required"}), 400
        try:
            operation = start_install_batch_operation(
                dependency_ids, approved_plan_id, Path(core.data_dir)
            )
        except ValueError as exc:
            return jsonify({"error": str(exc), "installation_started": False}), 409
        except RuntimeError as exc:
            return jsonify({"error": str(exc), "installation_started": False}), 409
        except OSError as exc:
            app.logger.exception("Profile installation could not be queued")
            return jsonify({
                "error": f"profile installation could not be queued ({type(exc).__name__})",
                "installation_started": False,
            }), 500
        return jsonify(operation), 202

    @app.get("/api/dependencies/install/<operation_id>")
    def api_dependencies_install_status(operation_id: str):
        from whaxon.core.dependency_jobs import get_install_operation

        try:
            operation = get_install_operation(Path(core.data_dir), operation_id)
        except (ValueError, OSError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 400
        if operation is None:
            return jsonify({"error": "dependency operation not found"}), 404
        return jsonify(operation)

    @app.post("/api/dependencies/install/<operation_id>/cancel")
    @limiter.limit("10 per minute")
    def api_dependencies_install_cancel(operation_id: str):
        from whaxon.core.dependency_jobs import cancel_install_operation

        try:
            operation = cancel_install_operation(Path(core.data_dir), operation_id)
        except (ValueError, OSError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 400
        if operation is None:
            return jsonify({"error": "dependency operation not found"}), 404
        return jsonify(operation), 202

    @app.get("/api/settings")
    def api_settings_get():
        try:
            return jsonify(_redact_sensitive_settings(registry.core.settings.get()))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/settings")
    def api_settings_post():
        data = request.get_json(silent=True) or {}
        try:
            updated = registry.core.settings.save(data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        return jsonify(_redact_sensitive_settings(updated))

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

    @app.get("/api/pivot/candidates")
    def api_pivot_candidates():
        """Ask each live session for its routing table; return subnets it can
        reach that the host probably cannot."""
        from whaxon.core import autopivot as _ap
        results = []
        try:
            sessions = registry.core.msf.sessions()
        except Exception:
            sessions = {}
        for sid in sessions:
            try:
                cands = _ap.detect(registry.core.msf, sid)
            except Exception as e:
                cands = [{"error": str(e)}]
            results.append({"session_id": str(sid), "candidates": cands})
        return jsonify({"sessions": results})

    @app.get("/api/ui-v2/findings")
    def api_ui_v2_findings():
        """Return bounded persisted job/finding records for lightweight UI panels.

        Unlike the full report endpoint, this deliberately avoids report
        enrichment and pivot-chain generation so auxiliary pages remain
        responsive even when optional report enrichment is slow.
        """
        try:
            jobs = registry.core.store.history(limit=500)
            entries = []
            for job in jobs:
                entries.append({
                    "job": job,
                    "findings": registry.core.store.get_findings(job["id"]) or [],
                })
            return jsonify({"jobs": entries})
        except Exception as exc:
            return jsonify({
                "error": "Unable to load live findings",
                "detail": str(exc),
            }), 500

    @app.get("/api/report")
    def api_report():
        """Generate an engagement report.

        Query params:
          engagement=<name>   default: 'default'
          format=md|json      default: 'md'
        """
        from whaxon.core import report as _report
        eng = request.args.get("engagement") or "default"
        fmt = (request.args.get("format") or request.args.get("fmt") or "md").lower()
        jobs_filter = (request.args.get("jobs") or "").strip()
        data = _report._load(registry.core.store, eng)
        if jobs_filter:
            wanted = {j.strip() for j in jobs_filter.split(",") if j.strip()}
            if wanted:
                data["jobs"] = [e for e in data["jobs"] if e["job"]["id"] in wanted]
                from whaxon.core.report import _LOOT_KINDS, _SEV_ORDER
                sev = {sx: 0 for sx in _SEV_ORDER}
                loot = []
                for entry in data["jobs"]:
                    for f in entry["findings"]:
                        sx = (f.get("severity") or "info").lower()
                        if sx in sev:
                            sev[sx] += 1
                        if f.get("kind") in _LOOT_KINDS:
                            loot.append({**f, "_job_id": entry["job"]["id"]})
                data["severity_counts"] = sev
                data["finding_count"] = sum(sev.values())
                data["job_count"] = len(data["jobs"])
                data["loot"] = loot
        # attach pivot chains
        from whaxon.core import report as _report
        data["chains"] = _report.attach_chains(registry.core.store)
        # Coverage is evidence of work that was not performed. Keep the same
        # persisted records in the API exports as the CLI report path.
        for entry in data.get("jobs", []):
            entry["coverage"] = registry.core.store.list_coverage(entry["job"]["id"])
        if fmt == "json":
            resp = jsonify(data)
            resp.headers["Content-Disposition"] = "attachment; filename=whaxon-report.json"
            return resp
        if fmt in ("html", "htm"):
            resp = app.response_class(_report.to_html(data), mimetype="text/html")
            resp.headers["Content-Disposition"] = "attachment; filename=whaxon-report.html"
            return resp
        md = _report.to_markdown(data, chains=data.get("chains", []))
        if fmt == "pdf":
            try:
                pdf = _report.to_pdf_bytes(data)
            except Exception as e:
                return {"error": f"pdf render failed: {e}"}, 500
            return app.response_class(pdf, mimetype="application/pdf",
                headers={"Content-Disposition": "attachment; filename=whaxon-report.pdf"})
        if fmt == "whaxon":
            import datetime as _dt
            import hashlib as _hashlib
            import json as _json
            canonical = _json.dumps(data, default=str, sort_keys=True)
            digest = _hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            from whaxon import __version__ as _whaxon_version
            envelope = {
                "format": "whaxon",
                "version": 1,
                "generated": data.get("generated") or _dt.datetime.now().isoformat(timespec="seconds"),
                "tool": "whaxon/" + _whaxon_version,
                "engagement": eng,
                "integrity": "sha256:" + digest,
                "integrity_note": "SHA-256 covers the payload for integrity checking only; the envelope is unsigned and has no external trust anchor, so it does not prove authenticity.",
                "payload": data,
            }
            out = _json.dumps(envelope, default=str, indent=2)
            resp = app.response_class(out, mimetype="application/json")
            resp.headers["Content-Disposition"] = "attachment; filename=whaxon-report.whaxon"
            return resp
        resp = app.response_class(md, mimetype="text/markdown")
        resp.headers["Content-Disposition"] = "attachment; filename=whaxon-report.md"
        return resp

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

    @app.get("/ui-v2/run")
    def ui_v2_run():
        """Canonical run and orchestration page backed by the live job API."""
        return render_template("ui_v2_run.html")

    @app.get("/ui-v2")
    @app.get("/ui-v2/dashboard")
    def ui_v2_home():
        """Canonical dashboard backed by live WHAXON state."""
        return render_template("ui_v2_dashboard.html")

    @app.get("/ui-v2/findings")
    def ui_v2_findings():
        """Canonical findings design, wired to live report and validation APIs."""
        return render_template("ui_v2_findings.html")

    @app.get("/ui-v2/scope")
    def ui_v2_scope():
        """Canonical scope and targets page backed by the live ScopeManager."""
        return render_template("ui_v2_scope.html")

    @app.get("/ui-v2/report")
    def ui_v2_report():
        """Canonical report and PTES page backed by live report APIs."""
        return render_template("ui_v2_report.html")

    @app.get("/ui-v2/reports")
    def ui_v2_reports():
        """Canonical report page backed by the live report API."""
        return render_template("ui_v2_reports.html")

    @app.get("/ui-v2/history")
    def ui_v2_history():
        """Canonical job history page backed by recorded WHAXON jobs."""
        return render_template("ui_v2_history.html")

    @app.get("/ui-v2/diagnostics")
    def ui_v2_diagnostics():
        """Canonical diagnostics page backed by live health and tool APIs."""
        return render_template("ui_v2_diagnostics.html")

    @app.get("/ui-v2/evidence")
    def ui_v2_evidence():
        """Canonical evidence inspector backed by recorded job evidence."""
        return render_template("ui_v2_evidence.html")

    @app.get("/ui-v2/ai")
    def ui_v2_ai():
        """Canonical AI strategy gate backed by live AI run and scope APIs."""
        return render_template("ui_v2_ai.html")

    @app.get("/ui-v2/retest")
    def ui_v2_retest():
        """Canonical remediation retest page backed by verified findings."""
        return render_template("ui_v2_retest.html")

    @app.get("/ui-v2/chains")
    def ui_v2_chains():
        """Canonical attack-chain page backed by stored pivot graph data."""
        return render_template("ui_v2_chains.html")

    @app.get("/ui-v2/adapters")
    def ui_v2_adapters():
        """Canonical adapter manager backed by the live tool catalog."""
        return render_template("ui_v2_adapters.html")

    @app.get("/ui-v2/settings")
    def ui_v2_settings():
        """Read-only settings and API explorer with secret redaction."""
        return render_template("ui_v2_settings.html")

    @app.get("/ui-v2/audit")
    def ui_v2_audit():
        """Show recorded execution metadata without inventing cryptographic claims."""
        return render_template("ui_v2_audit.html")

    @app.get("/ui-v2/monitoring")
    def ui_v2_monitoring():
        return render_template("ui_v2_monitoring.html")

    @app.get("/ui-v2/bas")
    def ui_v2_bas():
        return render_template("ui_v2_bas.html")

    @app.get("/ui-v2/bug-bounty")
    def ui_v2_bug_bounty():
        return render_template("ui_v2_bug_bounty.html")

    @app.get("/ui-v2/compliance")
    def ui_v2_compliance():
        return render_template("ui_v2_compliance.html")

    @app.get("/ui-v2/ptaas")
    def ui_v2_ptaas():
        return render_template("ui_v2_ptaas.html")

    @app.get("/ui-v2/threat-intel")
    def ui_v2_threat_intel():
        return render_template("ui_v2_threat_intel.html")

    @app.get("/ui-v2/approvals")
    def ui_v2_approvals():
        return render_template("ui_v2_approvals.html")

    @app.get("/ui")
    def ui():
        return render_template("index.html")

    @app.post("/api/jobs/<job_id>/cancel")
    def cancel_job(job_id: str):
        if core.store.is_engine_v2_execution_job(job_id):
            return jsonify({
                "ok": False,
                "job_id": job_id,
                "error": "Engine V2 jobs must be cancelled through their durable workflow run request",
                "cancellation_endpoint": "/api/v2/workflow-runs/<request_id>/cancel",
            }), 409
        ok = _cancel_job_blocking(core, job_id)
        return {"ok": ok, "job_id": job_id}

    @app.get("/")
    def index():
        from flask import redirect
        return redirect("/ui-v2")

    return app


def create_app_factory(host: str | None = None, port: int | None = None):
    """Gunicorn entry point. Reads env vars, with optional explicit host/port.

    When host or port is provided, WHAXON_HOST/WHAXON_PORT are also set in
    os.environ so create_app's exposed-on-network warning fires correctly.
    """
    if host is None:
        host = os.environ.get("WHAXON_HOST", "127.0.0.1")
    if port is None:
        port = int(os.environ.get("WHAXON_PORT", "5001"))

    # Never synthesize the known demo credentials for a network-facing
    # listener. Loopback development remains convenient; remote deployments
    # must explicitly configure a non-default username and password.
    import ipaddress
    try:
        loopback = ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    configured_user = os.environ.get("WHAXON_AUTH_USER", "").strip()
    configured_pass = os.environ.get("WHAXON_AUTH_PASS", "")
    configured_hash = os.environ.get("WHAXON_AUTH_PASS_HASH", "").strip()
    if not loopback and not _remote_auth_ready(
        configured_user, configured_pass, configured_hash
    ):
        raise RuntimeError(
            "Refusing to expose WHAXON on a non-loopback host without "
            "explicit non-default authentication credentials."
        )

    os.environ["WHAXON_HOST"] = host
    os.environ["WHAXON_PORT"] = str(port)
    os.environ.setdefault("WHAXON_AUTH_USER", "whaxon")
    if not os.environ.get("WHAXON_AUTH_PASS_HASH", "").strip():
        os.environ["WHAXON_AUTH_PASS_HASH"] = _hash_pw(
            os.environ.get("WHAXON_AUTH_PASS", "whaxon")
        )
    data_dir = Path(os.environ.get("WHAXON_DATA", "data"))
    core = Core(data_dir=data_dir)
    registry = JobRegistry(core)
    runner = AsyncRunner(core)
    app = create_app(core, registry, runner)
    # Recover queued (not running/uncertain) requests after service restart.
    if not _v2_worker_externally_supervised():
        runner.submit(lambda: asyncio.run(core.drain_workflow_run_requests()))
    return app


def main(args: list[str] | None = None) -> None:
    host = os.environ.get("WHAXON_HOST", "127.0.0.1")
    port = int(os.environ.get("WHAXON_PORT", "5001"))
    import ipaddress
    try:
        loopback = ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"

    # Convenience defaults are permitted only for loopback development.
    # Validate remote credentials before creating a fallback hash; otherwise a
    # custom username with an omitted password could inherit the demo password.
    if not loopback:
        configured_user = os.environ.get("WHAXON_AUTH_USER", "").strip()
        configured_pass = os.environ.get("WHAXON_AUTH_PASS", "")
        configured_hash = os.environ.get("WHAXON_AUTH_PASS_HASH", "").strip()
        if not _remote_auth_ready(
            configured_user, configured_pass, configured_hash
        ):
            raise SystemExit(
                "Refusing network exposure without explicit non-default "
                "WHAXON_AUTH_USER and WHAXON_AUTH_PASS or WHAXON_AUTH_PASS_HASH."
            )
    else:
        os.environ.setdefault("WHAXON_AUTH_USER", "whaxon")

    # Hash the explicitly supplied password only after remote credentials have
    # passed validation. This keeps custom remote credentials usable without
    # ever manufacturing a known password for an exposed listener.
    if not os.environ.get("WHAXON_AUTH_PASS_HASH", "").strip():
        os.environ["WHAXON_AUTH_PASS_HASH"] = _hash_pw(
            os.environ.get("WHAXON_AUTH_PASS", "whaxon")
        )

    data_dir = Path(os.environ.get("WHAXON_DATA", "data"))

    core = Core(data_dir=data_dir)
    registry = JobRegistry(core)
    runner = AsyncRunner(core)

    app = create_app(core, registry, runner)
    if not _v2_worker_externally_supervised():
        runner.submit(lambda: asyncio.run(core.drain_workflow_run_requests()))
    auth_user = os.environ.get("WHAXON_AUTH_USER", "")
    auth_on = "enabled" if auth_user else "DISABLED"
    print()
    print("  WHAXON web interface")
    print(f"  → http://{host}:{port}/ui-v2")
    print(f"  → data directory: {data_dir}")
    print(f"  → authentication: {auth_on}" + (f" (user: {auth_user})" if auth_user else ""))
    print()
    auth_pass_effective = os.environ.get("WHAXON_AUTH_PASS", "whaxon")
    is_default_creds = (auth_user == "whaxon" and auth_pass_effective == "whaxon")
    is_loopback = host in ("127.0.0.1", "::1")
    if is_default_creds and not is_loopback:
        print()
        print("  ERROR: default credentials (whaxon/whaxon) on non-loopback host " + host + ".")
        print("  Set WHAXON_AUTH_USER and WHAXON_AUTH_PASS before exposing on a network.")
        print("  Refusing to start.")
        raise SystemExit(1)
    if is_default_creds:
        print("  NOTE: default credentials (whaxon/whaxon) in use. Safe on loopback only.")
        print("  Change WHAXON_AUTH_USER / WHAXON_AUTH_PASS before exposing on a network.")
        print()
    # Dev server. whaxon serve uses waitress via serve.py instead.
    app.run(host=host, port=port, debug=False, use_reloader=False)
