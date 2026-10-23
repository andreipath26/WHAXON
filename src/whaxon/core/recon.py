"""Passive recon checks. Emit findings through the standard event pipeline.

Recon is not a tool: no subprocess, no catalog entry, no argv. Each check
speaks a protocol (DNS, TLS, HTTP) directly and returns Finding objects.
A single ReconRunner:

  1. Gates the target through ScopeManager. Out-of-scope targets are never
     touched — a single informational finding is emitted instead, surfacing
     the discovery for human authorization via the override log.
  2. Runs each registered check in isolation; a failing check produces a
     recon_error finding without aborting the run.
  3. Resolves findings through the same severity/vulndb path the tool runner
     uses (injected as `resolver`).
  4. Publishes JobStarted then JobFindings. The existing subscribers — store
     persister, correlator, suggester, automator — fire exactly as they do
     for tool runs. No parallel machinery.

The ReconRunner itself should not need to change as checks are added. New
checks are registered via `register()` and live in recon_checks.py.
"""
from __future__ import annotations

import os as _os_trace
import sys as _sys_trace
import uuid
from collections.abc import Callable

from .events import EventBus, JobFindings, JobStarted
from .findings import Finding
from .scope import ScopeManager


def _install_socket_trace() -> None:
    """Print every socket connect/send/recv to stderr. Enabled via WHAXON_TRACE=1."""
    if _os_trace.environ.get("WHAXON_TRACE") != "1":
        return
    import socket as _sock

    _orig_connect = _sock.socket.connect
    _orig_recv = _sock.socket.recv

    def _connect(self, addr):
        _sys_trace.stderr.write(f"[trace] connect -> {addr}\n")
        _sys_trace.stderr.flush()
        return _orig_connect(self, addr)

    def _recv(self, bufsize, *a, **k):
        _sys_trace.stderr.write(f"[trace] recv waiting ({bufsize}B)\n")
        _sys_trace.stderr.flush()
        r = _orig_recv(self, bufsize, *a, **k)
        _sys_trace.stderr.write(f"[trace] recv got {len(r)}B\n")
        _sys_trace.stderr.flush()
        return r

    _sock.socket.connect = _connect  # type: ignore[method-assign]
    _sock.socket.recv = _recv  # type: ignore[method-assign]


_install_socket_trace()

ReconCheck = Callable[[str], list[Finding]]


class ReconRunner:
    """Runs named recon checks against a target through the event pipeline."""

    def __init__(self, scope: ScopeManager, bus: EventBus, resolver: Callable) -> None:
        self._scope = scope
        self._bus = bus
        self._resolve = resolver
        self._checks: dict[str, ReconCheck] = {}

    def register(self, name: str, check: ReconCheck) -> None:
        """Register a check. Calling register() twice with the same name
        replaces the previous check (useful for tests / overrides)."""
        self._checks[name] = check

    def run(self, target: str, checks: list[str] | None = None) -> str | None:
        """Run recon on target.

        Returns the synthetic job_id on success, or None if the target was
        out of scope (an out-of-scope discovery finding is still emitted).
        """
        match = self._scope.check(target)

        if not match.allowed:
            self._emit_out_of_scope(target, match)
            return None

        findings = self._run_checks(target, checks)
        if not findings:
            return None

        job_id = f"recon:{target}:{uuid.uuid4().hex[:12]}"
        resolved = self._resolve(findings)
        # Publish JobStarted first so the store creates the jobs row and
        # sets its target — the correlator derives target from that row.
        self._bus.publish(JobStarted(job_id=job_id, tool_id="recon", target=target))
        self._bus.publish(JobFindings(job_id=job_id, findings=tuple(resolved)))
        return job_id

    # ---- internals ----

    def _run_checks(self, target: str, checks: list[str] | None) -> list[Finding]:
        """Run every named check concurrently. Each check owns its own thread
        and its own timeout; a hanging check cannot stall the others.
        Findings are returned in the original check order so output is
        deterministic even though execution is parallel."""
        import sys as _sys
        import time as _time
        from concurrent.futures import ThreadPoolExecutor, as_completed

        names = checks if checks is not None else list(self._checks.keys())
        # Keep only names we actually have a check for, preserving order.
        runnable = [n for n in names if self._checks.get(n) is not None]
        if not runnable:
            return []

        _trace = _os_trace.environ.get("WHAXON_RECON_TRACE") == "1"
        if _trace:
            started = _time.strftime('%H:%M:%S')
            _sys.stderr.write(f"[recon] dispatching {len(runnable)} checks in parallel @ {started}\n")
            _sys.stderr.flush()

        def _run_one(name: str):
            _t0 = _time.monotonic()
            if _trace:
                _sys.stderr.write(f"[recon] >>> START {name}\n")
                _sys.stderr.flush()
            try:
                res = self._checks[name](target)
                if _trace:
                    elapsed = _time.monotonic() - _t0
                    _sys.stderr.write(
                        f"[recon] <<< DONE  {name} ({len(res)} findings, {elapsed:.2f}s)\n"
                    )
                    _sys.stderr.flush()
                return (name, res, None)
            except Exception as exc:
                if _trace:
                    elapsed = _time.monotonic() - _t0
                    _sys.stderr.write(
                        f"[recon] !!! FAIL  {name} ({elapsed:.2f}s): "
                        f"{type(exc).__name__}: {exc}\n"
                    )
                    _sys.stderr.flush()
                return (name, [], exc)

        results: dict[str, list[Finding]] = {}
        errors: dict[str, Exception] = {}

        # max_workers = number of checks: they are independent, so let them
        # all start immediately. Wall clock = slowest single check.
        with ThreadPoolExecutor(max_workers=len(runnable),
                                thread_name_prefix="recon") as pool:
            futures = {pool.submit(_run_one, n): n for n in runnable}
            for fut in as_completed(futures):
                name, res, exc = fut.result()
                if exc is not None:
                    errors[name] = exc
                else:
                    results[name] = res

        # Rebuild findings in the original check order.
        findings: list[Finding] = []
        for name in runnable:
            if name in errors:
                exc = errors[name]
                findings.append(Finding(
                    kind="recon_error",
                    severity="info",
                    source=f"recon:{name}",
                    data={"target": target, "check": name, "error": str(exc)},
                    raw_line=f"recon {name} failed: {type(exc).__name__}: {exc}",
                ))
            else:
                findings.extend(results.get(name, []))
        return findings

    def _emit_out_of_scope(self, target: str, match) -> None:
        oos = Finding(
            kind="recon_out_of_scope",
            severity="info",
            source="recon",
            data={
                "target": target,
                "reason": match.reason,
                "matched_rule": match.matched_rule,
            },
            raw_line=f"recon: {target} out of scope ({match.reason})",
            remediation="Add the target to scope via the override log before scanning.",
            impact="Out-of-scope discovery. Not touched; surfaced for review.",
        )
        job_id = f"recon:oos:{target}:{uuid.uuid4().hex[:12]}"
        resolved = self._resolve([oos])
        self._bus.publish(JobStarted(job_id=job_id, tool_id="recon", target=target))
        self._bus.publish(JobFindings(job_id=job_id, findings=tuple(resolved)))
