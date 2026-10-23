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

from collections.abc import Callable

from .events import EventBus, JobFindings, JobStarted
from .findings import Finding
from .scope import ScopeManager

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

        job_id = f"recon:{target}"
        resolved = self._resolve(findings)
        # Publish JobStarted first so the store creates the jobs row and
        # sets its target — the correlator derives target from that row.
        self._bus.publish(JobStarted(job_id=job_id, tool_id="recon", target=target))
        self._bus.publish(JobFindings(job_id=job_id, findings=tuple(resolved)))
        return job_id

    # ---- internals ----

    def _run_checks(self, target: str, checks: list[str] | None) -> list[Finding]:
        names = checks if checks is not None else list(self._checks.keys())
        findings: list[Finding] = []
        for name in names:
            check = self._checks.get(name)
            if check is None:
                continue
            try:
                findings.extend(check(target))
            except Exception as exc:  # one failing check must not kill the run
                findings.append(Finding(
                    kind="recon_error",
                    severity="info",
                    source=f"recon:{name}",
                    data={"target": target, "check": name, "error": str(exc)},
                    raw_line=f"recon {name} failed: {type(exc).__name__}: {exc}",
                ))
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
        job_id = f"recon:oos:{target}"
        resolved = self._resolve([oos])
        self._bus.publish(JobStarted(job_id=job_id, tool_id="recon", target=target))
        self._bus.publish(JobFindings(job_id=job_id, findings=tuple(resolved)))
