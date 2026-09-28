"""Executor: the deterministic half of the planner/executor split.

This module is the ONLY place where an AI-proposed Action can become
a real tool invocation. It validates every Action against the
catalog and scope, and refuses anything that does not comply.

Design rules:
  1. The executor imports from whaxon.core — the reverse is forbidden.
  2. Validation happens *before* the runner is called.
  3. Every executed Action is persisted with actor=ai and the prompt.
  4. ask_human and stop produce no side effects.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable

from .actions import Action, ActionResult
from .agent import DEFAULT_MAX_STEPS, DEFAULT_MIN_CONFIDENCE, Agent


@dataclass
class ExecutorLimits:
    max_steps: int = DEFAULT_MAX_STEPS
    max_wall_seconds: float = 900.0
    min_confidence: float = DEFAULT_MIN_CONFIDENCE


class ExecutorError(RuntimeError):
    pass


class Executor:
    """Drives the plan/validate/run loop.

    The Executor holds *callables*, not objects from core. That keeps
    this file free of core imports and lets tests inject fakes. The
    wiring is done at the interface layer (CLI, web route).

    Callables expected:
        catalog_lookup(tool_id) -> dict | None
        scope_check(target) -> tuple[bool, str]
        run_tool(tool_id, target, extra_args, job_id) -> str  (job id)
        get_findings(job_id) -> list[dict]
    """

    def __init__(
        self,
        agent: Agent,
        catalog_lookup: Callable[[str], dict | None],
        scope_check: Callable[[str], tuple[bool, str]],
        run_tool: Callable[[str, str, str, str], Awaitable[str]],
        get_findings: Callable[[str], list[dict]],
        catalog_all: Callable[[], Iterable[dict]],
        scope_summary: Callable[[], dict],
        limits: ExecutorLimits | None = None,
        on_action: Callable[[Action], None] | None = None,
        on_result: Callable[[ActionResult], None] | None = None,
        target_lock: str | None = None,
        ask_human: Callable[[Action], Awaitable[str]] | None = None,
        phase_get: Callable[[], str] | None = None,
        phase_set: Callable[[str], None] | None = None,
        scope_policy: str = "strict",
    ) -> None:
        self.agent = agent
        self.catalog_lookup = catalog_lookup
        self.scope_check = scope_check
        self.run_tool = run_tool
        self.get_findings = get_findings
        self.catalog_all = catalog_all
        self.scope_summary = scope_summary
        self.limits = limits or ExecutorLimits()
        self.target_lock = target_lock or None
        self.ask_human = ask_human
        self.phase_get = phase_get or (lambda: "recon")
        self.phase_set = phase_set or (lambda p: None)
        self.scope_policy = scope_policy
        self.max_consecutive_failures = 2
        self.on_action = on_action or (lambda a: None)
        self.on_result = on_result or (lambda r: None)

    async def run(self, goal: str, job_id_prefix: str = "ai",
                  target_lock: str | None = None) -> list[ActionResult]:
        """Execute the loop until stop, ask_human, budget, or error."""
        audit = self.agent.audit(goal)
        if not audit.get("feasible", False):
            return [ActionResult(
                action=Action.stop(rationale=f"prompt not feasible: {audit.get(chr(39)+chr(39))}"),
                ok=False,
                error=audit.get("reason", "rejected by provider audit"),
            )]

        if target_lock is not None:
            self.target_lock = target_lock
        history: list[ActionResult] = []
        consecutive_failures = 0
        for step in range(1, self.limits.max_steps + 1):
            action = self.agent.next_action(
                goal=goal,
                history=[r.to_dict() for r in history],
                catalog=[dict(t) for t in self.catalog_all()],
                scope_summary=self.scope_summary(),
                step=step,
                phase=self.phase_get(),
            )
            self.on_action(action)

            if action.kind == "stop":
                result = ActionResult(action=action, ok=True,
                                      summary=action.rationale)
                history.append(result)
                self.on_result(result)
                return history

            if action.kind == "ask_human":
                result = ActionResult(action=action, ok=True,
                                      summary=action.rationale)
                history.append(result)
                self.on_result(result)
                if self.ask_human is None:
                    return history
                answer = await self.ask_human(action)
                ack = ActionResult(
                    action=Action.stop(
                        rationale=f"human answered: {answer!r}",
                        ai_source="human"),
                    ok=True,
                    summary=answer,
                )
                history.append(ack)
                self.on_result(ack)
                if action.proposed_phase and answer.strip().lower() in ("y", "yes"):
                    from .phases import is_valid, PHASES
                    if not is_valid(action.proposed_phase):
                        nack = ActionResult(
                            action=Action.stop(
                                rationale=f"rejected invalid phase: {action.proposed_phase!r}",
                                ai_source="human"),
                            ok=False,
                            error=f"invalid phase {action.proposed_phase!r}; valid: {list(PHASES)}",
                        )
                        history.append(nack)
                        self.on_result(nack)
                    else:
                        self.phase_set(action.proposed_phase)
                        tx = ActionResult(
                            action=Action.stop(
                                rationale=f"phase transitioned to {action.proposed_phase}",
                                ai_source="human"),
                            ok=True,
                            summary=action.proposed_phase,
                        )
                        history.append(tx)
                        self.on_result(tx)
                continue

            if action.kind != "run_tool":
                result = ActionResult(action=action, ok=False,
                                      error=f"unknown action kind: {action.kind}")
                history.append(result)
                self.on_result(result)
                continue

            result = await self._validate_and_run(action, job_id_prefix, step, history)
            history.append(result)
            self.on_result(result)
            if result.ok:
                consecutive_failures = 0
            else:
                consecutive_failures += 1
                if consecutive_failures >= self.max_consecutive_failures:
                    halt = ActionResult(
                        action=Action.stop(
                            rationale=f"halting: {consecutive_failures} consecutive failed steps",
                            ai_source=self.agent.provider.name),
                        ok=True,
                        summary="halting on stagnation",
                    )
                    history.append(halt)
                    self.on_result(halt)
                    return history

        return history

    def _already_ran(self, action, history):
        for r in history:
            a = r.action
            if (a.kind == 'run_tool' and r.ok
                    and a.tool_id == action.tool_id
                    and a.target == action.target):
                return True
        return False

    async def _validate_and_run(self, action: Action, job_id_prefix: str,
                                step: int, history) -> ActionResult:
        if not action.tool_id:
            return ActionResult(action=action, ok=False,
                                error="run_tool without tool_id")
        tool = self.catalog_lookup(action.tool_id)
        if tool is None:
            return ActionResult(action=action, ok=False,
                                error=f"tool not in catalog: {action.tool_id}")
        if not action.target:
            return ActionResult(action=action, ok=False,
                                error="run_tool without target")
        if self.target_lock is not None and action.target != self.target_lock:
            return ActionResult(
                action=action, ok=False,
                error=("target mismatch: goal locks target to "
                       + repr(self.target_lock) + " but action proposed "
                       + repr(action.target)),
            )
        allowed, reason = self.scope_check(action.target)
        if not allowed:
            return ActionResult(action=action, ok=False,
                                error=f"out of scope: {reason}")
        if self._already_ran(action, history):
            return ActionResult(
                action=action, ok=False,
                error='repeated action; already run successfully',
            )
        job_id = f"{job_id_prefix}-{step}-{action.tool_id}"
        try:
            real_job_id = await self.run_tool(action.tool_id, action.target,
                                              action.extra_args or "", job_id)
        except Exception as e:
            return ActionResult(action=action, ok=False,
                                error=f"run_tool raised: {e!r}")
        try:
            findings = self.get_findings(real_job_id) or []
        except Exception:
            findings = []
        return ActionResult(
            action=action,
            ok=True,
            job_id=real_job_id,
            summary=f"{action.tool_id} ran against {action.target}",
            findings=findings,
        )