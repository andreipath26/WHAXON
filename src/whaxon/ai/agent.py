"""The agent: pure planner side of the planner/executor split.

The Agent owns no runner, no store, no subprocess. It takes context
and returns an Action. The executor (in whaxon.core) owns the loop,
the validation, and the actual tool invocation.

This split is what keeps the AI layer from being able to do anything
the executor has not explicitly authorised.
"""
from __future__ import annotations

from typing import Any

from .actions import Action
from .provider import NullProvider, Provider


DEFAULT_MAX_STEPS = 12
DEFAULT_MIN_CONFIDENCE = 0.55


class Agent:
    """Stateless step planner. One instance per run.

    The executor calls ``next_action()`` repeatedly, feeding back the
    results of each step via ``history``. The Agent does not loop.
    """

    def __init__(
        self,
        provider: Provider | None = None,
        max_steps: int = DEFAULT_MAX_STEPS,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    ) -> None:
        self.provider = provider or NullProvider()
        self.max_steps = max_steps
        self.min_confidence = min_confidence

    def audit(self, goal: str) -> dict[str, Any]:
        """Step zero: assess whether the prompt is workable at all.

        Called by the executor before the loop begins. If the provider
        is Null, this returns feasible=True with an empty extraction —
        the loop will then immediately stop at step 1.
        """
        return self.provider.audit_prompt(goal)

    def next_action(
        self,
        goal: str,
        history: list[dict[str, Any]],
        catalog: list[dict[str, Any]],
        scope_summary: dict[str, Any],
        step: int,
    ) -> Action:
        """Ask the provider for one Action. No side effects.
"""
        if step > self.max_steps:
            return Action.stop(
                rationale=f"step budget exhausted ({self.max_steps})",
                ai_source=self.provider.name,
            )
        action = self.provider.plan_step(
            goal=goal,
            history=history,
            catalog=catalog,
            scope_summary=scope_summary,
            step=step,
            max_steps=self.max_steps,
        )
        if action.confidence and action.confidence < self.min_confidence \
                and action.kind == "run_tool":
            return Action.ask_human(
                rationale=f"proposed action below confidence floor "
                          f"({action.confidence:.2f} < {self.min_confidence:.2f}): "
                          + (action.rationale or "no rationale"),
                ai_source=self.provider.name,
            )
        return action