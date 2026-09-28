"""Planner provider interface.

A Provider is the thing that actually thinks. Today: NullProvider,
which plans nothing. Later: an OpenAI/Anthropic/local implementation
that takes a prompt + context and emits an Action.

The Provider must never import from core or adapters. It receives
plain dicts and returns Action / str. Anything richer is a leak.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .actions import Action


class Provider(ABC):
    """Emit a single Action given a goal and the history so far.

    Called once per step by the executor loop. Deterministic code owns
    the loop; the provider only proposes.
    """

    name: str = "unnamed"

    @abstractmethod
    def plan_step(
        self,
        goal: str,
        history: list[dict[str, Any]],
        catalog: list[dict[str, Any]],
        scope_summary: dict[str, Any],
        step: int,
        max_steps: int,
        phase: str = "recon",
    ) -> Action:
        """Return exactly one Action for the next step.

        Args:
            goal: the original user prompt, unmodified.
            history: list of ActionResult dicts from prior steps.
            catalog: list of tool dicts (id, name, category, args, ...).
            scope_summary: current scope state as a dict.
            step: 1-based step counter.
            max_steps: hard cap; provider should plan to finish by then.
            phase: current kill-chain phase (step 2 of the migration plan).
        """

    def audit_prompt(self, goal: str) -> dict[str, Any]:
        """Assess the prompt before planning.

        Returns a dict with at least:
            feasible: bool
            reason: str
            extracted: dict   (target, constraints, intent)

        Default implementation accepts everything — real providers
        override this to reject ambiguous or out-of-scope goals.
        """
        return {"feasible": True, "reason": "", "extracted": {}}


class NullProvider(Provider):
    """Default provider: plans nothing, safely.

    The executor loop with this provider will audit the prompt, then
    receive a single stop Action. No tools run. No surprise network
    calls. This is the state of the world until a real provider is
    wired and WHAXON_AI_ENABLED=true.
    """

    name = "null"

    def plan_step(self, goal, history, catalog, scope_summary, step, max_steps, phase="recon"):
        return Action.stop(
            rationale="No AI provider configured. Set WHAXON_AI_ENABLED=true "
                      "and configure a provider to enable autonomous planning.",
            ai_source="null",
        )