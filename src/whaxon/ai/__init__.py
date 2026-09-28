"""WHAXON AI layer: planner/executor split.

Public surface:
    Action        — the only thing a planner may emit
    ActionResult  — what the executor returns per step
    Provider      — planner interface (NullProvider by default)
    Agent         — stateless step planner
    Executor      — deterministic loop owner

Boundary rule (enforced by CI):
    whaxon.core and whaxon.adapters MUST NOT import from whaxon.ai.
"""
from .actions import Action, ActionResult
from .agent import Agent, DEFAULT_MAX_STEPS, DEFAULT_MIN_CONFIDENCE
from .executor import Executor, ExecutorLimits, ExecutorError
from .phases import PHASES, DEFAULT_PHASE, is_valid as phase_is_valid
from .provider import NullProvider, Provider

__all__ = [
    "Action",
    "ActionResult",
    "Provider",
    "NullProvider",
    "Agent",
    "Executor",
    "ExecutorLimits",
    "ExecutorError",
    "DEFAULT_MAX_STEPS",
    "DEFAULT_MIN_CONFIDENCE",
    "PHASES",
    "DEFAULT_PHASE",
    "phase_is_valid",
]