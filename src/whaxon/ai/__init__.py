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
from .agent import DEFAULT_MAX_STEPS, DEFAULT_MIN_CONFIDENCE, Agent
from .executor import Executor, ExecutorError, ExecutorLimits
from .phases import DEFAULT_PHASE, PHASES
from .phases import is_valid as phase_is_valid
from .provider import NullProvider, Provider
from .scope_policy import DEFAULT_POLICY as DEFAULT_SCOPE_POLICY
from .scope_policy import POLICIES as SCOPE_POLICIES
from .scope_policy import read_policy as read_scope_policy

__all__ = [
    "DEFAULT_MAX_STEPS",
    "DEFAULT_MIN_CONFIDENCE",
    "DEFAULT_PHASE",
    "DEFAULT_SCOPE_POLICY",
    "PHASES",
    "SCOPE_POLICIES",
    "Action",
    "ActionResult",
    "Agent",
    "Executor",
    "ExecutorError",
    "ExecutorLimits",
    "NullProvider",
    "Provider",
    "phase_is_valid",
    "read_scope_policy",
]