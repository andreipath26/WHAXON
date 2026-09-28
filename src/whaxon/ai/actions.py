"""The Action contract: the only thing the AI layer may emit.

An Action is a *proposal*, not a command. It is validated by the
executor (owned by whaxon.core) before anything runs. This module has
no imports from core or adapters — it is a pure data contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


ActionKind = Literal["run_tool", "ask_human", "stop"]


@dataclass(frozen=True)
class Action:
    """A single step proposed by the planner.

    The planner may only emit one of these three kinds. It cannot emit
    shell strings, raw argv, or tool ids outside the catalog. The
    executor is the sole authority on whether an Action runs.
    """

    kind: ActionKind
    tool_id: str | None = None
    target: str | None = None
    extra_args: str = ""
    rationale: str = ""
    confidence: float = 0.0
    ai_source: str = ""
    proposed_phase: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "tool_id": self.tool_id,
            "target": self.target,
            "extra_args": self.extra_args,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "ai_source": self.ai_source,
            "proposed_phase": self.proposed_phase,
        }

    @classmethod
    def run_tool(cls, tool_id: str, target: str, extra_args: str = "",
                 rationale: str = "", confidence: float = 0.0,
                 ai_source: str = "") -> "Action":
        return cls(kind="run_tool", tool_id=tool_id, target=target,
                   extra_args=extra_args, rationale=rationale,
                   confidence=confidence, ai_source=ai_source)

    @classmethod
    def ask_human(cls, rationale: str, confidence: float = 1.0,
                  ai_source: str = "",
                  proposed_phase: str | None = None) -> "Action":
        return cls(kind="ask_human", rationale=rationale,
                   confidence=confidence, ai_source=ai_source,
                   proposed_phase=proposed_phase)

    @classmethod
    def stop(cls, rationale: str, confidence: float = 1.0,
             ai_source: str = "") -> "Action":
        return cls(kind="stop", rationale=rationale,
                   confidence=confidence, ai_source=ai_source)


@dataclass(frozen=True)
class ActionResult:
    """The outcome of an executed Action, fed back to the planner.

    Kept small and structured. The planner never sees raw tool output
    here — findings and a short summary only. Raw output lives in the
    job store, retrievable by job_id if the planner needs it.
    """

    action: Action
    ok: bool
    job_id: str | None = None
    summary: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.to_dict(),
            "ok": self.ok,
            "job_id": self.job_id,
            "summary": self.summary,
            "findings": self.findings,
            "error": self.error,
        }