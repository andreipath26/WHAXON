"""LLMProvider: shared audit/plan logic over any LLMBackend."""
from __future__ import annotations

import json
import re
from typing import Any

from ..actions import Action
from ..provider import Provider
from ..prompts import planner_v1
from .backends.base import BackendError, LLMBackend

_JSON_OBJ = re.compile(r"\{.*\}", re.DOTALL)


class LLMProvider(Provider):
    """Provider that delegates to an LLMBackend.

    Owns: system prompt, JSON parsing, action validation, retries.
    Delegates: HTTP, auth, provider-specific message shapes.
    """

    name = "llm"

    def __init__(self, backend: LLMBackend, max_retries: int = 2) -> None:
        self.backend = backend
        self.max_retries = max_retries
        self.name = backend.name
        self._system = planner_v1()

    def audit_prompt(self, goal: str) -> dict[str, Any]:
        ok, reason = self.backend.available()
        if not ok:
            return {"feasible": False, "reason": reason, "extracted": {}}
        if not goal or not goal.strip():
            return {"feasible": False, "reason": "empty goal", "extracted": {}}
        return {"feasible": True, "reason": "", "extracted": {}}

    def plan_step(self, goal, history, catalog, scope_summary, step, max_steps):
        user = json.dumps({
            "GOAL": goal,
            "CATALOG": catalog,
            "SCOPE": scope_summary,
            "HISTORY": history,
            "STEP": step,
            "MAX_STEPS": max_steps,
        }, default=str)
        messages = [
            {"role": "system", "content": self._system},
            {"role": "user", "content": user},
        ]
        last_err = ""
        for attempt in range(self.max_retries + 1):
            try:
                raw = self.backend.chat(messages)
            except BackendError as e:
                return Action.ask_human(
                    rationale="LLM backend error: %s" % (e,),
                    ai_source=self.name)
            except Exception as e:
                return Action.ask_human(
                    rationale="LLM backend crashed: %r" % (e,),
                    ai_source=self.name)
            parsed = self._parse(raw)
            if parsed is not None:
                return self._to_action(parsed)
            last_err = "model returned invalid JSON"
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content": "Your previous reply was not a single JSON object. Reply again with exactly one JSON object and nothing else."})
        return Action.ask_human(
            rationale="could not obtain valid plan from model: %s" % last_err,
            ai_source=self.name)

    def _parse(self, raw: str) -> dict | None:
        if not raw:
            return None
        text = raw.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            text = chr(10).join(lines)
        m = _JSON_OBJ.search(text)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
        except Exception:
            return None
        return obj if isinstance(obj, dict) else None

    def _to_action(self, obj: dict) -> Action:
        kind = obj.get("kind")
        rationale = str(obj.get("rationale") or "")[:500]
        try:
            confidence = float(obj.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))
        if kind == "stop":
            return Action.stop(rationale=rationale or "done",
                               confidence=confidence or 1.0,
                               ai_source=self.name)
        if kind == "ask_human":
            return Action.ask_human(rationale=rationale or "need input",
                                    confidence=confidence or 1.0,
                                    ai_source=self.name)
        if kind == "run_tool":
            tool_id = obj.get("tool_id")
            target = obj.get("target")
            extra = obj.get("extra_args") or ""
            if not isinstance(tool_id, str) or not tool_id.strip():
                return Action.ask_human(
                    rationale="model produced run_tool without tool_id",
                    ai_source=self.name)
            if not isinstance(target, str) or not target.strip():
                return Action.ask_human(
                    rationale="model produced run_tool without target",
                    ai_source=self.name)
            if not isinstance(extra, str):
                extra = ""
            return Action.run_tool(tool_id.strip(), target.strip(),
                                   extra_args=extra.strip()[:200],
                                   rationale=rationale,
                                   confidence=confidence,
                                   ai_source=self.name)
        return Action.ask_human(
            rationale="model produced unknown kind %r" % (kind,),
            ai_source=self.name)
