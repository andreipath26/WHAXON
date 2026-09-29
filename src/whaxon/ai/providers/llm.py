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

_HISTORY_KEEP = 5
_TRUNCATE_CHARS = 120


def _slim_catalog(catalog: list[dict]) -> list[dict]:
    """Project catalog entries to {id, name, category}.

    The planner prompt only promises those three fields. The full
    Tool asdict includes args, binary, outfile_flag, and more — all
    noise that bloats the payload and slows small local models.
    """
    out = []
    for t in catalog or []:
        out.append({
            "id": t.get("id"),
            "name": t.get("name"),
            "category": t.get("category"),
        })
    return out


def _truncate(s, n=_TRUNCATE_CHARS):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + "..."


def _slim_history(history: list[dict], keep: int = _HISTORY_KEEP) -> list[dict]:
    """Project history entries to a small fixed-shape dict.

    Drops the findings array (which can be dozens of entries after a
    scan) and keeps only what a planner needs to avoid repeating work:
    what ran, against what, and whether it succeeded. Caps at the last
    N steps, with a sentinel at index 0 if anything was omitted.
    """
    items = list(history or [])
    omitted = max(0, len(items) - keep)
    items = items[-keep:] if keep > 0 else []
    out = []
    if omitted:
        out.append({"_omitted": omitted})
    for h in items:
        action = (h or {}).get("action") or {}
        out.append({
            "kind": action.get("kind"),
            "tool_id": action.get("tool_id"),
            "target": action.get("target"),
            "ok": h.get("ok"),
            "summary": _truncate(h.get("summary")),
            "error": _truncate(h.get("error")),
        })
    return out


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

    def plan_step(self, goal, history, catalog, scope_summary, step, max_steps, phase="recon"):
        user = json.dumps({
            "GOAL": goal,
            "CATALOG": _slim_catalog(catalog),
            "SCOPE": scope_summary,
            "HISTORY": _slim_history(history),
            "STEP": step,
            "MAX_STEPS": max_steps,
            "PHASE": phase,
            "PHASE_RULES": (
                "To propose moving to a new kill-chain phase, emit an "
                "ask_human Action with proposed_phase set to one of: "
                "recon, enumeration, vulnerability, initial-access, "
                "post-access, lateral, done. The human will approve or "
                "reject; the current PHASE only changes on approval."
            ),
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
            if "{" in extra or "}" in extra:
                extra = ""
            return Action.run_tool(tool_id.strip(), target.strip(),
                                   extra_args=extra.strip()[:200],
                                   rationale=rationale,
                                   confidence=confidence,
                                   ai_source=self.name)
        return Action.ask_human(
            rationale="model produced unknown kind %r" % (kind,),
            ai_source=self.name)
