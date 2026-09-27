"""RulesProvider: deterministic planner ladder, no LLM.

Bounded, auditable planning that exercises the full executor loop
against real tools without any external service. This is the
baseline: whatever an LLM provider does, it should beat this.

Ladder:
  step 1  run nmap for discovery
  step 2  based on open ports, run the matching web tool
  step 3  stop with a digest
"""
from __future__ import annotations

import re
from typing import Any

from ..actions import Action
from ..provider import Provider


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOSTNAME = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def extract_target(goal: str) -> str | None:
    m = _IPV4.search(goal)
    if m:
        return m.group(0)
    m = _HOSTNAME.search(goal)
    if m:
        return m.group(0)
    return None


class RulesProvider(Provider):
    """Deterministic planner. Two-step assessment ladder."""

    name = "rules"

    def audit_prompt(self, goal: str) -> dict[str, Any]:
        target = extract_target(goal)
        if not target:
            return {"feasible": False,
                    "reason": "no target (IP or hostname) found in prompt",
                    "extracted": {}}
        return {"feasible": True, "reason": "",
                "extracted": {"target": target, "intent": "assess"}}

    def plan_step(self, goal, history, catalog, scope_summary, step, max_steps):
        catalog_ids = {t.get("id") for t in catalog}
        target = extract_target(goal) or ""

        if step == 1:
            if "nmap" not in catalog_ids:
                return Action.ask_human(
                    rationale="nmap not in catalog; cannot perform discovery",
                    ai_source=self.name)
            return Action.run_tool("nmap", target,
                rationale="initial discovery",
                confidence=0.9, ai_source=self.name)

        if step == 2:
            findings = _findings_from(history, 0)
            ports = {f["data"].get("port")
                     for f in findings
                     if f.get("kind") == "open_port" and f.get("data")}
            if not ports:
                return Action.stop(
                    rationale="discovery produced no open ports; nothing more to do",
                    ai_source=self.name)
            web_ports = {p for p in ports if p in (80, 443, 8080, 8443)}
            if web_ports and "nikto" in catalog_ids:
                return Action.run_tool("nikto", target,
                    rationale=f"web ports open {sorted(web_ports)}; running nikto",
                    confidence=0.8, ai_source=self.name)
            return Action.stop(
                rationale=f"open ports {sorted(ports)}; no follow-up rule matched",
                ai_source=self.name)

        return Action.stop(
            rationale="plan complete",
            ai_source=self.name)


def _findings_from(history: list[dict[str, Any]], idx: int) -> list[dict[str, Any]]:
    try:
        return history[idx].get("findings") or []
    except (IndexError, AttributeError, TypeError):
        return []
