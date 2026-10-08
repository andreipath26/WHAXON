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

    def plan_step(self, goal, history, catalog, scope_summary, step, max_steps, phase="recon"):
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
            if web_ports and phase == "recon":
                return Action.ask_human(
                    rationale=f"recon complete (web ports {sorted(web_ports)}); move to enumeration?",
                    confidence=0.9,
                    ai_source=self.name,
                    proposed_phase="enumeration")
            if web_ports and "nikto" in catalog_ids:
                return Action.run_tool("nikto", target,
                    rationale=f"web ports open {sorted(web_ports)}; running nikto",
                    confidence=0.8, ai_source=self.name)
            return Action.stop(
                rationale=f"open ports {sorted(ports)}; no follow-up rule matched",
                ai_source=self.name)

        # Enumeration ladder: after enumeration tools have run, propose
        # the transition to vulnerability phase.
        if step > 2 and phase == "enumeration":
            return Action.ask_human(
                rationale="enumeration tools have run; move to vulnerability?",
                confidence=0.8,
                ai_source=self.name,
                proposed_phase="vulnerability")

        # Vulnerability ladder: run nuclei if available, else propose
        # the transition to initial-access.
        if step > 2 and phase == "vulnerability":
            ran_nuclei = any(
                r.get("action", {}).get("tool_id") == "nuclei"
                for r in (history or [])
            )
            if not ran_nuclei and "nuclei" in catalog_ids:
                return Action.run_tool(
                    "nuclei", target,
                    rationale="vulnerability phase; running nuclei",
                    confidence=0.8, ai_source=self.name)
            return Action.ask_human(
                rationale="vulnerability scan complete; move to initial-access?",
                confidence=0.7,
                ai_source=self.name,
                proposed_phase="initial-access")

        # Session ladder: if any prior step produced an msf_session
        # finding and we are at or past post-access, propose a
        # session-scoped tool against that session.
        session_id = _find_session_id(history)
        if session_id and phase in ("post-access", "lateral"):
            if "msf_sysinfo" in catalog_ids:
                return Action.run_in_session(
                    "msf_sysinfo", session_id,
                    rationale=f"enumerate session {session_id}",
                    confidence=0.8, ai_source=self.name)

        return Action.stop(
            rationale="plan complete",
            ai_source=self.name)


def _find_session_id(history: list[dict[str, Any]]) -> str | None:
    """Return the first msf_session session_id found in any step findings."""
    for step in history or []:
        for f in (step.get("findings") or []):
            if f.get("kind") == "msf_session":
                sid = (f.get("data") or {}).get("session_id")
                if sid:
                    return str(sid)
    return None


def _findings_from(history: list[dict[str, Any]], idx: int) -> list[dict[str, Any]]:
    try:
        return history[idx].get("findings") or []
    except (IndexError, AttributeError, TypeError):
        return []
