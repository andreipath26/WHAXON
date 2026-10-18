"""Enumeration phase runs a tool before proposing the phase transition.

Before this fix, the enumeration branch went straight to ask_human with
the rationale 'enumeration tools have run' — which was false when no
enumeration tool had run. Reproduced against bWAPP: nmap found web ports,
the AI transitioned to enumeration, immediately proposed the transition
to vulnerability, and nuclei ran against unenumerated hosts.
"""
from __future__ import annotations

from whaxon.ai.actions import Action
from whaxon.ai.providers.rules import RulesProvider

_CATALOG = [{"id": "nmap"}, {"id": "nikto"}, {"id": "gobuster"}, {"id": "nuclei"}]


def _plan(history, phase="enumeration", step=3):
    p = RulesProvider()
    return p.plan_step(
        goal="recon 10.0.0.1", history=history, catalog=_CATALOG,
        scope_summary={}, step=step, max_steps=20, phase=phase,
    )


def test_enumeration_runs_gobuster_when_not_yet_run():
    a = _plan(history=[{"action": {"kind": "run_tool", "tool_id": "nmap"}}])
    assert a.kind == "run_tool"
    assert a.tool_id == "gobuster"


def test_enumeration_proposes_transition_after_gobuster_ran():
    history = [
        {"action": {"kind": "run_tool", "tool_id": "nmap"}},
        {"action": {"kind": "run_tool", "tool_id": "gobuster"}},
    ]
    a = _plan(history=history)
    assert a.kind == "ask_human"
    assert a.proposed_phase == "vulnerability"


def test_enumeration_without_gobuster_in_catalog_transitions():
    p = RulesProvider()
    a = p.plan_step(
        goal="x", history=[{"action": {"kind": "run_tool", "tool_id": "nmap"}}],
        catalog=[{"id": "nmap"}, {"id": "nikto"}],
        scope_summary={}, step=3, max_steps=20, phase="enumeration",
    )
    assert a.kind == "ask_human"
    assert a.proposed_phase == "vulnerability"


def test_rationale_no_longer_claims_tools_ran_when_they_did_not():
    a = _plan(history=[])
    # Either it runs a tool (no false claim) or it says something true.
    if a.kind == "ask_human":
        assert "have run" not in (a.rationale or ""), a.rationale
