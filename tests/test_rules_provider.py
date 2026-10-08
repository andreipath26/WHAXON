"""Tests for the deterministic RulesProvider."""
from __future__ import annotations

from whaxon.ai.actions import Action
from whaxon.ai.providers.rules import RulesProvider, extract_target

CATALOG = [{"id": "nmap"}, {"id": "nikto"}]
SCOPE = {"enabled": True}


def test_extract_target_ipv4():
    assert extract_target("assess 10.0.0.5 please") == "10.0.0.5"


def test_extract_target_hostname():
    assert extract_target("scan example.com") == "example.com"


def test_extract_target_none():
    assert extract_target("please assess") is None


def test_audit_infeasible_without_target():
    r = RulesProvider()
    a = r.audit_prompt("please assess everything")
    assert a["feasible"] is False
    assert "no target" in a["reason"]


def test_audit_extracts_target():
    r = RulesProvider()
    a = r.audit_prompt("assess 10.0.0.5")
    assert a["feasible"] is True
    assert a["extracted"]["target"] == "10.0.0.5"


def test_step1_runs_nmap():
    r = RulesProvider()
    a = r.plan_step("assess 10.0.0.5", [], CATALOG, SCOPE, 1, 3)
    assert isinstance(a, Action)
    assert a.kind == "run_tool"
    assert a.tool_id == "nmap"
    assert a.target == "10.0.0.5"
    assert a.ai_source == "rules"


def test_step1_asks_human_without_nmap():
    r = RulesProvider()
    a = r.plan_step("assess 10.0.0.5", [], [{"id": "echo"}], SCOPE, 1, 3)
    assert a.kind == "ask_human"
    assert a.ai_source == "rules"


def test_step2_proposes_enumeration_phase_on_web_port():
    r = RulesProvider()
    history = [{"findings": [
        {"kind": "open_port", "data": {"port": 443}},
        {"kind": "open_port", "data": {"port": 22}},
    ]}]
    a = r.plan_step("assess 10.0.0.5", history, CATALOG, SCOPE, 2, 3, phase="recon")
    assert a.kind == "ask_human"
    assert a.proposed_phase == "enumeration"


def test_step2_runs_nikto_when_already_in_enumeration():
    r = RulesProvider()
    history = [{"findings": [
        {"kind": "open_port", "data": {"port": 443}},
        {"kind": "open_port", "data": {"port": 22}},
    ]}]
    a = r.plan_step("assess 10.0.0.5", history, CATALOG, SCOPE, 2, 3, phase="enumeration")
    assert a.kind == "run_tool"
    assert a.tool_id == "nikto"


def test_step2_stops_without_open_ports():
    r = RulesProvider()
    history = [{"findings": []}]
    a = r.plan_step("assess 10.0.0.5", history, CATALOG, SCOPE, 2, 3)
    assert a.kind == "stop"


def test_step2_stops_on_non_web_ports():
    r = RulesProvider()
    history = [{"findings": [{"kind": "open_port", "data": {"port": 22}}]}]
    a = r.plan_step("assess 10.0.0.5", history, CATALOG, SCOPE, 2, 3)
    assert a.kind == "stop"


def test_step3_stops():
    r = RulesProvider()
    a = r.plan_step("assess 10.0.0.5", [], CATALOG, SCOPE, 3, 3)
    assert a.kind == "stop"
