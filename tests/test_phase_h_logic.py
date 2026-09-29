"""Phase H steps 4-5 — objectives and auto-answers."""
from __future__ import annotations

from whaxon.ai.actions import Action
from whaxon.ai.objectives import parse_verb, terminal_phase, is_terminal
from whaxon.ai.auto_answers import answer_question, warn_high_risk, HIGH_RISK_PHASES


def test_parse_known_verbs() -> None:
    for verb in ("recon", "scan", "enumerate", "test", "foothold", "exploit"):
        assert parse_verb(verb + " 10.0.0.5") == verb


def test_parse_unknown_verb() -> None:
    assert parse_verb("frobnicate 10.0.0.5") is None
    assert parse_verb("") is None
    assert parse_verb("   ") is None


def test_parse_case_insensitive() -> None:
    assert parse_verb("Enumerate 10.0.0.5") == "enumerate"
    assert parse_verb("RECON target") == "recon"


def test_terminal_phase_map() -> None:
    assert terminal_phase("recon 10.0.0.5") == "recon"
    assert terminal_phase("enumerate 10.0.0.5") == "enumeration"
    assert terminal_phase("test 10.0.0.5") == "vulnerability"
    assert terminal_phase("foothold on 10.0.0.5") == "initial-access"
    assert terminal_phase("exploit 10.0.0.5") == "post-access"


def test_terminal_phase_unknown_verb() -> None:
    assert terminal_phase("frobnicate 10.0.0.5") is None


def test_is_terminal() -> None:
    assert is_terminal("enumerate 10.0.0.5", "enumeration") is True
    assert is_terminal("enumerate 10.0.0.5", "recon") is False
    assert is_terminal("frobnicate 10.0.0.5", "enumeration") is False


def test_transition_not_allowed_returns_n() -> None:
    a = Action.ask_human("move to enum?", proposed_phase="enumeration")
    assert answer_question(a, env={}) == "n"


def test_transition_allowed_returns_y() -> None:
    a = Action.ask_human("move to enum?", proposed_phase="enumeration")
    env = {"WHAXON_AI_AUTO_PHASES": "enumeration"}
    assert answer_question(a, env=env) == "y"


def test_transition_allowed_case_insensitive() -> None:
    a = Action.ask_human("x", proposed_phase="Enumeration")
    env = {"WHAXON_AI_AUTO_PHASES": "ENUMERATION"}
    assert answer_question(a, env=env) == "y"


def test_multiple_allowed_phases() -> None:
    env = {"WHAXON_AI_AUTO_PHASES": "enumeration,vulnerability"}
    a = Action.ask_human("x", proposed_phase="vulnerability")
    assert answer_question(a, env=env) == "y"
    b = Action.ask_human("x", proposed_phase="enumeration")
    assert answer_question(b, env=env) == "y"


def test_confirm_mode_returns_empty() -> None:
    a = Action.ask_human("x", proposed_phase="enumeration")
    env = {"WHAXON_AI_AUTO_PHASES": "enumeration", "WHAXON_AI_AUTO_CONFIRM": "1"}
    assert answer_question(a, env=env) == ""


def test_non_transition_returns_skip() -> None:
    a = Action.ask_human("which tool?")
    assert answer_question(a, env={}) == "skip"
    assert answer_question(a, env={"WHAXON_AI_AUTO_PHASES": "enumeration"}) == "skip"


def test_warn_high_risk() -> None:
    env = {"WHAXON_AI_AUTO_PHASES": "enumeration,initial-access,post-access"}
    warnings = warn_high_risk(env)
    assert "initial-access" in warnings
    assert "post-access" in warnings
    assert "enumeration" not in warnings


def test_warn_high_risk_empty() -> None:
    assert warn_high_risk({}) == []


def test_high_risk_phases_tuple() -> None:
    assert "initial-access" in HIGH_RISK_PHASES
    assert "post-access" in HIGH_RISK_PHASES
    assert "lateral" in HIGH_RISK_PHASES
    assert "recon" not in HIGH_RISK_PHASES
