"""§4.3: RulesProvider adjusts confidence from cross-run history.

Deterministic given prior_runs: same history → same confidence. No
history (None or empty) → base value unchanged, so first-run plans
are untouched.
"""
from whaxon.ai.providers.rules import _confidence


def test_no_prior_runs_returns_base():
    assert _confidence(0.9, "nmap", None) == 0.9
    assert _confidence(0.9, "nmap", {}) == 0.9


def test_empty_history_returns_base():
    prior = {"target": "x", "run_count": 0, "tools_used": [],
             "successful_tools": [], "last_phase": "recon"}
    assert _confidence(0.9, "nmap", prior) == 0.9


def test_successful_tool_raises_confidence():
    prior = {"successful_tools": ["nmap"], "tools_used": ["nmap"]}
    out = _confidence(0.9, "nmap", prior)
    assert out == 0.95
    assert out > 0.9


def test_used_but_unsuccessful_lowers_confidence():
    prior = {"successful_tools": [], "tools_used": ["nmap"]}
    out = _confidence(0.9, "nmap", prior)
    assert out == 0.75
    assert out < 0.9


def test_raised_confidence_capped_at_0_95():
    prior = {"successful_tools": ["nmap"], "tools_used": ["nmap"]}
    assert _confidence(0.93, "nmap", prior) == 0.95


def test_lowered_confidence_floored_at_0_5():
    prior = {"successful_tools": [], "tools_used": ["nmap"]}
    assert _confidence(0.55, "nmap", prior) == 0.5


def test_unrelated_tool_unchanged():
    prior = {"successful_tools": ["nmap"], "tools_used": ["nmap"]}
    assert _confidence(0.8, "nikto", prior) == 0.8


def test_deterministic_same_input():
    prior = {"successful_tools": ["nikto"], "tools_used": ["nikto", "nmap"]}
    assert _confidence(0.8, "nikto", prior) == _confidence(0.8, "nikto", prior)
    assert _confidence(0.8, "nmap", prior) == _confidence(0.8, "nmap", prior)
