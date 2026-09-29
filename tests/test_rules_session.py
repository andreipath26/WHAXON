"""RulesProvider session ladder — step 6 of the session-execution migration."""
from __future__ import annotations

from whaxon.ai.providers.rules import RulesProvider, _find_session_id


CATALOG = [
    {"id": "nmap"},
    {"id": "nikto"},
    {"id": "msf_sysinfo"},
    {"id": "msf_getuid"},
]
SCOPE = {"enabled": True}


def _session_history(sid="3"):
    return [{
        "action": {"kind": "run_tool", "tool_id": "msf", "target": "10.0.0.5"},
        "ok": True,
        "summary": "msf ran",
        "findings": [{
            "kind": "msf_session",
            "severity": "critical",
            "data": {"session_id": sid, "host": "10.0.0.5"},
        }],
        "error": "",
    }]


def test_find_session_id_returns_first_session() -> None:
    assert _find_session_id(_session_history("7")) == "7"


def test_find_session_id_returns_none_when_absent() -> None:
    assert _find_session_id([{"findings": []}]) is None
    assert _find_session_id([]) is None
    assert _find_session_id(None) is None


def test_find_session_id_ignores_non_session_findings() -> None:
    hist = [{"findings": [
        {"kind": "open_port", "data": {"port": 80}},
        {"kind": "msf_session", "data": {"session_id": "9"}},
    ]}]
    assert _find_session_id(hist) == "9"


def test_ladder_proposes_sysinfo_in_post_access() -> None:
    r = RulesProvider()
    a = r.plan_step(
        "enumerate 10.0.0.5", _session_history("3"),
        CATALOG, SCOPE, 3, 5, phase="post-access",
    )
    assert a.kind == "run_tool"
    assert a.tool_id == "msf_sysinfo"
    assert a.session_id == "3"
    assert a.target is None


def test_ladder_proposes_sysinfo_in_lateral() -> None:
    r = RulesProvider()
    a = r.plan_step(
        "enumerate 10.0.0.5", _session_history("3"),
        CATALOG, SCOPE, 3, 5, phase="lateral",
    )
    assert a.kind == "run_tool"
    assert a.tool_id == "msf_sysinfo"
    assert a.session_id == "3"


def test_ladder_does_not_fire_in_recon() -> None:
    r = RulesProvider()
    a = r.plan_step(
        "enumerate 10.0.0.5", _session_history("3"),
        CATALOG, SCOPE, 3, 5, phase="recon",
    )
    # Not a session action; falls through to the final stop
    assert a.kind == "stop"


def test_ladder_does_not_fire_when_no_session_in_history() -> None:
    r = RulesProvider()
    hist = [{"findings": [{"kind": "open_port", "data": {"port": 80}}]}]
    a = r.plan_step(
        "enumerate 10.0.0.5", hist,
        CATALOG, SCOPE, 3, 5, phase="post-access",
    )
    assert a.kind == "stop"


def test_ladder_stops_when_msf_sysinfo_not_in_catalog() -> None:
    r = RulesProvider()
    a = r.plan_step(
        "enumerate 10.0.0.5", _session_history("3"),
        [{"id": "nmap"}, {"id": "nikto"}], SCOPE, 3, 5, phase="post-access",
    )
    assert a.kind == "stop"


def test_ladder_preserves_step_1_and_2_behavior() -> None:
    """Adding the session ladder must not change step 1 or step 2."""
    r = RulesProvider()
    # Step 1: nmap discovery
    a = r.plan_step("assess 10.0.0.5", [], CATALOG, SCOPE, 1, 5)
    assert a.tool_id == "nmap"
    # Step 2 with web port in recon: ask to transition to enumeration
    hist = [{"findings": [{"kind": "open_port", "data": {"port": 443}}]}]
    a = r.plan_step("assess 10.0.0.5", hist, CATALOG, SCOPE, 2, 5, phase="recon")
    assert a.kind == "ask_human"
    assert a.proposed_phase == "enumeration"