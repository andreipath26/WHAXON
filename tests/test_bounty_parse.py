"""YesWeHack page parser: five real program pages (docs §26.1)."""
from whaxon.core.bounty_parse import parse_yeswehack
from whaxon.core.program_policy import validate_policy

_MONEYBOX = """Public programs
Moneybox Bug Bounty
Last update on 2026-05-26
Max reward
€2,000
Critical
€50
€50
€500
€1,000
€2,000
High
€100
€300
€800
€1,200
https://api.moneyboxapp.com
API
Critical
https://admin.moneyboxapp.org
Web application
Critical
Please append to your user-agent header the following value: ' bugbounty-0421 '.
Do not use automated scanners or tools that generate large amount of network traffic
No vulnerability disclosure, full, partial or otherwise, is allowed.
"""


def test_parse_moneybox_rewards_and_ua():
    p = parse_yeswehack(_MONEYBOX, slug="moneybox-bug-bounty")
    assert p["platform"] == "yeswehack"
    assert p["identity"]["user_agent_suffix"] == " bugbounty-0421 "
    assert p["reward_model"]["max_reward"] == 2000
    assert len(p["reward_model"]["grid"]) >= 1
    assert p["hunting_requirements"]["automated_scanners"] == "forbidden"
    assert p["hunting_requirements"]["disclosure_allowed"] is False


def test_parsed_policy_validates():
    p = parse_yeswehack(_MONEYBOX, slug="moneybox-bug-bounty")
    pol = validate_policy(p)
    assert pol.platform == "yeswehack"
    assert pol.matches("api.moneyboxapp.com")
    assert not pol.matches("google.com")


def test_scope_objects_carry_asset_value():
    p = parse_yeswehack(_MONEYBOX, slug="x")
    assert p["scope"]["in_scope"]
    first = p["scope"]["in_scope"][0]
    assert first["asset_value"] in ("critical", "high", "medium", "low", "very_low")
    assert first["type"] in ("api", "web_app", "wildcard", "mobile_ios", "mobile_android", "other")


def test_unimplemented_reward_type_refuses():
    p = parse_yeswehack(_MONEYBOX, slug="x")
    p["reward_model"]["type"] = "severity_table"
    try:
        validate_policy(p)
    except Exception as e:
        assert "not implemented in v1" in str(e)
    else:
        raise AssertionError("expected refusal")


def test_unknown_platform_refuses():
    p = parse_yeswehack(_MONEYBOX, slug="x")
    p["platform"] = "notaplatform"
    try:
        validate_policy(p)
    except Exception as e:
        assert "unknown platform" in str(e)
    else:
        raise AssertionError("expected refusal")


def test_empty_scope_refuses():
    p = parse_yeswehack(_MONEYBOX, slug="x")
    p["scope"]["in_scope"] = []
    try:
        validate_policy(p)
    except Exception as e:
        assert "empty scope" in str(e)
    else:
        raise AssertionError("expected refusal")


def test_missing_tools_mode_refuses():
    p = parse_yeswehack(_MONEYBOX, slug="x")
    p["tools"] = {}
    try:
        validate_policy(p)
    except Exception as e:
        assert "tools.mode" in str(e)
    else:
        raise AssertionError("expected refusal")
