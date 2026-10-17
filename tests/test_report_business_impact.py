"""Tests for business-impact severity wiring in the report."""
from whaxon.core.business_impact import _is_production_target, _shift_up, base_band, cost_range
from whaxon.core.report import _priority_band, _technical_band, to_markdown


def test_base_band_by_kind():
    assert base_band({"kind": "ntlm_hash"}) == "critical"
    assert base_band({"kind": "sqli"}) == "critical"
    assert base_band({"kind": "nxc_credential"}) == "high"
    assert base_band({"kind": "open_port"}) == "low"
    assert base_band({"kind": "sysinfo"}) == "low"


def test_base_band_open_port_with_lookup_hint():
    assert base_band({"kind": "open_port", "lookup_hint": "openssh 6.6"}) == "high"


def test_base_band_web_issue_exploitable():
    assert base_band({"kind": "web_issue", "raw_line": "sql injection in id"}) == "high"
    assert base_band({"kind": "web_issue", "raw_line": "directory listing"}) == "low"


def test_base_band_correlated_inherits_severity():
    assert base_band({"kind": "correlated", "severity": "critical"}) == "critical"
    assert base_band({"kind": "correlated", "severity": "high"}) == "high"


def test_base_band_deterministic():
    f = {"kind": "sqli", "severity": "high"}
    assert base_band(f) == base_band(f)


def test_is_production_target():
    assert _is_production_target("example.com") is True
    assert _is_production_target("example.com:443") is True
    assert _is_production_target("127.0.0.1") is False
    assert _is_production_target("10.0.0.5") is False
    assert _is_production_target("192.168.1.1") is False
    assert _is_production_target("172.16.0.1") is False
    assert _is_production_target("172.32.0.1") is True
    assert _is_production_target("localhost") is False
    assert _is_production_target("foo.test") is False
    assert _is_production_target("foo.local") is False
    assert _is_production_target("scanme.nmap.org") is False
    assert _is_production_target("") is False


def test_shift_up():
    assert _shift_up("low") == "medium"
    assert _shift_up("medium") == "high"
    assert _shift_up("high") == "critical"
    assert _shift_up("critical") == "critical"


def test_cost_range_lookup():
    row = cost_range({"kind": "sqli"})
    assert row is not None
    assert row["finding_class"] == "web_app_breach"
    assert row["median"] == 266000
    assert row["source"].startswith("Cyentia")


def test_cost_range_unknown_kind():
    assert cost_range({"kind": "no_such_kind"}) is None


def test_priority_band_shifts_up_for_business_impact():
    f = {"severity": "low", "business_impact": "critical"}
    assert _technical_band(f) == "medium-term"
    assert _priority_band(f) == "immediate"


def test_priority_band_uses_technical_when_no_business_impact():
    f = {"severity": "high"}
    assert _priority_band(f) == _technical_band(f)


def test_priority_band_never_lowers():
    f = {"kev": True, "business_impact": "low"}
    assert _priority_band(f) == "immediate"


def _make_report(findings):
    return {"engagement": "test", "generated": "2026-10-15T00:00:00", "job_count": 1, "finding_count": len(findings), "loot": [], "jobs": [], "session_findings": [], "ai_runs": [], "unique_findings": findings, "severity_counts": {}}


def test_exec_summary_shows_business_label():
    f = {"severity": "high", "business_impact": "critical", "raw_line": "sqli in id", "kind": "sqli", "count": 1}
    md = to_markdown(_make_report([f]), lookup=False)
    assert "/ Business: critical" in md


def test_appendix_shows_both_scales():
    f = {"severity": "critical", "business_impact": "high", "raw_line": "ntlm hash", "kind": "ntlm_hash", "count": 1}
    md = to_markdown(_make_report([f]), lookup=False, all_findings=True)
    assert "Business: high" in md


def test_appendix_falls_back_when_no_business_impact():
    f = {"severity": "critical", "raw_line": "legacy finding", "kind": "open_port", "count": 1}
    md = to_markdown(_make_report([f]), lookup=False, all_findings=True)
    assert "**[critical]**" in md
    assert "/ Business:" not in md


def test_exec_summary_ranks_by_business_impact():
    low_impact = {"severity": "critical", "business_impact": "low", "raw_line": "critical but low impact", "kind": "open_port", "count": 1}
    high_impact = {"severity": "medium", "business_impact": "critical", "raw_line": "medium but high impact", "kind": "sqli", "count": 1}
    md = to_markdown(_make_report([low_impact, high_impact]), lookup=False)
    hi = md.index("medium but high impact")
    lo = md.index("critical but low impact")
    assert hi < lo, "high business impact must rank above low business impact"
