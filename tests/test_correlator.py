"""Unit tests for the four correlation rules."""
from __future__ import annotations

from whaxon.core.correlator import (
    correlate,
    rule_exposed_service,
    rule_weak_credential,
    rule_web_service,
    rule_web_vuln,
)


def _f(kind, **data):
    return {"kind": kind, "data": data, "severity": "info", "source": "test"}


def test_no_findings_no_correlations():
    assert correlate("10.0.0.5", []) == []


def test_web_service_needs_a_web_port():
    assert rule_web_service("t", [_f("open_port", port=22)]) is None
    assert rule_web_service("t", [_f("open_port", port=3306)]) is None
    assert rule_web_service("t", [_f("open_port", port=5900)]) is None


def test_web_service_on_443_fires():
    r = rule_web_service("t", [_f("open_port", port=443)])
    assert r is not None and r.data["pattern"] == "web_service"


def test_web_service_on_tls_service_fires():
    r = rule_web_service("t", [_f("open_port", port=8443, service="ssl/http")])
    assert r is not None and r.data["pattern"] == "web_service"


def test_exposed_service_ignores_low_risk():
    assert rule_exposed_service("t", [_f("open_port", port=80)]) is None


def test_exposed_service_fires_on_445():
    r = rule_exposed_service("t", [_f("open_port", port=445)])
    assert r is not None and r.severity == "high"


def test_weak_credential_empty_hash():
    r = rule_weak_credential("t", [_f("ntlm_hash", user="svc", nt_hash="")])
    assert r is not None and r.severity == "critical"


def test_weak_credential_placeholder_hash():
    r = rule_weak_credential("t", [_f("ntlm_hash", user="guest",
                                       nt_hash="aad3b435b51404eeaad3b435b51404ee")])
    assert r is not None


def test_weak_credential_ignores_real_hash():
    r = rule_weak_credential("t", [_f("ntlm_hash", user="alice",
                                       nt_hash="5f4dcc3b5aa765d61d8327deb882cf99")])
    assert r is None


def test_web_vuln_needs_both_sql_and_web():
    assert rule_web_vuln("t", [_f("sql_injection", param="id")]) is None
    assert rule_web_vuln("t", [_f("open_port", port=443)]) is None


def test_web_vuln_fires_when_both_present():
    findings = [_f("sql_injection", param="id"),
                _f("open_port", port=80)]
    r = rule_web_vuln("t", findings)
    assert r is not None and r.data["pattern"] == "web_vuln"


def test_correlate_runs_all_rules():
    findings = [_f("open_port", port=443),
                _f("open_port", port=445),
                _f("ntlm_hash", user="u", nt_hash="")]
    hits = correlate("t", findings)
    patterns = {h.data["pattern"] for h in hits}
    assert patterns == {"web_service", "exposed_service", "weak_credential"}


def test_vulnerable_service_fires_on_vsftpd_234():
    """rule_vulnerable_service must fire on a known-vulnerable version."""
    from whaxon.core.correlator import correlate
    findings = [{
        "kind": "open_port",
        "raw_line": "21/tcp open ftp vsftpd 2.3.4",
        "data": {"port": 21, "service": "ftp"},
    }]
    out = correlate("127.0.0.1", findings)
    assert any(f.data.get("pattern") == "vulnerable_service" for f in out)


def test_vulnerable_service_ignores_unknown_version():
    """rule_vulnerable_service must not fire on a version not in the table."""
    from whaxon.core.correlator import correlate
    findings = [{
        "kind": "open_port",
        "raw_line": "21/tcp open ftp vsftpd 3.0.3",
        "data": {"port": 21, "service": "ftp"},
    }]
    out = correlate("127.0.0.1", findings)
    assert not any(f.data.get("pattern") == "vulnerable_service" for f in out)
