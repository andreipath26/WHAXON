"""Tests for the weak_tls and recon_activity_burst rules."""
from __future__ import annotations

from whaxon.core.correlator import rule_weak_tls, rule_recon_burst


def _f(kind, raw_line="", **data):
    return {"kind": kind, "data": data, "raw_line": raw_line,
            "severity": "info", "source": "test"}


def test_weak_tls_requires_web_and_cert_issue():
    assert rule_weak_tls("t", [_f("open_port", port=443)]) is None
    assert rule_weak_tls("t", [_f("open_port", port=22, raw_line="self-signed")]) is None


def test_weak_tls_fires_on_self_signed():
    findings = [_f("open_port", port=443),
                _f("web_issue", raw_line="certificate is self-signed")]
    r = rule_weak_tls("t", findings)
    assert r is not None and r.data["pattern"] == "weak_tls"


def test_weak_tls_fires_on_expired():
    findings = [_f("open_port", port=443),
                _f("web_issue", raw_line="SSL certificate expired")]
    r = rule_weak_tls("t", findings)
    assert r is not None


def test_recon_burst_needs_five_kinds():
    four = [_f("open_port"), _f("service"), _f("web_issue"), _f("ntlm_hash")]
    assert rule_recon_burst("t", four) is None


def test_recon_burst_fires_on_five_kinds():
    five = [_f("open_port"), _f("service"), _f("web_issue"),
            _f("ntlm_hash"), _f("sql_injection")]
    r = rule_recon_burst("t", five)
    assert r is not None and r.data["pattern"] == "recon_activity_burst"
