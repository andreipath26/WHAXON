"""Severity resolver tests.

Covers: CVE extraction, CVSS band mapping, the resolve() path with and
without a vulndb record, EPSS/KEV attachment, priority computation, and
accepting either a Finding object or a dict.
"""
from __future__ import annotations

from whaxon.core.severity import (
    cvss_to_severity,
    extract_cve,
    priority,
    resolve,
)


class FakeVulnDB:
    """Minimal vulndb stub for testing."""

    def __init__(self, records=None):
        self._records = records or {}

    def lookup(self, cve_id):
        return self._records.get(cve_id.upper())


# ------------------------------------------------------------------ cvss_to_severity

def test_cvss_bands():
    assert cvss_to_severity(0.0) == "info"
    assert cvss_to_severity(0.1) == "low"
    assert cvss_to_severity(3.9) == "low"
    assert cvss_to_severity(4.0) == "medium"
    assert cvss_to_severity(6.9) == "medium"
    assert cvss_to_severity(7.0) == "high"
    assert cvss_to_severity(8.9) == "high"
    assert cvss_to_severity(9.0) == "critical"
    assert cvss_to_severity(10.0) == "critical"


def test_cvss_none_is_info():
    assert cvss_to_severity(None) == "info"


# ------------------------------------------------------------------ extract_cve

def test_extract_cve_from_reference():
    f = {"enrichment": {"references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]}}
    assert extract_cve(f) == "CVE-2021-44228"


def test_extract_cve_from_data_field():
    f = {"data": {"cve": "CVE-2019-0708"}}
    assert extract_cve(f) == "CVE-2019-0708"


def test_extract_cve_from_raw_line():
    f = {"raw_line": "something about CVE-1999-0678 in a URL"}
    assert extract_cve(f) == "CVE-1999-0678"


def test_extract_cve_lowercase_normalized():
    f = {"raw_line": "see cve-2019-0708"}
    assert extract_cve(f) == "CVE-2019-0708"


def test_extract_cve_none_when_absent():
    assert extract_cve({"raw_line": "no cve here"}) is None


# ------------------------------------------------------------------ resolve

def test_resolve_uses_cvss_when_cve_on_record():
    db = FakeVulnDB({"CVE-2021-44228": {"cvss_v3_score": 10.0, "cvss_v4_score": None}})
    f = {"severity": "medium", "raw_line": "log4j CVE-2021-44228"}
    out = resolve(f, db)
    assert out["severity"] == "critical"
    assert out["cvss"] == 10.0
    assert out["severity_source"] == "nvd"
    assert out["cve"] == "CVE-2021-44228"


def test_resolve_falls_back_when_cve_not_on_record():
    db = FakeVulnDB({})
    f = {"severity": "high", "raw_line": "something CVE-2099-0001"}
    out = resolve(f, db)
    assert out["severity"] == "high"
    assert out["severity_source"] == "adapter"


def test_resolve_falls_back_when_no_cve():
    db = FakeVulnDB({})
    f = {"severity": "medium", "raw_line": "directory listing"}
    out = resolve(f, db)
    assert out["severity"] == "medium"
    assert out["severity_source"] == "adapter"


def test_resolve_attaches_epss_and_kev():
    db = FakeVulnDB({"CVE-2021-44228": {
        "cvss_v3_score": 10.0, "epss_score": 0.97, "epss_percentile": 0.99, "kev": 1,
    }})
    f = {"severity": "medium", "raw_line": "CVE-2021-44228"}
    out = resolve(f, db)
    assert out["epss"] == 0.97
    assert out["epss_percentile"] == 0.99
    assert out["kev"] is True


def test_resolve_prefers_v3_over_v4():
    db = FakeVulnDB({"CVE-2021-44228": {"cvss_v3_score": 9.8, "cvss_v4_score": 5.0}})
    f = {"severity": "low", "raw_line": "CVE-2021-44228"}
    out = resolve(f, db)
    assert out["cvss"] == 9.8
    assert out["severity"] == "critical"


def test_resolve_uses_v4_when_v3_missing():
    db = FakeVulnDB({"CVE-2021-44228": {"cvss_v3_score": None, "cvss_v4_score": 8.5}})
    f = {"severity": "low", "raw_line": "CVE-2021-44228"}
    out = resolve(f, db)
    assert out["cvss"] == 8.5
    assert out["severity"] == "high"


def test_resolve_accepts_finding_object():
    class FakeFinding:
        def to_dict(self):
            return {"severity": "medium", "raw_line": "CVE-2021-44228"}
    db = FakeVulnDB({"CVE-2021-44228": {"cvss_v3_score": 10.0}})
    out = resolve(FakeFinding(), db)
    assert out["severity"] == "critical"
    assert out["severity_source"] == "nvd"


# ------------------------------------------------------------------ priority

def test_priority_kev_is_high():
    assert priority({"kev": True, "cvss": 5.0}) == "high"


def test_priority_high_epss():
    assert priority({"epss": 0.5, "cvss": 5.0}) == "high"


def test_priority_high_cvss():
    assert priority({"cvss": 9.5}) == "high"


def test_priority_medium_epss():
    assert priority({"epss": 0.1, "cvss": 5.0}) == "medium"


def test_priority_medium_cvss():
    assert priority({"cvss": 7.5}) == "medium"


def test_priority_low_default():
    assert priority({"cvss": 3.0, "epss": 0.01}) == "low"


def test_priority_empty_is_low():
    assert priority({}) == "low"
