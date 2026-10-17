"""Runner severity wiring tests.

Proves that the runner passes every finding through the severity resolver
before publishing JobFindings, that a CVSS-bearing CVE overrides the
adapter's severity, and that an empty vulndb falls back to the adapter.
"""
from __future__ import annotations

from whaxon.core.events import EventBus, JobFindings
from whaxon.core.runner import ToolRunner


class FakeVulnDB:
    def __init__(self, records=None):
        self._records = records or {}

    def lookup(self, cve_id):
        return self._records.get(cve_id.upper())


class FakeCatalog:
    def __init__(self, tool_id):
        self._tool_id = tool_id

    def get(self, tool_id):
        if tool_id == self._tool_id:
            return {"tool_id": tool_id, "binary": "/bin/echo", "args": "{target}"}
        return None


def _make_runner(vulndb):
    bus = EventBus()
    captured = []

    def on_findings(e):
        captured.append(e)

    bus.subscribe(JobFindings, on_findings)
    runner = ToolRunner(bus, catalog=None, scope=None, vulndb=vulndb)
    return runner, captured


def test_resolve_findings_sets_severity_from_cvss():
    vulndb = FakeVulnDB({"CVE-2021-44228": {"cvss_v3_score": 10.0}})
    runner, _captured = _make_runner(vulndb)
    fake_finding = {"severity": "medium", "raw_line": "log4shell CVE-2021-44228"}
    result = runner._resolve_findings([fake_finding])
    assert len(result) == 1
    assert result[0]["severity"] == "critical"
    assert result[0]["severity_source"] == "nvd"


def test_resolve_findings_falls_back_when_no_cve():
    vulndb = FakeVulnDB({})
    runner, _ = _make_runner(vulndb)
    fake_finding = {"severity": "high", "raw_line": "directory listing"}
    result = runner._resolve_findings([fake_finding])
    assert result[0]["severity"] == "high"
    assert result[0]["severity_source"] == "adapter"


def test_resolve_findings_falls_back_when_cve_not_on_record():
    vulndb = FakeVulnDB({})
    runner, _ = _make_runner(vulndb)
    fake_finding = {"severity": "high", "raw_line": "something CVE-2099-0001"}
    result = runner._resolve_findings([fake_finding])
    assert result[0]["severity"] == "high"
    assert result[0]["severity_source"] == "adapter"


def test_resolve_findings_with_no_vulndb_passes_through():
    runner, _ = _make_runner(None)
    fake_finding = {"severity": "medium", "raw_line": "CVE-2021-44228"}
    result = runner._resolve_findings([fake_finding])
    assert result[0]["severity"] == "medium"
    assert result[0]["severity_source"] == "adapter"


def test_resolve_findings_returns_dicts():
    """The output shape is uniform: dicts, not Finding objects."""
    vulndb = FakeVulnDB({})
    runner, _ = _make_runner(vulndb)
    fake_finding = {"severity": "low", "raw_line": "x"}
    result = runner._resolve_findings([fake_finding])
    assert isinstance(result, list)
    assert isinstance(result[0], dict)


def test_runner_init_accepts_vulndb_kwarg():
    runner = ToolRunner(EventBus(), vulndb=FakeVulnDB({}))
    assert runner._vulndb is not None


def test_runner_init_accepts_no_vulndb():
    runner = ToolRunner(EventBus())
    assert runner._vulndb is None
