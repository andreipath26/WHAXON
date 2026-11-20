"""E1 regression tests for Nikto issue parsing and evidence fidelity."""
from whaxon.adapters.nikto import NiktoAdapter


def test_nikto_metadata_is_not_a_finding():
    adapter = NiktoAdapter()
    findings = adapter.parse([("stdout", "+ Target Hostname: example.test"), ("stdout", "+ Server: nginx")])
    assert findings == []


def test_nikto_duplicate_issue_preserves_raw_source():
    adapter = NiktoAdapter()
    line = "+ /admin/: Directory indexing found."
    findings = adapter.parse([("stdout", line), ("stdout", line)])
    assert len(findings) == 1
    assert findings[0].raw_line == line
    assert findings[0].data["path"] == "/admin/"


def test_nikto_stderr_is_not_interpreted_as_findings():
    assert NiktoAdapter().parse([("stderr", "+ /admin/: Directory indexing found.")]) == []
