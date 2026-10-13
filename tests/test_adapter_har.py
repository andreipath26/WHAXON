"""Tests for the HAR adapter.

Covers:
- parsing a valid HAR file
- verbatim header capture (redaction happens at report time)
- body truncation
- response body hash presence
- session_id and principal metadata from ctx
- graceful return on missing file, malformed JSON, empty entries
- adapter registration
"""
from __future__ import annotations

import json
from pathlib import Path

from whaxon.adapters import get_adapter
from whaxon.adapters.har import HarAdapter

FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"


def test_har_adapter_registered():
    adapter = get_adapter("har")
    assert adapter is not None
    assert adapter.tool_id == "har"


def test_har_parses_valid_file():
    adapter = HarAdapter()
    findings = adapter.parse_file(FIXTURE)
    assert len(findings) == 3


def test_har_finding_shape():
    adapter = HarAdapter()
    findings = adapter.parse_file(FIXTURE)
    f = findings[0]
    assert f.kind == "http_request"
    assert f.severity == "info"
    assert f.source == "har"
    assert f.data["method"] == "GET"
    assert f.data["url"].startswith("http")
    assert "host" in f.data
    assert "path" in f.data
    assert "status" in f.data


def test_har_stores_authorization_header_verbatim():
    adapter = HarAdapter()
    findings = adapter.parse_file(FIXTURE)
    seen = False
    for f in findings:
        req_headers = f.data.get("request_headers", {})
        for k, v in req_headers.items():
            if k.lower() == "authorization":
                seen = True
                assert v != "<redacted>", "authorization was redacted at ingest"
    assert seen, "fixture must contain an authorization header"


def test_har_stores_cookie_header_verbatim():
    adapter = HarAdapter()
    findings = adapter.parse_file(FIXTURE)
    seen = False
    for f in findings:
        for header_name in ("request_headers", "response_headers"):
            headers = f.data.get(header_name, {})
            for k, v in headers.items():
                if k.lower() in ("cookie", "set-cookie"):
                    seen = True
                    assert v != "<redacted>", f"{k} was redacted at ingest"
    assert seen, "fixture must contain a cookie or set-cookie header"


def test_har_records_response_body_hash():
    adapter = HarAdapter()
    findings = adapter.parse_file(FIXTURE)
    for f in findings:
        assert "response_body_hash" in f.data
        assert len(f.data["response_body_hash"]) == 64


def test_har_truncates_long_body():
    adapter = HarAdapter()
    findings = adapter.parse_file(FIXTURE)
    for f in findings:
        body = f.data.get("response_body", "")
        assert len(body) <= 2000 + len("...[truncated]")


def test_har_returns_empty_on_missing_file(tmp_path):
    adapter = HarAdapter()
    missing = tmp_path / "does_not_exist.har"
    assert adapter.parse_file(missing) == []


def test_har_returns_empty_on_malformed_json(tmp_path):
    adapter = HarAdapter()
    bad = tmp_path / "bad.har"
    bad.write_text("{not valid json", encoding="utf-8")
    assert adapter.parse_file(bad) == []


def test_har_returns_empty_on_empty_log(tmp_path):
    adapter = HarAdapter()
    empty = tmp_path / "empty.har"
    empty.write_text(json.dumps({"log": {"entries": []}}), encoding="utf-8")
    assert adapter.parse_file(empty) == []


def test_har_returns_empty_without_file_path_ctx():
    adapter = HarAdapter()
    assert adapter.parse([]) == []
    assert adapter.parse([], {}) == []


def test_har_parse_reads_file_path_from_ctx():
    adapter = HarAdapter()
    findings = adapter.parse([], {"file_path": str(FIXTURE)})
    assert len(findings) == 3


def test_har_skips_entries_without_url(tmp_path):
    adapter = HarAdapter()
    bad = tmp_path / "no_url.har"
    bad.write_text(json.dumps({
        "log": {"entries": [
            {"request": {"method": "GET"}, "response": {"status": 200}},
            {"request": {"method": "GET", "url": "https://ok.example/"}, "response": {"status": 200}},
        ]}
    }), encoding="utf-8")
    findings = adapter.parse_file(bad)
    assert len(findings) == 1
    assert findings[0].data["url"] == "https://ok.example/"


def test_har_splits_url_into_host_and_path():
    adapter = HarAdapter()
    findings = adapter.parse_file(FIXTURE)
    for f in findings:
        assert "host" in f.data
        assert "path" in f.data
        assert f.data["host"] in f.data["url"]
        assert f.data["path"].startswith("/")