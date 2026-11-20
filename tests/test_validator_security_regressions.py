"""Regression tests for conservative HTTP validation replay safety."""

from pathlib import Path

import pytest

from whaxon.core.findings import Finding
from whaxon.core.validator import Validator


def test_context_replay_refuses_state_changing_methods(tmp_path: Path) -> None:
    validator = Validator(tmp_path)
    status, reason = validator._replay_ctx(
        {"method": "DELETE", "url": "https://example.test/item/1"},
        target_url="https://example.test",
        kind="sqli",
    )
    assert status == "candidate"
    assert "may change target state" in reason


def test_context_replay_refuses_post_until_explicit_safe_replay_exists(
    tmp_path: Path,
) -> None:
    validator = Validator(tmp_path)
    status, reason = validator._replay_ctx(
        {"method": "POST", "url": "https://example.test/search", "body": "q=test"},
        target_url="https://example.test",
        kind="sqli",
    )
    assert status == "candidate"
    assert "may change target state" in reason


def test_context_replay_rejects_non_http_urls(tmp_path: Path) -> None:
    validator = Validator(tmp_path)
    status, reason = validator._replay_ctx(
        {"method": "GET", "url": "file:///etc/passwd"},
        target_url="https://example.test",
        kind="sqli",
    )
    assert status == "candidate"
    assert "absolute HTTP(S)" in reason


def test_context_replay_rejects_credentials_embedded_in_url(tmp_path: Path) -> None:
    validator = Validator(tmp_path)
    status, reason = validator._replay_ctx(
        {"method": "GET", "url": "https://user:secret@example.test/search"},
        target_url="https://example.test",
        kind="sqli",
    )
    assert status == "candidate"
    assert "must not embed credentials" in reason


def test_context_replay_rejects_different_target_host(tmp_path: Path) -> None:
    validator = Validator(tmp_path)
    status, reason = validator._replay_ctx(
        {"method": "GET", "url": "https://other.example.test/search?q=test"},
        target_url="https://example.test",
        kind="sqli",
    )
    assert status == "candidate"
    assert "does not match the authorized target" in reason



def test_context_replay_requires_authorized_target_before_network(
    tmp_path: Path, monkeypatch,
) -> None:
    import urllib.request

    def unexpected_network(*args, **kwargs):
        pytest.fail("context replay must not make a request without an authorized target")

    monkeypatch.setattr(urllib.request, "build_opener", unexpected_network)
    validator = Validator(tmp_path)
    status, reason = validator._replay_ctx(
        {"method": "GET", "url": "http://127.0.0.1:9/"},
        target_url=None,
        kind="sqli",
    )
    assert status == "candidate"
    assert "authorized target URL required" in reason
    assert "no request sent" in reason

    finding = Finding(
        kind="sqli",
        severity="high",
        source="test",
        data={"parameter": "q", "_request_context": {
            "method": "GET", "url": "http://127.0.0.1:9/", "parameter": "q",
        }},
        raw_line="",
    )
    status, reason = validator.validate(finding, target_url=None)
    assert status == "candidate"
    assert "authorized target URL required" in reason
    assert "no request sent" in reason


def test_query_fetch_rejects_non_http_urls() -> None:
    with pytest.raises(ValueError, match="absolute HTTP"):
        Validator._fetch("file:///etc/passwd", "q", "test")
