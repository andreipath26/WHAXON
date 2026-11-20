"""Focused contract and safety tests for standalone V2 headers recon."""
from __future__ import annotations

import asyncio

import pytest

from whaxon.core import Core, headers_v2
from whaxon.core.capabilities import CapabilityUnavailable
from whaxon.core.recon_checks import _MISSING_HEADER_KNOWLEDGE
from whaxon.core.workflow import WorkflowTask


class _CaptureConnection:
    def __init__(self) -> None:
        self.payload = None

    def send_bytes(self, value: bytes) -> None:
        import json
        self.payload = json.loads(value.decode("utf-8"))

    def close(self) -> None:
        pass


def _task(**overrides) -> WorkflowTask:
    values = {
        "id": "headers-task",
        "capability_id": headers_v2.CAPABILITY_ID,
        "target": "example.test",
        "permissions": ("network.scan",),
        "impact": "moderate",
        "timeout_s": 20.0,
        "idempotency_key": "headers-v2-test",
    }
    values.update(overrides)
    return WorkflowTask(**values)


def test_headers_manifest_is_fixed_https_with_closed_empty_input_and_bounded_output():
    manifest = headers_v2._MANIFEST
    assert manifest.capability_id == "web.recon.headers"
    assert manifest.protocols == ("https",)
    assert manifest.scope_mode == "pinned_network"
    assert manifest.input_schema["additionalProperties"] is False
    assert manifest.input_schema["required"] == ()
    assert manifest.output_schema["additionalProperties"] is False
    assert manifest.output_schema["properties"]["findings"]["maxItems"] == headers_v2.MAX_FINDINGS
    assert "no redirect following or HTTP fallback" in manifest.limitations[0]


def test_collect_findings_matches_legacy_missing_header_semantics_and_sanitizes_text():
    headers = [(header, "present") for header in _MISSING_HEADER_KNOWLEDGE]
    headers.extend([("Content-Security-Policy", "present"), ("X-Test", "ok")])
    findings = headers_v2._collect_findings("example.test", "example.test", headers)
    assert findings == []

    missing = headers_v2._collect_findings("example.test", "example.test", [])
    assert len(missing) == len(_MISSING_HEADER_KNOWLEDGE)
    assert {item.data["header"] for item in missing} == set(_MISSING_HEADER_KNOWLEDGE)
    assert all(item.source == "recon:headers" for item in missing)
    assert all(item.data["url"] == "https://example.test/" for item in missing)


def test_headers_worker_rechecks_scope_and_makes_one_fixed_request_without_body_read(monkeypatch, tmp_path):
    calls: list[tuple[str, str, dict]] = []

    class _Scope:
        def __init__(self, path):
            self.path = path

        def resolve_for_execution(self, target, *, port):
            assert target == "example.test"
            assert port == 443
            return type("Resolution", (), {
                "allowed": True,
                "addresses": (object(),),
                "reason": "",
            })()

    class _Response:
        status = 200

        def getheaders(self):
            return [("Strict-Transport-Security", "max-age=31536000")]

        def read(self, *_args, **_kwargs):
            raise AssertionError("headers recon must not read the response body")

        def close(self):
            pass

    class _Connection:
        def __init__(self, host, addresses, *, timeout):
            assert host == "example.test"
            assert len(addresses) == 1
            assert timeout == headers_v2.CONNECT_TIMEOUT_S

        def request(self, method, path, *, headers):
            calls.append((method, path, headers))

        def getresponse(self):
            return _Response()

        def close(self):
            pass

    monkeypatch.setattr(headers_v2, "ScopeManager", _Scope)
    monkeypatch.setattr(headers_v2, "_PinnedHTTPSConnection", _Connection)
    conn = _CaptureConnection()
    headers_v2._headers_worker(conn, "example.test", str(tmp_path / "scope.json"))

    assert conn.payload["status"] == "complete"
    assert len(calls) == 1
    method, path, request_headers = calls[0]
    assert method == "GET" and path == "/"
    assert request_headers["Host"] == "example.test"
    assert request_headers["Connection"] == "close"
    assert all(item.data["header"] != "strict-transport-security"
               for item in headers_v2._decode_findings(conn.payload["findings"], "example.test"))


def test_headers_worker_scope_denial_prevents_connection(monkeypatch, tmp_path):
    class _Scope:
        def __init__(self, _path):
            pass

        def resolve_for_execution(self, _target, *, port):
            assert port == 443
            return type("Resolution", (), {
                "allowed": False, "addresses": (), "reason": "excluded",
            })()

    def unexpected_connection(*_args, **_kwargs):
        raise AssertionError("out-of-scope target reached the network transport")

    monkeypatch.setattr(headers_v2, "ScopeManager", _Scope)
    monkeypatch.setattr(headers_v2, "_PinnedHTTPSConnection", unexpected_connection)
    conn = _CaptureConnection()
    headers_v2._headers_worker(conn, "example.test", str(tmp_path / "scope.json"))
    assert conn.payload["status"] == "scope_denied"


def test_headers_worker_fails_closed_when_response_header_bounds_are_exceeded(
    monkeypatch, tmp_path,
):
    class _Scope:
        def __init__(self, _path):
            pass

        def resolve_for_execution(self, _target, *, port):
            assert port == 443
            return type("Resolution", (), {
                "allowed": True, "addresses": (object(),), "reason": "",
            })()

    class _Response:
        status = 200

        def getheaders(self):
            return [(f"X-Fixture-{index}", "x")
                    for index in range(headers_v2.MAX_RESPONSE_HEADERS + 1)]

        def close(self):
            pass

    class _Connection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, method, path, *, headers):
            assert (method, path) == ("GET", "/")

        def getresponse(self):
            return _Response()

        def close(self):
            pass

    monkeypatch.setattr(headers_v2, "ScopeManager", _Scope)
    monkeypatch.setattr(headers_v2, "_PinnedHTTPSConnection", _Connection)
    conn = _CaptureConnection()
    headers_v2._headers_worker(conn, "example.test", str(tmp_path / "scope.json"))
    assert conn.payload["status"] == "error"
    assert "header count limit" in conn.payload["error"]


def test_headers_decoder_rejects_malformed_or_unapproved_findings():
    encoded = headers_v2._collect_findings("example.test", "example.test", [])[0].to_dict()
    with pytest.raises(RuntimeError, match="invalid finding contract"):
        headers_v2._decode_findings([dict(encoded, source="untrusted")], "example.test")
    with pytest.raises(RuntimeError, match="invalid finding list"):
        headers_v2._decode_findings([encoded] * (headers_v2.MAX_FINDINGS + 1), "example.test")
    with pytest.raises(RuntimeError, match="invalid missing-header observation"):
        bad = dict(encoded, data={"header": "x-unreviewed", "url": "https://example.test/"})
        headers_v2._decode_findings([bad], "example.test")
    with pytest.raises(RuntimeError, match="invalid missing-header observation"):
        headers_v2._decode_findings([encoded], "other.example.test")
    error = headers_v2._error_finding("example.test", "HTTPS returned status 503").to_dict()
    assert headers_v2._decode_findings([error], "example.test")[0].data["target"] == "example.test"
    with pytest.raises(RuntimeError, match="invalid error observation"):
        headers_v2._decode_findings([error], "other.example.test")


def test_headers_provider_rejects_dynamic_inputs_and_persists_v2_evidence(tmp_path, monkeypatch):
    core = Core(tmp_path)
    assert core.providers.manifest_for(headers_v2.CAPABILITY_ID).provider_id == headers_v2.PROVIDER_ID
    provider = headers_v2.HeadersReconProvider(
        store=core.store, registry=core.capabilities, scope=core.scope,
    )
    with pytest.raises(CapabilityUnavailable, match="inputs must be empty"):
        provider.resolve_task(_task(inputs={"path": "/admin"}))

    def missing_headers():
        return [item.to_dict() for item in headers_v2._collect_findings(
            "example.test", "example.test", [],
        )]

    class _Worker:
        def __init__(self, *_args, **_kwargs):
            pass

        def run(self):
            return {"status": "complete", "findings": missing_headers()}

        def request_termination(self):
            pass

    monkeypatch.setattr(headers_v2, "_BoundedHttpsWorker", _Worker)
    result = asyncio.run(provider.dispatch(_task()))
    assert result["tool_id"] == headers_v2.CAPABILITY_ID
    assert result["provider_id"] == headers_v2.PROVIDER_ID
    assert core.store.is_engine_v2_execution_job(result["job_id"])
    persisted = core.store.get_findings(result["job_id"])
    assert len(persisted) == len(_MISSING_HEADER_KNOWLEDGE)
    assert result["findings"] == persisted
