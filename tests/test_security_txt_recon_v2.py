from __future__ import annotations

import json
import socket
import unicodedata
from types import SimpleNamespace

import pytest

from whaxon.core import security_txt_v2 as security_txt
from whaxon.core.capabilities import CapabilityRegistry
from whaxon.core.scope import PinnedSocketAddress, ScopeManager
from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowTask


class _Response:
    def __init__(self, status=200, body=b"", headers=()):
        self.status, self.body, self.headers = status, body, list(headers)
        self.read_sizes, self.closed = [], False

    def getheaders(self):
        return self.headers

    def read(self, size):
        self.read_sizes.append(size)
        return self.body[:size]

    def close(self):
        self.closed = True


class _Connection:
    def __init__(self, _host, addresses, *, timeout, response):
        self.addresses, self.timeout, self.response = addresses, timeout, response
        self.requests, self.closed = [], 0

    def request(self, method, path, *, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed += 1


class _Pipe:
    def close(self):
        pass


def _worker(monkeypatch, response, *, allowed=True):
    address = PinnedSocketAddress(socket.AF_INET, socket.SOCK_STREAM,
                                  socket.IPPROTO_TCP, ("192.0.2.44", 443))
    scope = SimpleNamespace(calls=[], resolve_for_execution=lambda target, *, port: (
        scope.calls.append((target, port)) or SimpleNamespace(
            allowed=allowed, addresses=(address,) if allowed else (), reason="denied",
        )
    ))
    connection = _Connection("example.test", (address,), timeout=8, response=response)
    payloads = []
    monkeypatch.setattr(security_txt, "ScopeManager", lambda _path: scope)
    monkeypatch.setattr(security_txt, "_PinnedHTTPSConnection", lambda *a, **k: connection)
    monkeypatch.setattr(security_txt, "_send_child_result", lambda _conn, p: payloads.append(p))
    security_txt._worker(_Pipe(), "example.test", "scope.json")
    return scope, connection, payloads


def test_security_txt_worker_makes_only_one_fixed_pinned_get(monkeypatch):
    response = _Response(body=(
        b"Contact: mailto:security@example.test\nPolicy: https://other.test/policy\n"
        b"Unknown: ignore\nExpires: 2030-01-01T00:00:00Z\n"
    ))
    scope, connection, payloads = _worker(monkeypatch, response)
    assert scope.calls == [("example.test", 443)]
    assert connection.addresses[0].sockaddr == ("192.0.2.44", 443)
    assert [(method, path) for method, path, _ in connection.requests] == [("GET", security_txt.PATH)]
    assert response.read_sizes == [security_txt.MAX_BODY_BYTES + 1]
    assert response.closed and connection.closed == 1
    assert payloads[0]["status"] == "complete"
    assert {item["data"]["field"] for item in payloads[0]["findings"]} == {"Contact", "Policy", "Expires"}


def test_security_txt_worker_never_follows_redirect_or_out_of_scope_url(monkeypatch):
    response = _Response(302, b"must not read", [("Location", "https://elsewhere.test/security.txt")])
    _scope, connection, payloads = _worker(monkeypatch, response)
    assert len(connection.requests) == 1
    assert response.read_sizes == []
    assert payloads[0]["findings"][0]["kind"] == "recon_error"


def test_security_txt_worker_checks_child_scope_before_request(monkeypatch):
    _scope, connection, payloads = _worker(monkeypatch, _Response(), allowed=False)
    assert payloads[0]["status"] == "scope_denied"
    assert connection.requests == []


def test_security_txt_body_and_serialized_text_are_bounded(monkeypatch):
    big = _Response(body=b"Contact: " + b"x" * security_txt.MAX_BODY_BYTES)
    _scope, _connection, payloads = _worker(monkeypatch, big)
    assert big.read_sizes == [security_txt.MAX_BODY_BYTES + 1]
    assert payloads[0]["findings"][0]["kind"] == "recon_error"
    unsafe = security_txt._parse("example.test", ("Contact: mailto:a\x1b\u202e@b.test\n").encode())
    serialized = json.dumps([item.to_dict() for item in unsafe])
    assert "\\x1b" in serialized and "\\u202e" in serialized
    assert all(unicodedata.category(c) not in {"Cc", "Cf", "Cs", "Zl", "Zp"} for c in serialized)


@pytest.mark.asyncio
async def test_security_txt_provider_persists_attempt_linked_sealed_evidence(tmp_path, monkeypatch):
    store = JobStore(tmp_path / "jobs.db")
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({"enabled": True, "in_scope": ["example.test"], "out_of_scope": []}))
    provider = security_txt.SecurityTxtReconProvider(
        store=store, registry=CapabilityRegistry(store), scope=ScopeManager(scope_path),
    )
    task = WorkflowTask(id="security-txt-1", capability_id=security_txt.CAPABILITY_ID,
        target="example.test", inputs={}, permissions=("network.scan",), impact="moderate", timeout_s=40)
    payload = {"status": "complete", "findings": [security_txt._parse(
        "example.test", b"Contact: mailto:security@example.test\n")[0].to_dict()]}

    class _Worker:
        def __init__(self, *_args, **_kwargs): pass
        def run(self): return payload
        def request_termination(self): pass

    monkeypatch.setattr(security_txt, "_BoundedHttpsWorker", _Worker)
    result = await provider.dispatch(task)
    assert result["tool_id"] == security_txt.CAPABILITY_ID
    assert store.is_engine_v2_execution_job(result["job_id"])
    assert store.get(result["job_id"])["status"] == "finished"
    assert len(store.get_findings(result["job_id"])) == 1
    assert provider.resolve_task(task, require_installed=True).manifest.scope_mode == "pinned_network"
