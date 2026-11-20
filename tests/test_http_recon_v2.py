from __future__ import annotations

import asyncio
import json
import multiprocessing
import socket
import ssl
import time
import unicodedata
from pathlib import Path
from types import SimpleNamespace

import pytest

from whaxon.core import Core
from whaxon.core.capabilities import CapabilityRegistry, CapabilityUnavailable
from whaxon.core.findings import Finding
from whaxon.core.http_recon_v2 import (
    CAPABILITY_ID,
    PROVIDER_ID,
    PROVIDER_VERSION,
    PassiveHttpsReconProvider,
    _BoundedHttpsWorker,
    _checked_headers,
    _collect_findings,
    _https_worker,
    _PinnedHTTPSConnection,
    _valid_target,
)
from whaxon.core.scope import ScopeManager
from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowTask


def _write_scope(path, *, in_scope=None, out_of_scope=None):
    path.write_text(json.dumps({
        "engagement": "http-recon-test",
        "enabled": True,
        "in_scope": in_scope or ["api.acme.test", "192.0.2.0/24"],
        "out_of_scope": out_of_scope or [],
    }))
    return path


def test_https_transport_connects_only_to_scope_returned_numeric_address(
    tmp_path, monkeypatch,
):
    scope = ScopeManager(_write_scope(tmp_path / "scope.json"))
    resolution_calls = []

    def resolve(host, port, **kwargs):
        resolution_calls.append((host, port, kwargs))
        return [(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
            ("192.0.2.44", port),
        )]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    pinned = scope.resolve_for_execution("api.acme.test", port=443)

    assert pinned.allowed is True
    assert len(pinned.addresses) == 1

    dialed = []
    tls_names = []

    class _Socket:
        def __init__(self, family, socktype, proto):
            self.family = family
            self.socktype = socktype
            self.proto = proto

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, sockaddr):
            dialed.append(sockaddr)

        def close(self):
            pass

    class _Context:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True

        def wrap_socket(self, raw, *, server_hostname):
            tls_names.append(server_hostname)
            return raw

    connection = _PinnedHTTPSConnection(
        "api.acme.test", pinned.addresses, timeout=1,
        context=_Context(), socket_factory=_Socket,
    )
    connection.connect()
    connection.close()

    assert len(resolution_calls) == 1
    assert dialed == [("192.0.2.44", 443)]
    assert tls_names == ["api.acme.test"]


def test_https_worker_reads_headers_once_and_never_reads_response_body(monkeypatch):
    requests = []
    response = SimpleNamespace(
        status=200,
        getheaders=lambda: [
            ("Server", "Apache/2.4.57"),
            ("X-Powered-By", "PHP/8.2.1"),
            ("Set-Cookie", "session=abc; Path=/"),
            ("Set-Cookie", "__cf_bm=xyz; Path=/; Secure; HttpOnly; SameSite=None"),
            ("CF-Ray", "abc123"),
        ],
        read=lambda *_args, **_kwargs: pytest.fail("HTTPS recon must not read the body"),
    )

    class _Scope:
        def __init__(self, _path):
            pass

        def resolve_for_execution(self, target, *, port):
            assert target == "api.acme.test"
            assert port == 443
            return SimpleNamespace(
                allowed=True,
                reason="",
                addresses=(object(),),
            )

    class _Connection:
        def __init__(self, host, addresses, *, timeout):
            assert host == "api.acme.test"
            assert len(addresses) == 1
            assert timeout > 0

        def request(self, method, path, *, headers):
            requests.append((method, path, headers))

        def getresponse(self):
            return response

        def close(self):
            pass

    monkeypatch.setattr("whaxon.core.http_recon_v2.ScopeManager", _Scope)
    monkeypatch.setattr("whaxon.core.http_recon_v2._PinnedHTTPSConnection", _Connection)

    receiver, sender = multiprocessing.Pipe(duplex=False)
    try:
        _https_worker(sender, "api.acme.test", "/unused/scope.json")
        payload = json.loads(receiver.recv_bytes())
    finally:
        receiver.close()
        sender.close()

    assert payload["status"] == "complete"
    assert requests == [(
        "GET", "/", {
            "Host": "api.acme.test",
            "User-Agent": "WHAXON-recon/2.0",
            "Connection": "close",
        },
    )]
    findings = payload["findings"]
    kinds = {finding["kind"] for finding in findings}
    assert {"http_header_missing", "tech_detected", "open_port", "cookie_insecure", "waf_detected"} <= kinds
    tech = [item for item in findings if item["kind"] == "tech_detected"]
    assert {item["data"]["product"] for item in tech} == {"apache", "php"}
    assert any(
        item["data"].get("cookie") == "session"
        and item["data"].get("missing") == "secure"
        for item in findings
    )
    waf = [item for item in findings if item["kind"] == "waf_detected"]
    assert any(item["data"]["waf"] == "cloudflare" for item in waf)


def test_https_worker_does_not_follow_redirect_or_try_http(monkeypatch):
    requests = []
    response = SimpleNamespace(
        status=302,
        getheaders=lambda: [("Location", "http://other.acme.test/")],
        read=lambda *_args, **_kwargs: pytest.fail("redirect body must not be read"),
    )

    class _Scope:
        def __init__(self, _path):
            pass

        def resolve_for_execution(self, _target, *, port):
            assert port == 443
            return SimpleNamespace(allowed=True, reason="", addresses=(object(),))

    class _Connection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, method, path, *, headers):
            requests.append((method, path, headers))

        def getresponse(self):
            return response

        def close(self):
            pass

    monkeypatch.setattr("whaxon.core.http_recon_v2.ScopeManager", _Scope)
    monkeypatch.setattr("whaxon.core.http_recon_v2._PinnedHTTPSConnection", _Connection)
    receiver, sender = multiprocessing.Pipe(duplex=False)
    try:
        _https_worker(sender, "api.acme.test", "/unused/scope.json")
        payload = json.loads(receiver.recv_bytes())
    finally:
        receiver.close()
        sender.close()

    assert payload["status"] == "complete"
    assert len(requests) == 1
    assert requests[0][0:2] == ("GET", "/")
    kinds = [item["kind"] for item in payload["findings"]]
    assert "http_header_missing" in kinds
    errors = [item for item in payload["findings"] if item["kind"] == "recon_error"]
    assert len(errors) == 1
    assert "status 302" in errors[0]["raw_line"]


def test_https_header_parser_enforces_count_and_aggregate_caps():
    with pytest.raises(ValueError, match="header count"):
        _checked_headers([("X-Test", "v")] * 101)
    with pytest.raises(ValueError, match="aggregate header"):
        _checked_headers([("X-Test", "x" * 65_000), ("Y-Test", "y" * 1000)])


def test_https_provider_has_fixed_empty_input_contract_and_manifest():
    class _Store:
        pass

    registry = CapabilityRegistry()
    provider = PassiveHttpsReconProvider(
        store=_Store(),
        registry=registry,
        scope=SimpleNamespace(path=Path("/scope.json")),
    )
    manifest = provider.bindings()[0]

    assert manifest.capability_id == CAPABILITY_ID
    assert manifest.provider_id == PROVIDER_ID
    assert manifest.provider_version == PROVIDER_VERSION
    assert manifest.scope_mode == "pinned_network"
    assert manifest.input_schema["additionalProperties"] is False
    assert manifest.input_schema["properties"] == {}
    assert _valid_target("api.acme.test")
    assert _valid_target("192.0.2.44")
    assert not _valid_target("https://api.acme.test/")
    assert not _valid_target("[2001:db8::1]")

    task = WorkflowTask(
        id="task-1",
        capability_id=CAPABILITY_ID,
        target="api.acme.test",
        inputs={"path": "/admin"},
        permissions=manifest.permissions,
        impact=manifest.impact,
    )
    with pytest.raises(CapabilityUnavailable):
        provider.resolve_task(task)


def _sleeping_http_worker(conn, _target, _scope_path):
    time.sleep(5)
    conn.close()


def test_https_child_hard_deadline_terminates_worker_process(tmp_path):
    child = _BoundedHttpsWorker(
        "api.acme.test",
        str(tmp_path / "scope.json"),
        timeout_s=0.15,
        worker_target=_sleeping_http_worker,
    )

    with pytest.raises(TimeoutError, match="hard deadline"):
        child.run()

    assert child._process is None



def test_https_dispatch_persists_v2_owned_job_and_findings(tmp_path, monkeypatch):
    scope_path = _write_scope(tmp_path / "scope.json")
    scope = ScopeManager(scope_path)
    store = JobStore(tmp_path / "jobs.db")
    registry = CapabilityRegistry(store)
    provider = PassiveHttpsReconProvider(store=store, registry=registry, scope=scope)
    manifest = provider.bindings()[0]
    finding = Finding(
        kind="http_header_missing",
        severity="low",
        source="recon:headers",
        data={"header": "strict-transport-security", "url": "https://api.acme.test/"},
        raw_line="https://api.acme.test/: missing strict-transport-security",
    )

    class _Worker:
        def __init__(self, *_args, **_kwargs):
            pass

        def request_termination(self):
            pass

        def run(self):
            return {"status": "complete", "findings": [finding.to_dict()]}

    monkeypatch.setattr("whaxon.core.http_recon_v2._BoundedHttpsWorker", _Worker)
    task = WorkflowTask(
        id="task-1",
        capability_id=CAPABILITY_ID,
        target="api.acme.test",
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
    )

    result = asyncio.run(provider.dispatch(task))

    assert result["tool_id"] == CAPABILITY_ID
    assert result["provider_id"] == PROVIDER_ID
    assert result["provider_version"] == PROVIDER_VERSION
    assert result["manifest_fingerprint"] == manifest.fingerprint
    assert result["registry_digest"] == registry.digest
    assert result["transport"] == "isolated_process"
    assert store.is_engine_v2_execution_job(result["job_id"])
    assert [item["kind"] for item in store.get_findings(result["job_id"])] == [
        "http_header_missing",
    ]



def test_core_pinned_https_authorization_does_not_resolve_target(tmp_path, monkeypatch):
    core = Core(tmp_path)
    _write_scope(
        core.scope.path,
        in_scope=["api.acme.test", "192.0.2.0/24"],
    )
    manifest = core.providers.manifest_for(CAPABILITY_ID)
    task = WorkflowTask(
        id="http-scope-task",
        capability_id=CAPABILITY_ID,
        target="api.acme.test",
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
    )

    def unexpected_resolution(*_args, **_kwargs):
        pytest.fail("Core pinned-network authorization must not resolve the hostname")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_resolution)

    assert core.authorize_workflow_task(task) is True



def test_untrusted_header_controls_are_escaped_before_finding_persistence():
    findings = _collect_findings(
        "api.acme.test",
        "api.acme.test",
        [
            ("Server", "Apache/2.4.57\x1b[31m\u202e"),
            ("Set-Cookie", "session=abc\x1b[2J; Path=/\u202e"),
        ],
    )

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, item in value.items():
                yield from strings(key)
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    output = list(strings([finding.to_dict() for finding in findings]))
    forbidden_categories = {"Cc", "Cf", "Cs", "Zl", "Zp"}
    assert all(
        unicodedata.category(char) not in forbidden_categories
        for value in output
        for char in value
    )
    assert any("\\x1b" in value for value in output)
    assert any("\\u202e" in value for value in output)
