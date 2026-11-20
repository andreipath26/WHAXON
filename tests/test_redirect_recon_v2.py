from __future__ import annotations

import json
import socket
from types import SimpleNamespace

import pytest

from whaxon.core import redirect_recon_v2 as redirects
from whaxon.core.capabilities import CapabilityRegistry
from whaxon.core.scope import PinnedSocketAddress, ScopeManager
from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowTask


class _Response:
    def __init__(self, status=302, headers=()):
        self.status = status
        self.headers = list(headers)
        self.closed = False
        self.read_calls = 0

    def getheaders(self):
        return self.headers

    def close(self):
        self.closed = True

    def read(self, *_args):
        self.read_calls += 1
        raise AssertionError("redirect observer must not read the response body")


class _Connection:
    def __init__(self, _host, addresses, *, timeout, response):
        self.addresses = addresses
        self.timeout = timeout
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method, path, *, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class _Pipe:
    def close(self):
        pass


def _run_worker(monkeypatch, response, *, allowed=True):
    address = PinnedSocketAddress(
        socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
        ("192.0.2.44", 443),
    )
    scope = SimpleNamespace(calls=[])

    def resolve(target, *, port):
        scope.calls.append((target, port))
        return SimpleNamespace(
            allowed=allowed,
            addresses=(address,) if allowed else (),
            reason="denied",
        )

    scope.resolve_for_execution = resolve
    connection = _Connection("example.test", (address,), timeout=8, response=response)
    payloads = []
    monkeypatch.setattr(redirects, "ScopeManager", lambda _path: scope)
    monkeypatch.setattr(redirects, "_PinnedHTTPSConnection", lambda *a, **k: connection)
    monkeypatch.setattr(redirects, "_send_child_result", lambda _conn, payload: payloads.append(payload))
    redirects._worker(_Pipe(), "example.test", "scope.json")
    return scope, connection, payloads


def test_worker_observes_only_first_hop_and_redacts_location(monkeypatch):
    response = _Response(302, [(
        "Location", "http://user:secret@outside.test/login?token=secret#fragment",
    )])
    scope, connection, payloads = _run_worker(monkeypatch, response)

    assert scope.calls == [("example.test", 443)]
    assert [(method, path) for method, path, _ in connection.requests] == [("GET", "/")]
    assert connection.requests[0][2]["Host"] == "example.test"
    assert response.read_calls == 0
    assert response.closed and connection.closed
    finding = payloads[0]["findings"][0]
    assert payloads[0]["status"] == "complete"
    assert finding["data"] == {
        "url": "https://example.test/",
        "status_code": 302,
        "redirect_status": True,
        "location_present": True,
        "location_display": "http://outside.test/login",
        "cross_origin": True,
        "https_downgrade": True,
    }
    serialized = json.dumps(finding)
    assert "user" not in serialized and "secret" not in serialized and "fragment" not in serialized
    assert redirects._decode([finding], "example.test")[0].kind == "redirect_observation"


def test_worker_reports_same_origin_first_hop_without_following(monkeypatch):
    response = _Response(302, [("Location", "/next?session=private")])
    _scope, connection, payloads = _run_worker(monkeypatch, response)
    finding = payloads[0]["findings"][0]
    assert len(connection.requests) == 1
    assert finding["data"]["location_display"] == "https://example.test/next"
    assert finding["data"]["cross_origin"] is False
    assert finding["data"]["https_downgrade"] is False
    assert "private" not in json.dumps(finding)


def test_equivalent_ipv6_text_forms_are_same_origin():
    finding = redirects._make_observation(
        "2001:db8::1", 302,
        "https://[2001:0db8:0000:0000:0000:0000:0000:0001]/next",
    ).to_dict()
    assert finding["data"]["cross_origin"] is False
    assert finding["data"]["https_downgrade"] is False
    assert redirects._decode([finding], "2001:db8::1")[0].kind == "redirect_observation"


def test_non_redirect_location_is_observed_but_not_classified(monkeypatch):
    response = _Response(200, [("Location", "http://outside.test/next?secret=1")])
    _scope, connection, payloads = _run_worker(monkeypatch, response)
    finding = payloads[0]["findings"][0]
    assert len(connection.requests) == 1
    assert finding["data"]["redirect_status"] is False
    assert finding["data"]["cross_origin"] is False
    assert finding["data"]["https_downgrade"] is False
    assert finding["data"]["location_display"] == "http://outside.test/next"
    assert redirects._decode([finding], "example.test")[0].data["location_display"] == (
        "http://outside.test/next"
    )


def test_non_http_location_is_unsupported_not_a_cross_origin(monkeypatch):
    response = _Response(302, [("Location", "javascript:alert(1)?secret=1#fragment")])
    _scope, connection, payloads = _run_worker(monkeypatch, response)
    finding = payloads[0]["findings"][0]
    assert len(connection.requests) == 1
    assert finding["data"]["location_display"] == "javascript:[unsupported location scheme]"
    assert finding["data"]["cross_origin"] is False
    assert finding["data"]["https_downgrade"] is False
    assert "secret" not in json.dumps(finding) and "fragment" not in json.dumps(finding)


def test_child_scope_denial_happens_before_request(monkeypatch):
    _scope, connection, payloads = _run_worker(monkeypatch, _Response(), allowed=False)
    assert payloads[0]["status"] == "scope_denied"
    assert connection.requests == []


def test_decoder_rejects_unredacted_or_forged_child_evidence():
    item = redirects._make_observation(
        "example.test", 302, "https://outside.test/path?secret=1",
    ).to_dict()
    forged = {**item, "data": {**item["data"], "location_display": "https://user:pw@outside.test/path?secret=1"}}
    with pytest.raises(RuntimeError, match="unredacted"):
        redirects._decode([forged], "example.test")
    forged = {**item, "data": {**item["data"], "https_downgrade": True}}
    with pytest.raises(RuntimeError):
        redirects._decode([forged], "example.test")


@pytest.mark.asyncio
async def test_provider_persists_v2_owned_first_hop_evidence(tmp_path, monkeypatch):
    store = JobStore(tmp_path / "jobs.db")
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "enabled": True, "in_scope": ["example.test"], "out_of_scope": [],
    }))
    provider = redirects.RedirectObservationProvider(
        store=store,
        registry=CapabilityRegistry(store),
        scope=ScopeManager(scope_path),
    )
    task = WorkflowTask(
        id="redirect-1", capability_id=redirects.CAPABILITY_ID,
        target="example.test", inputs={}, permissions=("network.scan",),
        impact="moderate", timeout_s=40,
    )
    payload = {
        "status": "complete",
        "findings": [redirects._make_observation(
            "example.test", 302, "https://outside.test/path?secret=1",
        ).to_dict()],
    }

    class _Worker:
        def __init__(self, *_args, **_kwargs):
            pass

        def run(self):
            return payload

        def request_termination(self):
            pass

    monkeypatch.setattr(redirects, "_BoundedHttpsWorker", _Worker)
    result = await provider.dispatch(task)
    assert result["tool_id"] == redirects.CAPABILITY_ID
    assert store.is_engine_v2_execution_job(result["job_id"])
    assert store.get(result["job_id"])["status"] == "finished"
    assert store.get_findings(result["job_id"])[0]["kind"] == "redirect_observation"
