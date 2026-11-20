from __future__ import annotations

import json
import socket
import unicodedata
from types import SimpleNamespace

import pytest

from whaxon.core import robots_recon_v2 as robots
from whaxon.core.capabilities import CapabilityRegistry
from whaxon.core.scope import PinnedSocketAddress, ScopeManager
from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


class _FakeResponse:
    def __init__(self, status, body=b"", headers=()):
        self.status = status
        self._body = body
        self._headers = list(headers)
        self.read_sizes = []
        self.closed = False

    def getheaders(self):
        return self._headers

    def read(self, size):
        self.read_sizes.append(size)
        return self._body[:size]

    def close(self):
        self.closed = True


class _FakeConnection:
    def __init__(self, host, addresses, *, timeout, responses):
        self.host = host
        self.addresses = addresses
        self.timeout = timeout
        self.responses = list(responses)
        self.requests = []
        self.closed = 0

    def request(self, method, path, *, headers):
        self.requests.append((method, path, dict(headers)))

    def getresponse(self):
        return self.responses.pop(0)

    def close(self):
        self.closed += 1


class _PipeCapture:
    def close(self):
        pass


def _run_worker(monkeypatch, responses, *, allowed=True):
    address = PinnedSocketAddress(
        socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
        ("192.0.2.44", 443),
    )
    scope = SimpleNamespace(
        resolutions=[],
        resolve_for_execution=lambda target, *, port: (
            scope.resolutions.append((target, port))
            or SimpleNamespace(
                allowed=allowed,
                addresses=(address,) if allowed else (),
                reason="outside test scope",
            )
        ),
    )
    connection = _FakeConnection(
        "example.test", (address,), timeout=robots.CONNECT_TIMEOUT_S,
        responses=responses,
    )
    payloads = []
    monkeypatch.setattr(robots, "ScopeManager", lambda _path: scope)
    monkeypatch.setattr(robots, "_PinnedHTTPSConnection", lambda *a, **k: connection)
    monkeypatch.setattr(robots, "_send_child_result", lambda _conn, payload: payloads.append(payload))
    robots._robots_worker(_PipeCapture(), "example.test", "scope.json")
    return scope, connection, payloads


def test_robots_worker_uses_one_pinned_resolution_and_only_fixed_paths(monkeypatch):
    robots_body = (
        b"User-agent: *\nDisallow: /admin\nDisallow: /\n"
        b"Sitemap: https://outside.test/map.xml\n"
    )
    sitemap_body = (
        b"<urlset><url><loc>https://outside.test/private</loc></url></urlset>"
    )
    responses = [
        _FakeResponse(200, robots_body),
        _FakeResponse(200, sitemap_body),
    ]

    scope, connection, payloads = _run_worker(monkeypatch, responses)

    assert scope.resolutions == [("example.test", 443)]
    assert connection.addresses[0].sockaddr == ("192.0.2.44", 443)
    assert [(method, path) for method, path, _ in connection.requests] == [
        ("GET", "/robots.txt"), ("GET", "/sitemap.xml"),
    ]
    assert all(headers["Connection"] == "close" for _, _, headers in connection.requests)
    assert all(response.read_sizes == [robots.MAX_BODY_BYTES + 1] for response in responses)
    assert all(response.closed for response in responses)
    assert connection.closed >= 2
    payload = payloads[0]
    assert payload["status"] == "complete"
    kinds = [item["kind"] for item in payload["findings"]]
    assert "robots_disallow" in kinds
    assert any(item["data"].get("path") == "/" for item in payload["findings"])
    assert "robots_sitemap_ref" in kinds
    assert "sitemap_url" in kinds
    assert any(
        item["data"].get("url") == "https://outside.test/private"
        for item in payload["findings"]
    )
    assert len(connection.requests) == 2



def test_fixed_path_request_closes_connection_when_request_fails():
    class _FailingConnection:
        def __init__(self):
            self.closed = 0

        def request(self, *_args, **_kwargs):
            raise OSError("connect failed")

        def close(self):
            self.closed += 1

    connection = _FailingConnection()

    with pytest.raises(OSError, match="connect failed"):
        robots._request_fixed_path(connection, "example.test", "/robots.txt")

    assert connection.closed == 1



def test_robots_findings_escape_controls_in_all_serialized_fields(monkeypatch):
    robots_body = (
        "Disallow: /admin\x1b\u202e\n"
        "Sitemap: https://outside.test/map\x1b\u202e\n"
    ).encode("utf-8")
    sitemap_body = (
        "<urlset><url><loc>https://outside.test/private\x1b\u202e</loc></url></urlset>"
    ).encode("utf-8")
    _scope, _connection, payloads = _run_worker(
        monkeypatch,
        [_FakeResponse(200, robots_body), _FakeResponse(200, sitemap_body)],
    )

    findings = json.loads(json.dumps(payloads[0]["findings"]))
    strings = []

    def collect(value):
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, dict):
            for key, item in value.items():
                collect(key)
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(findings)
    assert strings
    assert all(
        unicodedata.category(char) not in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for value in strings
        for char in value
    )
    assert any("\\x1b" in value for value in strings)
    assert any("\\u202e" in value for value in strings)
    assert any(item["kind"] == "robots_disallow" for item in findings)
    assert any(item["kind"] == "robots_sitemap_ref" for item in findings)
    assert any(item["kind"] == "sitemap_url" for item in findings)


def test_robots_worker_reports_redirect_and_non_2xx_without_following(monkeypatch):
    responses = [
        _FakeResponse(302, b"should not be read", [("Location", "https://outside.test/robots")]),
        _FakeResponse(404, b"should not be read"),
    ]

    _scope, connection, payloads = _run_worker(monkeypatch, responses)

    findings = payloads[0]["findings"]
    assert [(method, path) for method, path, _ in connection.requests] == [
        ("GET", "/robots.txt"), ("GET", "/sitemap.xml"),
    ]
    assert all(response.read_sizes == [] for response in responses)
    assert len(findings) == 2
    assert all(item["kind"] == "recon_error" for item in findings)
    assert "302" in findings[0]["data"]["error"]
    assert "404" in findings[1]["data"]["error"]
    assert all(item["kind"] != "robots_missing" for item in findings)


def test_robots_worker_detects_oversized_body_and_keeps_other_path_bounded(monkeypatch):
    oversized = _FakeResponse(200, b"Disallow: /x\n" * 7000)
    sitemap = _FakeResponse(200, b"<urlset></urlset>")

    _scope, connection, payloads = _run_worker(monkeypatch, [oversized, sitemap])

    assert oversized.read_sizes == [robots.MAX_BODY_BYTES + 1]
    assert [path for _, path, _ in connection.requests] == list(robots.REQUEST_PATHS)
    findings = payloads[0]["findings"]
    assert any("64 KiB" in item["data"].get("error", "") for item in findings)
    assert not any(item["kind"] == "robots_disallow" for item in findings)



def test_robots_worker_keeps_truncation_error_within_finding_cap(monkeypatch):
    robots_body = b"Disallow: /x\n" * robots.MAX_FINDINGS
    sitemap_body = b"<urlset><url><loc>https://example.test/a</loc></url></urlset>"
    _scope, _connection, payloads = _run_worker(
        monkeypatch,
        [_FakeResponse(200, robots_body), _FakeResponse(200, sitemap_body)],
    )

    findings = payloads[0]["findings"]
    assert len(findings) == robots.MAX_FINDINGS
    assert findings[-1]["kind"] == "recon_error"
    assert "finding limit" in findings[-1]["data"]["error"]


def test_robots_worker_denies_scope_before_connect_or_requests(monkeypatch):
    _scope, connection, payloads = _run_worker(
        monkeypatch, [], allowed=False,
    )

    assert payloads[0]["status"] == "scope_denied"
    assert connection.requests == []
    assert connection.closed == 0


@pytest.mark.asyncio
async def test_robots_provider_persists_error_and_observation_evidence(tmp_path, monkeypatch):
    store = JobStore(tmp_path / "jobs.db")
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "enabled": True, "in_scope": ["example.test"], "out_of_scope": [],
    }), encoding="utf-8")
    scope = ScopeManager(scope_path)
    registry = CapabilityRegistry(store)
    provider = robots.RobotsReconProvider(
        store=store, registry=registry, scope=scope,
    )
    task = WorkflowTask(
        id="robots-1", capability_id=robots.CAPABILITY_ID,
        target="example.test", inputs={}, permissions=("network.scan",),
        impact="moderate", timeout_s=40,
    )
    payload = {
        "status": "complete",
        "findings": [
            robots._error_finding(
                "example.test", "/robots.txt", "HTTPS returned status 302",
            ).to_dict(),
            robots._finding(
                "robots_disallow",
                {"url": "https://example.test/robots.txt", "path": "/admin"},
                "https://example.test/robots.txt: Disallow /admin",
            ).to_dict(),
        ],
    }

    class _Worker:
        def __init__(self, *_args, **_kwargs):
            self.terminated = False

        def run(self):
            return payload

        def request_termination(self):
            self.terminated = True

    monkeypatch.setattr(robots, "_BoundedHttpsWorker", _Worker)
    result = await provider.dispatch(task)

    assert result["tool_id"] == robots.CAPABILITY_ID
    assert result["target"] == "example.test"
    assert result["exit_code"] == 0
    assert len(store.get_findings(result["job_id"])) == 2
    assert store.get(result["job_id"])["status"] == "finished"
    assert store.is_engine_v2_execution_job(result["job_id"])
    assert provider.resolve_task(task, require_installed=True).manifest.scope_mode == "pinned_network"


def test_robots_plan_requires_exact_separate_approval(tmp_path):
    from whaxon.core import Core
    from whaxon.core.providers import BoundProviderRouter

    store = JobStore(tmp_path / "jobs.db")
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "enabled": True, "in_scope": ["example.test"], "out_of_scope": [],
    }), encoding="utf-8")
    scope = ScopeManager(scope_path)
    registry = CapabilityRegistry(store)
    provider = robots.RobotsReconProvider(
        store=store, registry=registry, scope=scope,
    )
    core = Core.__new__(Core)
    core.store = store
    core.scope = scope
    core.capabilities = registry
    core.providers = BoundProviderRouter((provider,))
    task = WorkflowTask(
        id="robots-1", capability_id=robots.CAPABILITY_ID,
        target="example.test", inputs={}, permissions=("network.scan",),
        impact="moderate", timeout_s=40,
    )
    plan = WorkflowPlan("mission", (task,), metadata={
        "provider_bindings": {task.id: {
            "provider_id": provider.bindings()[0].provider_id,
            "manifest_fingerprint": provider.bindings()[0].fingerprint,
        }},
    })
    store.create_mission("mission", "robots recon")
    store.save_workflow_plan("robots-plan", plan)

    assert core.authorize_workflow_task_for_plan("robots-plan", task) is False
    store.grant_workflow_approval(
        "robots-plan", task.id, "robots-approval", "operator",
        expires_at=4_000_000_000,
    )
    assert core.authorize_workflow_task_for_plan("robots-plan", task) is True
