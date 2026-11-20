from __future__ import annotations

import asyncio
import json
import socket
import ssl
import threading

import pytest

from whaxon.core import Core
from whaxon.core.scope import PinnedSocketAddress, ScopeMatch, ScopeResolution
from whaxon.core.tls_cert_v2 import (
    CAPABILITY_ID,
    TlsCertificateProvider,
    _certificate_findings,
    _decode_findings,
    _tls_cert_worker,
)
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.core.workflow_proposals import propose_tls_certificate_plan

HOST = "example.test"
NUMERIC = PinnedSocketAddress(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, ("192.0.2.10", 443))
CERTIFICATE = {
    "subject": ((("commonName", HOST),),),
    "issuer": ((("commonName", "Test CA"),),),
    "notBefore": "Nov 12 00:00:00 2026 GMT",
    "notAfter": "Nov 12 00:00:00 2027 GMT",
    "serialNumber": "01",
    "version": 3,
    "subjectAltName": (("DNS", HOST), ("DNS", "alt.example.test")),
}


class _Capture:
    def __init__(self) -> None:
        self.payload: dict | None = None
        self.closed = False

    def send_bytes(self, encoded: bytes) -> None:
        self.payload = json.loads(encoded.decode("utf-8"))

    def close(self) -> None:
        self.closed = True


class _FakeTls:
    def __init__(self, cert: dict) -> None:
        self.cert = cert

    def getpeercert(self) -> dict:
        return self.cert

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None


def _scope_resolution(allowed: bool = True) -> ScopeResolution:
    return ScopeResolution(
        ScopeMatch(allowed, "" if allowed else "one answer is outside scope"),
        (NUMERIC,) if allowed else (),
    )


def _provider(core: Core) -> TlsCertificateProvider:
    return next(
        item for item in core.providers._providers
        if isinstance(item, TlsCertificateProvider)
    )


def _task(provider: TlsCertificateProvider, *, target: str = HOST) -> WorkflowTask:
    manifest = provider.bindings()[0]
    return WorkflowTask(
        id="task-1",
        capability_id=CAPABILITY_ID,
        target=target,
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
        idempotency_key="tls-provider-test",
    )


def _write_scope(core: Core, *, in_scope: list[str], out_scope: list[str] | None = None) -> None:
    core.scope.path.write_text(json.dumps({
        "engagement": "tls-provider-test",
        "enabled": True,
        "in_scope": in_scope,
        "out_of_scope": out_scope or [],
        "notes": "",
    }), encoding="utf-8")
    core.scope.load()


def test_tls_manifest_is_pinned_fixed_port_and_closed() -> None:
    from whaxon.core.tls_cert_v2 import _MANIFEST

    assert _MANIFEST.scope_mode == "pinned_network"
    assert _MANIFEST.target_types == ("hostname",)
    assert _MANIFEST.input_schema["additionalProperties"] is False
    assert set(_MANIFEST.output_schema["required"]) == set(_MANIFEST.output_schema["properties"])
    assert "443" in " ".join(_MANIFEST.limitations)


def test_tls_worker_resolves_once_and_connects_only_to_numeric_sockaddr(monkeypatch, tmp_path) -> None:
    calls: list[tuple[str, int]] = []
    connects: list[tuple[str, int]] = []
    sni: list[str] = []

    class _Scope:
        def __init__(self, _path) -> None:
            pass

        def resolve_for_execution(self, target: str, *, port: int) -> ScopeResolution:
            calls.append((target, port))
            return _scope_resolution()

    class _Raw:
        def settimeout(self, _value: float) -> None:
            pass

        def connect(self, address) -> None:
            connects.append(address)

        def close(self) -> None:
            pass

    class _Context:
        def wrap_socket(self, _raw, *, server_hostname: str):
            sni.append(server_hostname)
            return _FakeTls(CERTIFICATE)

    monkeypatch.setattr("whaxon.core.tls_cert_v2.ScopeManager", _Scope)
    monkeypatch.setattr("whaxon.core.tls_cert_v2.socket.socket", lambda *_args: _Raw())
    monkeypatch.setattr("whaxon.core.tls_cert_v2.ssl.create_default_context", _Context)
    captured = _Capture()

    _tls_cert_worker(captured, HOST, str(tmp_path / "scope.json"))

    assert calls == [(HOST, 443)]
    assert connects == [("192.0.2.10", 443)]
    assert sni == [HOST]
    assert captured.payload["status"] == "complete"
    assert captured.closed


def test_tls_worker_denies_mixed_scope_resolution_before_any_socket(monkeypatch, tmp_path) -> None:
    calls = []

    class _Scope:
        def __init__(self, _path) -> None:
            pass

        def resolve_for_execution(self, target: str, *, port: int) -> ScopeResolution:
            calls.append((target, port))
            return _scope_resolution(allowed=False)

    monkeypatch.setattr("whaxon.core.tls_cert_v2.ScopeManager", _Scope)
    monkeypatch.setattr(
        "whaxon.core.tls_cert_v2.socket.socket",
        lambda *_args: pytest.fail("socket opened for a mixed/out-of-scope answer"),
    )
    captured = _Capture()

    _tls_cert_worker(captured, HOST, str(tmp_path / "scope.json"))

    assert calls == [(HOST, 443)]
    assert captured.payload["status"] == "scope_denied"



def test_real_scope_rejects_mixed_in_and_out_of_scope_dns_answers_before_connect(
    tmp_path, monkeypatch,
) -> None:
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "engagement": "mixed-dns-test",
        "enabled": True,
        "in_scope": [HOST, "192.0.2.0/24"],
        "out_of_scope": ["198.51.100.0/24"],
        "notes": "",
    }), encoding="utf-8")
    answers = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.10", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("198.51.100.20", 443)),
    ]
    resolve_calls = []
    monkeypatch.setattr(
        "whaxon.core.scope.socket.getaddrinfo",
        lambda *args, **kwargs: (resolve_calls.append((args, kwargs)) or answers),
    )
    monkeypatch.setattr(
        "whaxon.core.tls_cert_v2.socket.socket",
        lambda *_args: pytest.fail("socket opened after one DNS answer was out of scope"),
    )
    captured = _Capture()

    _tls_cert_worker(captured, HOST, str(scope_path))

    assert len(resolve_calls) == 1
    assert resolve_calls[0][0][0] == HOST
    assert resolve_calls[0][0][1] == 443
    assert captured.payload["status"] == "scope_denied"


def test_tls_hostname_verification_failure_retries_same_pinned_ip_and_sni(monkeypatch) -> None:
    connects: list[tuple[str, int]] = []
    sni: list[str] = []
    contexts: list[str] = []

    class _Raw:
        def settimeout(self, _value: float) -> None:
            pass

        def connect(self, address) -> None:
            connects.append(address)

        def close(self) -> None:
            pass

    class _VerifiedContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, _raw, *, server_hostname: str):
            sni.append(server_hostname)
            raise ssl.SSLCertVerificationError("hostname mismatch")

    class _UnverifiedContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, _raw, *, server_hostname: str):
            sni.append(server_hostname)
            return _FakeTls(CERTIFICATE)

    def _default_context():
        contexts.append("verified")
        return _VerifiedContext()

    def _unverified_context(_protocol):
        contexts.append("unverified")
        return _UnverifiedContext()

    monkeypatch.setattr("whaxon.core.tls_cert_v2.socket.socket", lambda *_args: _Raw())
    monkeypatch.setattr("whaxon.core.tls_cert_v2.ssl.create_default_context", _default_context)
    monkeypatch.setattr("whaxon.core.tls_cert_v2.ssl.SSLContext", _unverified_context)

    from whaxon.core.tls_cert_v2 import _read_certificate

    certificate, error = _read_certificate(NUMERIC, HOST)

    assert error.startswith("SSLCertVerificationError:")
    assert certificate == CERTIFICATE
    assert connects == [("192.0.2.10", 443), ("192.0.2.10", 443)]
    assert sni == [HOST, HOST]
    assert contexts == ["verified", "unverified"]


def test_invalid_certificate_findings_keep_san_names_informational() -> None:
    findings = _certificate_findings(CERTIFICATE, HOST, "hostname mismatch")
    decoded = _decode_findings([item.to_dict() for item in findings], HOST)

    assert [item.kind for item in decoded] == [
        "ssl_cert_invalid", "ssl_cert", "recon_discovered_host",
    ]
    assert decoded[0].cvss == 5.9
    assert decoded[0].cwe == "CWE-295"
    assert decoded[0].remediation == "Use a certificate from a trusted CA and ensure the hostname matches."
    assert decoded[0].impact == "Certificate verification failure permits MITM if users ignore the warning."
    assert decoded[-1].data == {
        "host": "alt.example.test", "relation": "san", "from": HOST,
    }
    assert decoded[-1].impact == "Additional hostname associated with the target via certificate SANs."




def test_invalid_certificate_survives_empty_cert_none_fallback(monkeypatch) -> None:
    contexts = []

    class _Raw:
        def settimeout(self, _value: float) -> None:
            pass

        def connect(self, _address) -> None:
            pass

        def close(self) -> None:
            pass

    class _VerifiedContext:
        def wrap_socket(self, _raw, *, server_hostname: str):
            assert server_hostname == HOST
            raise ssl.SSLCertVerificationError("hostname mismatch")

    class _UnverifiedContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, _raw, *, server_hostname: str):
            assert server_hostname == HOST
            return _FakeTls({})

    monkeypatch.setattr("whaxon.core.tls_cert_v2.socket.socket", lambda *_args: _Raw())
    monkeypatch.setattr(
        "whaxon.core.tls_cert_v2.ssl.create_default_context",
        lambda: (contexts.append("verified") or _VerifiedContext()),
    )
    monkeypatch.setattr(
        "whaxon.core.tls_cert_v2.ssl.SSLContext",
        lambda _protocol: (contexts.append("unverified") or _UnverifiedContext()),
    )
    from whaxon.core.tls_cert_v2 import _read_certificate

    certificate, error = _read_certificate(NUMERIC, HOST)
    assert certificate is None
    decoded = _decode_findings(
        [item.to_dict() for item in _certificate_findings(certificate, HOST, error)], HOST,
    )

    assert contexts == ["verified", "unverified"]
    assert [item.kind for item in decoded] == ["ssl_cert_invalid"]
    assert decoded[0].cvss == 5.9
    assert decoded[0].cwe == "CWE-295"



def test_invalid_certificate_survives_failed_cert_none_retry(monkeypatch) -> None:
    class _Context:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

    attempts = []
    monkeypatch.setattr("whaxon.core.tls_cert_v2.ssl.create_default_context", lambda: _Context())
    monkeypatch.setattr("whaxon.core.tls_cert_v2.ssl.SSLContext", lambda _protocol: _Context())

    def _connect(_address, _hostname, _context):
        attempts.append(True)
        if len(attempts) == 1:
            raise ssl.SSLCertVerificationError("hostname mismatch")
        raise OSError("second pinned connection refused")

    monkeypatch.setattr("whaxon.core.tls_cert_v2._socket_connect", _connect)
    from whaxon.core.tls_cert_v2 import _read_certificate

    certificate, error = _read_certificate(NUMERIC, HOST)
    assert certificate is None
    decoded = _decode_findings(
        [item.to_dict() for item in _certificate_findings(certificate, HOST, error)], HOST,
    )

    assert len(attempts) == 2
    assert [item.kind for item in decoded] == ["ssl_cert_invalid"]

def test_tls_plan_proposal_is_fixed_and_requires_exact_approval_before_socket(
    tmp_path, monkeypatch,
) -> None:
    core = Core(tmp_path)
    _write_scope(core, in_scope=[HOST])
    core.create_mission("tls-mission", "Review a TLS certificate")
    provider = _provider(core)
    proposal = propose_tls_certificate_plan(
        core, mission_id="tls-mission", plan_id="tls-plan", target=HOST,
    )
    assert proposal["status"] == "proposed"
    assert proposal["approval_granted"] is False
    assert proposal["provider_id"] == provider.bindings()[0].provider_id
    plan = WorkflowPlan.from_dict(proposal["plan"])
    assert plan.metadata["provider_bindings"]["task-1"] == {
        "provider_id": provider.bindings()[0].provider_id,
        "manifest_fingerprint": provider.bindings()[0].fingerprint,
    }
    task = plan.tasks[0]
    core.save_workflow_plan("tls-plan", WorkflowPlan.from_dict(proposal["plan"]))
    monkeypatch.setattr(core.scope, "check_for_pinned_execution", lambda _target: ScopeMatch(True))

    socket_calls: list[object] = []
    monkeypatch.setattr(
        "whaxon.core.tls_cert_v2.socket.socket",
        lambda *_args: socket_calls.append(_args),
    )

    assert core.authorize_workflow_task_for_plan("tls-plan", task) is False
    assert socket_calls == []



def test_tls_plan_proposal_rejects_out_of_scope_and_url_targets(tmp_path) -> None:
    core = Core(tmp_path)
    core.create_mission("tls-mission", "Review a TLS certificate")
    _write_scope(core, in_scope=["other.test"])
    denied = propose_tls_certificate_plan(
        core, mission_id="tls-mission", plan_id="tls-plan-denied", target=HOST,
    )
    assert denied["status"] == "blocked"
    assert "outside current scope" in denied["reason"]

    _write_scope(core, in_scope=[HOST])
    invalid = propose_tls_certificate_plan(
        core, mission_id="tls-mission", plan_id="tls-plan-url",
        target=f"https://{HOST}/",
    )
    assert invalid["status"] == "blocked"
    assert "normalized hostname" in invalid["reason"]

def test_tls_dispatch_persists_sealed_evidence_and_marks_job_v2(tmp_path, monkeypatch) -> None:
    core = Core(tmp_path)
    _write_scope(core, in_scope=[HOST])
    provider = _provider(core)

    class _Child:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self) -> dict:
            return {
                "status": "complete",
                "certificate": CERTIFICATE,
                "verification_error": "",
            }

        def request_termination(self) -> None:
            pass

    monkeypatch.setattr("whaxon.core.tls_cert_v2._BoundedDnsWorker", _Child)

    async def _run():
        return await provider.dispatch(_task(provider))

    result = asyncio.run(_run())
    stored = core.store.get_findings(result["job_id"])
    job = core.store.get(result["job_id"])

    assert result["exit_code"] == 0
    assert [finding["kind"] for finding in stored] == ["ssl_cert", "recon_discovered_host"]
    assert job is not None and job["status"] == "finished"
    assert core.store.is_engine_v2_execution_job(result["job_id"]) is True


def test_tls_dispatch_timeout_marks_job_failed(tmp_path, monkeypatch) -> None:
    core = Core(tmp_path)
    _write_scope(core, in_scope=[HOST])
    provider = _provider(core)

    class _Child:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self) -> dict:
            raise TimeoutError("hard child deadline")

        def request_termination(self) -> None:
            pass

    monkeypatch.setattr("whaxon.core.tls_cert_v2._BoundedDnsWorker", _Child)

    async def _run():
        with pytest.raises(TimeoutError):
            await provider.dispatch(_task(provider))

    asyncio.run(_run())


def test_tls_dispatch_cancellation_requests_child_termination(tmp_path, monkeypatch) -> None:
    core = Core(tmp_path)
    _write_scope(core, in_scope=[HOST])
    provider = _provider(core)
    entered = threading.Event()
    release = threading.Event()
    terminated = threading.Event()

    class _Child:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self) -> dict:
            entered.set()
            release.wait(timeout=1)
            return {}

        def request_termination(self) -> None:
            terminated.set()
            release.set()

    monkeypatch.setattr("whaxon.core.tls_cert_v2._BoundedDnsWorker", _Child)

    async def _run() -> None:
        task = asyncio.create_task(provider.dispatch(_task(provider)))
        await asyncio.to_thread(entered.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_run())
    assert terminated.is_set()
