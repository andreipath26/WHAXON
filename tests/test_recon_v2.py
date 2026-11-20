"""Qualification coverage for the isolated passive DNS V2 provider."""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import dns.resolver
import pytest

from whaxon.core import Core, recon_v2
from whaxon.core.recon_checks import check_dns
from whaxon.core.recon_v2 import (
    CAPABILITY_ID,
    MAX_CHILD_OUTPUT_BYTES,
    RECORD_TYPES,
    _BoundedDnsWorker,
    _decode_findings,
    _send_child_result,
)
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.core.workflow_proposals import propose_passive_dns_plan


def _finding(target: str, record_type: str, value: str) -> dict:
    return {
        "kind": "dns_record",
        "severity": "info",
        "source": "recon:dns",
        "data": {"record_type": record_type, "value": value, "host": target},
        "raw_line": f"{target} {record_type} {value}",
        "remediation": "",
        "impact": "",
        "cvss": None,
        "cwe": "",
        "references": [],
        "lookup_hint": "",
        "request_context": {},
    }


def _fixture_dns_child(conn, target: str, _scope_path: str) -> None:
    records = [_finding(target, kind, f"{kind.lower()}-fixture") for kind in RECORD_TYPES]
    conn.send_bytes(json.dumps({"status": "complete", "findings": records}).encode())
    conn.close()


def _slow_dns_child(conn, _target: str, _scope_path: str) -> None:
    marker = Path(os.environ["WHAXON_TEST_DNS_CHILD_MARKER"])
    marker.write_text(str(os.getpid()), encoding="ascii")
    time.sleep(30)
    conn.close()


def _write_scope(core: Core, in_scope: list[str], out_scope: list[str] | None = None) -> None:
    core.scope.path.write_text(json.dumps({
        "engagement": "dns-provider-test",
        "enabled": True,
        "in_scope": in_scope,
        "out_of_scope": out_scope or [],
        "notes": "deterministic provider qualification fixture",
    }), encoding="utf-8")
    core.scope.load()


def _provider(core: Core, monkeypatch):
    provider = next(
        item for item in core.providers._providers
        if isinstance(item, recon_v2.PassiveDnsReconProvider)
    )
    monkeypatch.setattr(provider, "_readiness", lambda: True)
    return provider


def _bind_fake_worker(monkeypatch, worker_target) -> None:
    real_worker = recon_v2._BoundedDnsWorker
    monkeypatch.setattr(
        recon_v2,
        "_BoundedDnsWorker",
        lambda target, scope_path, timeout_s: real_worker(
            target, scope_path, timeout_s, worker_target=worker_target,
        ),
    )


def _approved_plan(core: Core, plan_id: str = "dns-plan") -> dict:
    core.create_mission("dns-mission", "Collect scoped passive DNS observations")
    proposal = propose_passive_dns_plan(
        core,
        mission_id="dns-mission",
        plan_id=plan_id,
        target="example.test",
    )
    assert proposal["status"] == "proposed"
    assert proposal["approval_granted"] is False
    assert proposal["execution_submitted"] is False
    core.save_workflow_plan(plan_id, WorkflowPlan.from_dict(proposal["plan"]))
    assert core.grant_workflow_approval(
        plan_id, "task-1", "dns-approval", "test-operator",
        expires_at=time.time() + 3600,
    )
    return proposal


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_dns_manifest_declares_an_accepting_closed_output_contract(tmp_path):
    core = Core(tmp_path)
    provider = next(
        item for item in core.providers._providers
        if isinstance(item, recon_v2.PassiveDnsReconProvider)
    )
    schema = provider.bindings()[0].output_schema
    assert set(schema["required"]) <= set(schema["properties"])
    assert schema["properties"]["tool_id"] == {"const": CAPABILITY_ID}
    assert schema["properties"]["findings"]["type"] == "array"
    assert schema["additionalProperties"] is False

    sample = {
        "job_id": "job-1",
        "tool_id": CAPABILITY_ID,
        "target": "example.test",
        "exit_code": 0,
        "duration_s": 0.1,
        "findings": [],
        "provider_id": provider.bindings()[0].provider_id,
        "provider_version": provider.bindings()[0].provider_version,
        "manifest_fingerprint": provider.bindings()[0].fingerprint,
        "registry_digest": core.capabilities.digest,
        "transport": "isolated_process",
    }
    assert set(sample) == set(schema["properties"])


def test_dns_query_contract_uses_only_fixed_record_types(monkeypatch):
    calls: list[tuple[str, str, bool]] = []

    class _Record:
        def __init__(self, value: str) -> None:
            self.value = value

        def to_text(self) -> str:
            return self.value

    class _Answers:
        rrset = object()

        def __init__(self, record_type: str) -> None:
            self.records = [_Record(f"{record_type.lower()}-answer")]

        def __iter__(self):
            return iter(self.records)

    class _Resolver:
        timeout = 0.0
        lifetime = 0.0

        def resolve(self, host, record_type, *, raise_on_no_answer):
            calls.append((host, record_type, raise_on_no_answer))
            return _Answers(record_type)

    monkeypatch.setattr(dns.resolver, "Resolver", _Resolver)
    findings = check_dns("example.test")

    assert tuple(record_type for _, record_type, _ in calls) == RECORD_TYPES
    assert all(host == "example.test" and no_answer is False
               for host, _, no_answer in calls)
    assert [item.data["record_type"] for item in findings] == list(RECORD_TYPES)
    assert all(item.kind == "dns_record" and item.source == "recon:dns" for item in findings)
    assert len(json.dumps([item.to_dict() for item in findings]).encode()) < MAX_CHILD_OUTPUT_BYTES


def test_dns_child_output_cap_replaces_oversized_payload_with_error():
    class _Capture:
        value: dict | None = None

        def send_bytes(self, encoded: bytes) -> None:
            self.value = json.loads(encoded.decode("utf-8"))

    conn = _Capture()
    _send_child_result(conn, {
        "status": "complete",
        "findings": [],
        "oversized": "x" * MAX_CHILD_OUTPUT_BYTES,
    })
    assert conn.value == {
        "status": "error",
        "error": "child output exceeded the configured limit",
    }


def test_dns_findings_decoder_rejects_provider_contract_drift():
    records = [_finding("example.test", record_type, "answer")
               for record_type in RECORD_TYPES]
    decoded = _decode_findings(records, "example.test")
    assert [item.data["record_type"] for item in decoded] == list(RECORD_TYPES)

    malformed = [dict(
        records[0],
        data={"record_type": "CAA", "value": "x", "host": "example.test"},
    )]
    with pytest.raises(RuntimeError, match="unsupported record type"):
        _decode_findings(malformed, "example.test")


def test_dns_worker_hard_deadline_terminates_spawned_child(tmp_path, monkeypatch):
    marker = tmp_path / "dns-child.pid"
    monkeypatch.setenv("WHAXON_TEST_DNS_CHILD_MARKER", str(marker))
    worker = _BoundedDnsWorker(
        "example.test", str(tmp_path / "scope.json"), 5.0,
        worker_target=_slow_dns_child,
    )

    with pytest.raises(TimeoutError, match="hard deadline"):
        worker.run()

    pid = int(marker.read_text(encoding="ascii"))
    deadline = time.monotonic() + 3
    while _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _pid_alive(pid)


def test_passive_dns_workflow_persists_and_seals_child_findings(tmp_path, monkeypatch):
    core = Core(tmp_path)
    _write_scope(core, ["example.test"])
    _provider(core, monkeypatch)
    _bind_fake_worker(monkeypatch, _fixture_dns_child)
    proposal = _approved_plan(core)
    assert proposal["capability_id"] == CAPABILITY_ID

    result = asyncio.run(core.run_workflow_plan("dns-plan"))
    assert result["complete"] is True
    assert result["tasks"][0]["status"] == "succeeded"

    evidence = core.workflow_evidence("dns-plan")
    attempt = evidence["attempts"][0]
    assert attempt["evidence_status"] == "recorded"
    assert attempt["integrity_status"] == "verified"
    job_id = attempt["job_id"]
    assert core.store.is_engine_v2_execution_job(job_id)
    findings = core.store.get_findings(job_id)
    assert [item["data"]["record_type"] for item in findings] == list(RECORD_TYPES)
    assert core.store.has_valid_workflow_evidence_seal(job_id)

    core.store.append_line(job_id, "stdout", "post-seal mutation")
    changed = core.workflow_evidence("dns-plan")["attempts"][0]
    assert changed["integrity_status"] == "changed"
    assert core.store.has_valid_workflow_evidence_seal(job_id) is False


def test_passive_dns_child_rechecks_revoked_scope_before_query(tmp_path, monkeypatch):
    core = Core(tmp_path)
    _write_scope(core, ["example.test"])
    _provider(core, monkeypatch)
    proposal = _approved_plan(core, "dns-scope-race")
    assert proposal["status"] == "proposed"

    original = core.scope.check_for_dns_query
    checks = 0

    def revoke_after_dispatch_authorization(target: str):
        nonlocal checks
        decision = original(target)
        checks += 1
        # The scheduler authorizes once while claiming the task, then repeats
        # the check at the consequential dispatch boundary. Revoke scope just
        # after that second authorization so the child must recheck persisted
        # scope before making any DNS query.
        if checks == 2:
            _write_scope(core, ["other.test"], ["example.test"])
        return decision

    monkeypatch.setattr(core.scope, "check_for_dns_query", revoke_after_dispatch_authorization)
    result = asyncio.run(core.run_workflow_plan("dns-scope-race"))

    assert result["tasks"][0]["status"] == "uncertain"
    assert checks == 2
    assert core.store.history(limit=10)[0]["status"] == "failed"
    assert core.workflow_evidence("dns-scope-race")["all_evidence_recorded"] is False


def test_passive_dns_dispatch_cancellation_terminates_child_and_records_failure(
    tmp_path, monkeypatch,
):
    core = Core(tmp_path)
    _write_scope(core, ["example.test"])
    provider = _provider(core, monkeypatch)
    marker = tmp_path / "cancelled-dns-child.pid"
    monkeypatch.setenv("WHAXON_TEST_DNS_CHILD_MARKER", str(marker))
    _bind_fake_worker(monkeypatch, _slow_dns_child)
    task = WorkflowTask(
        "task-cancel",
        CAPABILITY_ID,
        "example.test",
        permissions=("network.scan",),
        impact="moderate",
        timeout_s=5.0,
        idempotency_key="dns-cancel-test",
    )

    async def cancel_after_child_start() -> str:
        operation = asyncio.create_task(provider.dispatch(task))
        deadline = time.monotonic() + 5
        # File creation can precede the child's PID write by a scheduling tick.
        child_pid = ""
        while time.monotonic() < deadline:
            try:
                child_pid = marker.read_text(encoding="ascii").strip()
            except FileNotFoundError:
                pass
            if child_pid:
                break
            await asyncio.sleep(0.02)
        assert child_pid, "spawned DNS worker did not publish its pid"
        operation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await operation
        return child_pid

    child_pid = asyncio.run(cancel_after_child_start())
    pid = int(child_pid)
    deadline = time.monotonic() + 3
    while _pid_alive(pid) and time.monotonic() < deadline:
        await_sleep = 0.02
        time.sleep(await_sleep)
    assert not _pid_alive(pid)

    failed = next(
        item for item in core.store.history(limit=20)
        if item["tool"] == CAPABILITY_ID and item["target"] == "example.test"
    )
    assert failed["status"] == "failed"
