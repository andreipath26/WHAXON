from __future__ import annotations

import asyncio
import json
import time

import dns.resolver
import pytest

from whaxon.core import Core, dns_full_v2
from whaxon.core.dns_full_v2 import (
    CAPABILITY_ID,
    DnsFullPostureProvider,
    _decode_findings,
    _dns_full_worker,
)
from whaxon.core.findings import Finding
from whaxon.core.workflow import WorkflowPlan
from whaxon.core.workflow_proposals import propose_dns_full_posture_plan


def _finding(kind: str, severity: str, data: dict, raw_line: str, **overrides) -> dict:
    record = Finding(
        kind=kind,
        severity=severity,
        source="recon:dns_full",
        data=data,
        raw_line=raw_line,
        remediation=overrides.get("remediation", ""),
        impact=overrides.get("impact", ""),
        cvss=overrides.get("cvss"),
        cwe=overrides.get("cwe", ""),
    )
    return record.to_dict()


def _records(target: str) -> list[dict]:
    return [
        _finding(
            "dns_caa", "info", {"host": target, "value": '0 issue "ca.example"'},
            f'{target} CAA 0 issue "ca.example"',
        ),
        _finding(
            "dns_dmarc_permissive", "medium",
            {"host": target, "record": "v=DMARC1; p=none", "policy": "none"},
            f"_dmarc.{target}: DMARC p=none (v=DMARC1; p=none)",
            remediation="Move DMARC to quarantine or reject.",
            impact="A permissive policy allows sender forgery.",
            cwe="CWE-290",
            cvss=5.3,
        ),
        _finding(
            "dns_spf", "info", {"host": target, "record": "v=spf1 -all"},
            f"{target} SPF v=spf1 -all",
        ),
    ]


def _fixture_child(conn, target: str, _scope_path: str) -> None:
    conn.send_bytes(json.dumps({
        "status": "complete", "findings": _records(target),
    }).encode("utf-8"))
    conn.close()


def _write_scope(core: Core, in_scope: list[str], out_scope: list[str] | None = None) -> None:
    core.scope.path.write_text(json.dumps({
        "engagement": "dns-full-test",
        "enabled": True,
        "in_scope": in_scope,
        "out_of_scope": out_scope or [],
        "notes": "deterministic DNS posture fixture",
    }), encoding="utf-8")
    core.scope.load()


def test_dns_full_manifest_and_decoder_are_closed_for_fixed_observations(tmp_path):
    core = Core(tmp_path)
    provider = next(
        item for item in core.providers._providers
        if isinstance(item, DnsFullPostureProvider)
    )
    manifest = provider.bindings()[0]
    assert manifest.capability_id == CAPABILITY_ID
    assert manifest.input_schema["additionalProperties"] is False
    assert set(manifest.output_schema["required"]) == set(manifest.output_schema["properties"])
    decoded = _decode_findings(_records("example.test"), "example.test")
    assert [item.kind for item in decoded] == ["dns_caa", "dns_dmarc_permissive", "dns_spf"]

    malformed = _records("example.test")
    malformed[0]["data"] = {"host": "example.test", "value": "x", "record_type": "TXT"}
    with pytest.raises(RuntimeError, match="fixed-query observation"):
        _decode_findings(malformed, "example.test")


def test_dns_full_queries_only_caa_host_dmarc_txt_and_host_spf_txt(monkeypatch):
    calls: list[tuple[str, str, bool]] = []

    class _Record:
        def __init__(self, value: str) -> None:
            self.value = value

        def to_text(self) -> str:
            return self.value

    class _Answers:
        rrset = object()

        def __init__(self, value: str) -> None:
            self.records = [_Record(value)]

        def __iter__(self):
            return iter(self.records)

    class _Resolver:
        timeout = 0.0
        lifetime = 0.0

        def resolve(self, host, record_type, *, raise_on_no_answer):
            calls.append((host, record_type, raise_on_no_answer))
            values = {
                ("example.test", "CAA"): '0 issue "ca.example"',
                ("_dmarc.example.test", "TXT"): '"v=DMARC1; p=reject"',
                ("example.test", "TXT"): '"v=spf1 -all"',
            }
            return _Answers(values[(host, record_type)])

    monkeypatch.setattr(dns.resolver, "Resolver", _Resolver)
    from whaxon.core.recon_checks import check_dns_full

    findings = check_dns_full("example.test")
    assert calls == [
        ("example.test", "CAA", False),
        ("_dmarc.example.test", "TXT", False),
        ("example.test", "TXT", False),
    ]
    assert len(findings) == 3


def test_dns_full_child_denies_unscoped_dmarc_name_before_resolver_query(tmp_path, monkeypatch):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "engagement": "exact-host-only",
        "enabled": True,
        "in_scope": ["example.test"],
        "out_of_scope": [],
        "notes": "",
    }), encoding="utf-8")

    class _Capture:
        payload = None

        def send_bytes(self, encoded: bytes) -> None:
            self.payload = json.loads(encoded.decode("utf-8"))

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "whaxon.core.recon_checks.check_dns_full",
        lambda _target: pytest.fail("DNS lookup ran outside the explicitly scoped hostname set"),
    )
    conn = _Capture()
    _dns_full_worker(conn, "example.test", str(scope_path))
    assert conn.payload["status"] == "scope_denied"
    assert conn.payload["reason"].startswith("_dmarc.example.test:")


def test_dns_full_proposal_requires_scope_for_base_and_dmarc_subdomain(tmp_path):
    core = Core(tmp_path)
    core.create_mission("dns-full-mission", "Review email and certificate DNS posture")
    _write_scope(core, ["example.test"])

    proposal = propose_dns_full_posture_plan(
        core, mission_id="dns-full-mission", plan_id="dns-full-plan",
        target="example.test",
    )
    assert proposal["status"] == "blocked"
    assert "_dmarc.example.test" in proposal["reason"]


def test_dns_full_workflow_persists_sealed_findings_and_requires_approval(tmp_path, monkeypatch):
    core = Core(tmp_path)
    _write_scope(core, ["example.test", "*.example.test", "192.0.2.0/24"])
    monkeypatch.setattr(
        core.scope,
        "check_for_execution",
        lambda _target: pytest.fail("DNS-only workflow used the execution scope gate"),
    )
    provider = next(
        item for item in core.providers._providers
        if isinstance(item, DnsFullPostureProvider)
    )
    monkeypatch.setattr(provider, "_readiness", lambda: True)

    core.create_mission("dns-full-mission", "Review email and certificate DNS posture")
    unapproved = propose_dns_full_posture_plan(
        core, mission_id="dns-full-mission", plan_id="dns-full-unapproved",
        target="example.test",
    )
    assert unapproved["status"] == "proposed"
    core.save_workflow_plan(
        "dns-full-unapproved", WorkflowPlan.from_dict(unapproved["plan"]),
    )
    _bind_real_worker = dns_full_v2._BoundedDnsWorker
    monkeypatch.setattr(
        dns_full_v2,
        "_BoundedDnsWorker",
        lambda target, scope_path, timeout_s, **kwargs: _bind_real_worker(
            target, scope_path, timeout_s, worker_target=_fixture_child,
        ),
    )

    denied = asyncio.run(core.run_workflow_plan("dns-full-unapproved"))
    assert denied["complete"] is True
    assert denied["tasks"][0]["status"] == "blocked"

    approved = propose_dns_full_posture_plan(
        core, mission_id="dns-full-mission", plan_id="dns-full-plan",
        target="example.test",
    )
    assert approved["status"] == "proposed"
    core.save_workflow_plan(
        "dns-full-plan", WorkflowPlan.from_dict(approved["plan"]),
    )
    assert core.grant_workflow_approval(
        "dns-full-plan", "task-1", "dns-full-approval", "test-operator",
        expires_at=time.time() + 3600,
    )
    result = asyncio.run(core.run_workflow_plan("dns-full-plan"))
    assert result["complete"] is True
    assert result["tasks"][0]["status"] == "succeeded"
    evidence = core.workflow_report("dns-full-plan")
    assert evidence["status"] == "complete"
    assert [item["kind"] for item in evidence["findings"]] == [
        "dns_caa", "dns_dmarc_permissive", "dns_spf",
    ]
