"""Scheduler ownership and sealed evidence for bounded V2 finding verification."""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from whaxon.core import Core
from whaxon.core.findings import Finding
from whaxon.core.providers import FindingVerificationProvider
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


class _SQLiFixture(BaseHTTPRequestHandler):
    requests = 0
    vulnerable = True
    reflect_xss = True
    scope_path = None
    revoke_after = None

    def do_GET(self):
        type(self).requests += 1
        if (
            type(self).scope_path is not None
            and type(self).revoke_after == type(self).requests
        ):
            type(self).scope_path.write_text(json.dumps({
                "engagement": "revoked-fixture-scope",
                "enabled": True,
                "in_scope": [],
                "out_of_scope": [],
                "notes": "revoked during controlled test",
            }), encoding="utf-8")
        query = parse_qs(urlsplit(self.path).query)
        value = query.get("id", [""])[0]
        xss_value = query.get("q", [""])[0]
        body = (
            xss_value.encode() if type(self).reflect_xss and "whaxon_xss_" in xss_value
            else b"You have an error in your SQL syntax"
            if "'" in value and type(self).vulnerable else b"Product found"
        )
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def _bound_plan(core, *, plan_id, capability_id, target, inputs):
    core.create_mission(plan_id, "Exercise the bounded verifier on the controlled fixture")
    task = WorkflowTask(
        id="verification", capability_id=capability_id, target=target,
        inputs=inputs, permissions=("network.verify",), impact="moderate",
        timeout_s=75,
    )
    manifest = core.providers.manifest_for(capability_id)
    plan = WorkflowPlan(
        mission_id=plan_id, tasks=(task,),
        metadata={"provider_bindings": {task.id: {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }}},
    )
    core.save_workflow_plan(plan_id, plan)
    core.grant_workflow_approval(
        plan_id, task.id, f"approval-{plan_id}", "ci-operator",
        expires_at=time.time() + 120,
    )
    return task


async def _seed_sealed_source(core, *, plan_id, target, request_context=None, kind="sqli"):
    """Persist a test-only SQLmap result through the real scheduler seal path."""
    from whaxon.core.workflow import WorkflowPlan

    core.create_mission(plan_id, "Seed a sealed in-process scanner fixture")
    tool_id = "nuclei" if kind == "xss" else "sqlmap"
    task = WorkflowTask(
        id="scan", capability_id=f"tool.{tool_id}", target=target,
        permissions=("network.scan",), impact="moderate",
    )
    core.save_workflow_plan(plan_id, WorkflowPlan(mission_id=plan_id, tasks=(task,)))
    source_job = hashlib.sha256(plan_id.encode("utf-8")).hexdigest()[:12]

    async def fake_scan(_task):
        core.store.create(source_job)
        core.store.set_started(source_job, tool_id, target)
        core.store.mark_engine_v2_execution_job(source_job)
        core.store.append_finding(source_job, Finding(
            kind=kind, severity="high", source=tool_id,
            data={"parameter": "q" if kind == "xss" else "id"}, raw_line="controlled fixture finding",
            request_context=(request_context if request_context is not None else {
                "method": "GET", "url": target, "parameter": "id",
            }),
        ), 0)
        core.store.set_finished(source_job, 0, 0.01)
        return {
            "job_id": source_job, "tool_id": tool_id, "target": target,
            "exit_code": 0,
        }

    scheduler = core.workflow_scheduler(
        plan_id=plan_id, authorize=lambda _task: True, dispatch=fake_scan,
    )
    result = await scheduler.run(plan_id, max_tasks=1, max_concurrency=1)
    assert result["tasks"] == [{"id": "scan", "status": "succeeded"}]
    assert core.workflow_evidence(plan_id)["all_evidence_integrity_verified"] is True
    return source_job


def test_v2_verify_and_retest_are_scheduler_owned_and_sealed(tmp_path):
    _SQLiFixture.requests = 0
    _SQLiFixture.vulnerable = True
    _SQLiFixture.scope_path = None
    _SQLiFixture.revoke_after = None
    server = HTTPServer(("127.0.0.1", 0), _SQLiFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/search?id=1"
    try:
        async def exercise():
            core = Core(tmp_path / "data")
            await core.initialize(drain=False)

            source_job = await _seed_sealed_source(
                core, plan_id="source-plan", target=target,
            )

            _bound_plan(
                core, plan_id="verification-plan",
                capability_id=FindingVerificationProvider.VERIFY,
                target=target,
                inputs={"source_job_id": source_job, "finding_seq": 0},
            )
            verified = await core.run_workflow_plan(
                "verification-plan", max_tasks=1, max_concurrency=1,
            )
            assert verified["tasks"] == [{"id": "verification", "status": "succeeded"}]
            verify_evidence = core.workflow_evidence("verification-plan")
            assert verify_evidence["all_evidence_recorded"] is True
            assert verify_evidence["all_evidence_integrity_verified"] is True, verify_evidence
            verify_attempt = verify_evidence["attempts"][0]
            assert verify_attempt["findings"][0]["verification_status"] == "verified"
            assert verify_attempt["findings"][0]["verification_reason"].startswith(
                "SQL error signature"
            )

            _bound_plan(
                core, plan_id="retest-plan",
                capability_id=FindingVerificationProvider.RETEST,
                target=target,
                inputs={"source_job_id": verify_attempt["job_id"], "finding_seq": 0},
            )
            retested = await core.run_workflow_plan(
                "retest-plan", max_tasks=1, max_concurrency=1,
            )
            assert retested["tasks"] == [{"id": "verification", "status": "succeeded"}]
            retest_evidence = core.workflow_evidence("retest-plan")
            assert retest_evidence["all_evidence_integrity_verified"] is True
            finding = retest_evidence["attempts"][0]["findings"][0]
            assert finding["verification_status"] == "still_vulnerable"
            assert _SQLiFixture.requests == 12

            _SQLiFixture.vulnerable = False
            _bound_plan(
                core, plan_id="inconclusive-retest-plan",
                capability_id=FindingVerificationProvider.RETEST,
                target=target,
                inputs={"source_job_id": verify_attempt["job_id"], "finding_seq": 0},
            )
            inconclusive = await core.run_workflow_plan(
                "inconclusive-retest-plan", max_tasks=1, max_concurrency=1,
            )
            assert inconclusive["tasks"] == [{"id": "verification", "status": "succeeded"}]
            result = core.workflow_evidence("inconclusive-retest-plan")["attempts"][0]["findings"][0]
            assert result["verification_status"] == "inconclusive"
            assert "inconclusive" in result["verification_reason"]
            assert _SQLiFixture.requests == 18

        asyncio.run(exercise())
    finally:
        server.shutdown()
        server.server_close()


def test_v2_reflected_xss_verify_and_retest_are_scheduler_owned(tmp_path):
    _SQLiFixture.requests = 0
    _SQLiFixture.reflect_xss = True
    _SQLiFixture.scope_path = None
    _SQLiFixture.revoke_after = None
    server = HTTPServer(("127.0.0.1", 0), _SQLiFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/search?id=1"
    try:
        async def exercise():
            core = Core(tmp_path / "data")
            await core.initialize(drain=False)
            source_job = await _seed_sealed_source(
                core, plan_id="xss-source-plan", target=target, kind="xss",
                request_context={"method": "GET", "url": target, "parameter": "q"},
            )
            _bound_plan(
                core, plan_id="xss-verification-plan",
                capability_id=FindingVerificationProvider.VERIFY_XSS,
                target=target,
                inputs={"source_job_id": source_job, "finding_seq": 0},
            )
            verified = await core.run_workflow_plan(
                "xss-verification-plan", max_tasks=1, max_concurrency=1,
            )
            assert verified["tasks"] == [{"id": "verification", "status": "succeeded"}]
            evidence = core.workflow_evidence("xss-verification-plan")
            assert evidence["all_evidence_integrity_verified"] is True, evidence
            attempt = evidence["attempts"][0]
            assert attempt["findings"][0]["verification_status"] == "verified"
            verified_job = attempt["job_id"]

            _SQLiFixture.reflect_xss = False
            _bound_plan(
                core, plan_id="xss-retest-plan",
                capability_id=FindingVerificationProvider.RETEST_XSS,
                target=target,
                inputs={"source_job_id": verified_job, "finding_seq": 0},
            )
            retested = await core.run_workflow_plan(
                "xss-retest-plan", max_tasks=1, max_concurrency=1,
            )
            assert retested["tasks"] == [{"id": "verification", "status": "succeeded"}]
            retest_evidence = core.workflow_evidence("xss-retest-plan")
            assert retest_evidence["all_evidence_integrity_verified"] is True
            assert retest_evidence["attempts"][0]["findings"][0]["verification_status"] == "inconclusive"

        asyncio.run(exercise())
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
        thread.join(timeout=5)


def test_v2_retest_requires_a_prior_v2_verified_finding(tmp_path):
    async def exercise():
        core = Core(tmp_path / "data")
        await core.initialize(drain=False)
        target = "http://127.0.0.1:8000/search?id=1"
        source_job = await _seed_sealed_source(
            core, plan_id="source-plan", target=target,
        )
        _bound_plan(
            core, plan_id="retest-unverified-plan",
            capability_id=FindingVerificationProvider.RETEST,
            target=target,
            inputs={"source_job_id": source_job, "finding_seq": 0},
        )
        result = await core.run_workflow_plan(
            "retest-unverified-plan", max_tasks=1, max_concurrency=1,
        )
        assert result["tasks"] == [{"id": "verification", "status": "blocked"}]
        assert core.workflow_evidence("retest-unverified-plan")["all_evidence_recorded"] is False

    asyncio.run(exercise())


def test_v2_verify_rejects_mutated_source_after_evidence_seal(tmp_path):
    async def exercise():
        core = Core(tmp_path / "data")
        await core.initialize(drain=False)
        target = "http://127.0.0.1:8000/search?id=1"
        source_job = await _seed_sealed_source(
            core, plan_id="source-plan", target=target,
        )
        assert core.store.has_valid_workflow_evidence_seal(source_job) is True
        core.store.update_verification(
            source_job, 0, "verified", by="operator", reason="post-seal mutation",
        )
        assert core.store.has_valid_workflow_evidence_seal(source_job) is False
        _bound_plan(
            core, plan_id="mutated-source-verification-plan",
            capability_id=FindingVerificationProvider.VERIFY,
            target=target,
            inputs={"source_job_id": source_job, "finding_seq": 0},
        )
        result = await core.run_workflow_plan(
            "mutated-source-verification-plan", max_tasks=1, max_concurrency=1,
        )
        assert result["tasks"] == [{"id": "verification", "status": "blocked"}]
        assert core.workflow_evidence(
            "mutated-source-verification-plan",
        )["all_evidence_recorded"] is False

    asyncio.run(exercise())


def test_v2_verification_rejects_hostname_targets_before_dispatch(tmp_path):
    async def exercise():
        core = Core(tmp_path / "data")
        await core.initialize(drain=False)
        target = "http://localhost:8000/search?id=1"
        source_job = await _seed_sealed_source(
            core, plan_id="source-plan", target=target,
        )
        task = _bound_plan(
            core, plan_id="hostname-verification-plan",
            capability_id=FindingVerificationProvider.VERIFY,
            target=target,
            inputs={"source_job_id": source_job, "finding_seq": 0},
        )
        try:
            core.providers.resolve_task(task)
        except ValueError as exc:
            assert "IP literal" in str(exc)
        else:
            raise AssertionError("hostname verification target must be rejected")

    asyncio.run(exercise())


def test_v2_verifier_readiness_and_inventory_are_documented(tmp_path):
    async def exercise():
        core = Core(tmp_path / "data")
        await core.initialize(drain=False)
        rows = [
            row for row in core.providers.inventory()
            if row.get("provider_id") == FindingVerificationProvider.PROVIDER_ID
        ]
        assert {row["capability_id"] for row in rows} == {
            FindingVerificationProvider.VERIFY,
            FindingVerificationProvider.RETEST,
            FindingVerificationProvider.VERIFY_XSS,
            FindingVerificationProvider.RETEST_XSS,
        }
        assert all(
            row["provider_version"] == FindingVerificationProvider.PROVIDER_VERSION
            and row["readiness"] == "registered"
            and row["smoke_tested"] is False
            and row["lab_validated"] is False
            and row["end_to_end_verified"] is False
            for row in rows
        )
        inventory = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "ENGINE_V2_LEGACY_EXECUTION_INVENTORY.md"
        ).read_text(encoding="utf-8")
        section = inventory[
            inventory.index("The separately bound HTTP verifier"):
            inventory.index("The built-in adapter registry")
        ]
        assert all(capability in section for capability in (
            FindingVerificationProvider.VERIFY,
            FindingVerificationProvider.RETEST,
            FindingVerificationProvider.VERIFY_XSS,
            FindingVerificationProvider.RETEST_XSS,
        ))

    asyncio.run(exercise())


def test_v2_verification_authorizes_contextless_and_rejects_changed_path(tmp_path):
    _SQLiFixture.requests = 0
    _SQLiFixture.vulnerable = True
    _SQLiFixture.scope_path = None
    _SQLiFixture.revoke_after = None
    server = HTTPServer(("127.0.0.1", 0), _SQLiFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/search?id=1"
    try:
        async def exercise():
            core = Core(tmp_path / "data")
            await core.initialize(drain=False)
            source_job = await _seed_sealed_source(
                core, plan_id="contextless-source-plan", target=target,
                request_context={},
            )
            _bound_plan(
                core, plan_id="contextless-verification-plan",
                capability_id=FindingVerificationProvider.VERIFY,
                target=target,
                inputs={"source_job_id": source_job, "finding_seq": 0},
            )
            verified = await core.run_workflow_plan(
                "contextless-verification-plan", max_tasks=1, max_concurrency=1,
            )
            assert verified["tasks"] == [{"id": "verification", "status": "succeeded"}]
            evidence = core.workflow_evidence("contextless-verification-plan")
            assert evidence["all_evidence_integrity_verified"] is True
            assert evidence["attempts"][0]["findings"][0]["verification_status"] == "verified"
            assert _SQLiFixture.requests == 6

            other_path_source = await _seed_sealed_source(
                core, plan_id="changed-path-source-plan", target=target,
                request_context={
                    "method": "GET", "url": target.replace("/search", "/other"),
                    "parameter": "id",
                },
            )
            _bound_plan(
                core, plan_id="changed-path-verification-plan",
                capability_id=FindingVerificationProvider.VERIFY,
                target=target,
                inputs={"source_job_id": other_path_source, "finding_seq": 0},
            )
            result = await core.run_workflow_plan(
                "changed-path-verification-plan", max_tasks=1, max_concurrency=1,
            )
            assert result["tasks"] == [{"id": "verification", "status": "succeeded"}]
            changed = core.workflow_evidence("changed-path-verification-plan")
            assert changed["all_evidence_integrity_verified"] is True
            finding = changed["attempts"][0]["findings"][0]
            assert finding["verification_status"] == "candidate"
            assert "scope authorization denied" in finding["verification_reason"]
            assert _SQLiFixture.requests == 6

        asyncio.run(exercise())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_v2_validation_rechecks_scope_before_each_probe(tmp_path):
    _SQLiFixture.requests = 0
    _SQLiFixture.vulnerable = True
    server = HTTPServer(("127.0.0.1", 0), _SQLiFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/search?id=1"
    try:
        async def exercise():
            core = Core(tmp_path / "data")
            await core.initialize(drain=False)
            _SQLiFixture.scope_path = tmp_path / "data" / "scope.json"
            _SQLiFixture.revoke_after = 3
            scope_decisions = []
            original_check = core.scope.check_for_execution

            def track_scope_check(url):
                result = original_check(url)
                scope_decisions.append((url, result.allowed, tuple(core.scope._in)))
                return result

            core.scope.check_for_execution = track_scope_check
            provider = core.providers._routes[FindingVerificationProvider.VERIFY]
            assert provider.scope is core.scope
            assert core.scope.path == _SQLiFixture.scope_path
            source_job = await _seed_sealed_source(
                core, plan_id="source-plan", target=target,
            )
            _bound_plan(
                core, plan_id="scope-revocation-plan",
                capability_id=FindingVerificationProvider.VERIFY,
                target=target,
                inputs={"source_job_id": source_job, "finding_seq": 0},
            )
            result = await core.run_workflow_plan(
                "scope-revocation-plan", max_tasks=1, max_concurrency=1,
            )
            assert result["tasks"] == [{"id": "verification", "status": "succeeded"}]
            evidence = core.workflow_evidence("scope-revocation-plan")
            assert evidence["all_evidence_integrity_verified"] is True
            finding = evidence["attempts"][0]["findings"][0]
            assert finding["verification_status"] == "candidate", (
                _SQLiFixture.requests, str(core.scope.path),
                len(scope_decisions), scope_decisions[-1:] if scope_decisions else [],
            )
            assert "scope authorization denied" in finding["verification_reason"]
            assert _SQLiFixture.requests == 3

        asyncio.run(exercise())
    finally:
        _SQLiFixture.scope_path = None
        _SQLiFixture.revoke_after = None
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
