"""Engine V2 API uses the same persisted Core service as the headless CLI."""
from __future__ import annotations

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.web.server import AsyncRunner, JobRegistry, create_app


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    core = Core(data_dir=tmp_path)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    return app.test_client(), core


def test_v2_followups_api_is_evidence_bound_and_inert(tmp_path, monkeypatch):
    """API reuses the CLI/Core follow-up planner without independent execution."""
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m-followup", "authorized lab")
    core.save_workflow_plan("p-source", WorkflowPlan("m-followup", (
        WorkflowTask("scan", "tool.nmap", "192.0.2.10"),
    )))
    response = client.post(
        "/api/v2/workflows/p-source/followups",
        json={"max_tasks": 4, "save": True},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["source_plan_id"] == "p-source"
    assert body["plan"] is None
    assert body["created"] is False
    assert body["approval_granted"] is False
    assert body["execution_started"] is False
    assert core.mission_workflow_plans("m-followup")[0]["id"] == "p-source"
    assert len(core.mission_workflow_plans("m-followup")) == 1
    assert core.workflow_run_queue_summary()["counts"]["queued"] == 0

    for payload in (
        {"max_tasks": True}, {"max_tasks": 0}, {"max_tasks": 101},
        {"max_tasks": "4"}, {"save": "true"}, {"unknown": 1},
        [], "invalid",
    ):
        assert client.post(
            "/api/v2/workflows/p-source/followups", json=payload,
        ).status_code == 400
    assert client.post(
        "/api/v2/workflows/missing/followups", json={},
    ).status_code == 404
    assert client.post(
        "/api/v2/workflows/p-source/followups", json={},
        headers={"Origin": "https://attacker.invalid"},
    ).status_code == 403


def test_v2_workflow_proposal_api_is_inert_and_validates_contract(
    tmp_path, monkeypatch,
):
    from whaxon.core import workflow_proposals

    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m-proposal", "authorized lab")
    plan = WorkflowPlan("m-proposal", (
        WorkflowTask("scan", "tool.nmap", "192.0.2.10"),
    ))
    calls = []

    def propose_tool(_core, **kwargs):
        calls.append(("tool", kwargs))
        return {
            "status": "proposed", "plan": plan.to_dict(),
            "execution_submitted": False, "approval_granted": False,
        }

    def propose_verification(_core, **kwargs):
        calls.append(("verification", kwargs))
        return {
            "status": "proposed", "plan": plan.to_dict(),
            "execution_submitted": False, "approval_granted": False,
        }

    monkeypatch.setattr(workflow_proposals, "propose_tool_workflow_plan", propose_tool)
    monkeypatch.setattr(
        workflow_proposals, "propose_finding_verification_plan", propose_verification,
    )

    response = client.post("/api/v2/workflow-proposals", json={
        "kind": "tool", "mission_id": "m-proposal", "id": "p-proposed",
        "tool": "nmap", "target": "192.0.2.10",
    })
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "proposed"
    assert body["created"] is False
    assert body["approval_granted"] is False
    assert body["execution_submitted"] is False
    assert calls[-1] == ("tool", {
        "mission_id": "m-proposal", "plan_id": "p-proposed",
        "tool_id": "nmap", "target": "192.0.2.10",
    })
    assert core.workflow_run_queue_summary()["counts"]["queued"] == 0

    response = client.post("/api/v2/workflow-proposals", json={
        "kind": "verification", "mission_id": "m-proposal", "id": "p-verify",
        "source_job_id": "job-source", "finding_seq": 2, "mode": "retest",
        "save": True,
    })
    assert response.status_code == 200
    assert response.get_json()["created"] is True
    assert response.get_json()["execution_submitted"] is False
    assert response.get_json()["approval_granted"] is False
    assert calls[-1] == ("verification", {
        "mission_id": "m-proposal", "plan_id": "p-verify",
        "source_job_id": "job-source", "finding_seq": 2, "mode": "retest",
    })
    assert core.store.get_workflow_plan("p-verify")["digest"] == plan.digest
    assert core.workflow_approvals("p-verify") == []
    assert core.workflow_run_queue_summary()["counts"]["queued"] == 0

    invalid = (
        ([], "JSON object required"),
        ({"kind": "other"}, "kind must be tool or verification"),
        (
            {"kind": "tool", "mission_id": "m", "id": "p"},
            "tool proposal requires mission_id, id, tool and target",
        ),
        (
            {"kind": "tool", "mission_id": "m", "id": "p", "tool": "nmap",
             "target": "192.0.2.10", "extra": True},
            "tool proposal requires mission_id, id, tool and target",
        ),
        (
            {"kind": "tool", "mission_id": "m", "id": "p", "tool": "nmap",
             "target": "192.0.2.10", "save": "true"},
            "save must be a boolean",
        ),
        (
            {"kind": "verification", "mission_id": "m", "id": "p",
             "source_job_id": "job", "finding_seq": True, "mode": "verify"},
            "verification proposal requires mission_id, id, source_job_id, non-negative finding_seq and mode",
        ),
        (
            {"kind": "verification", "mission_id": "m", "id": "p",
             "source_job_id": "job", "finding_seq": 0, "mode": "execute"},
            "mode must be verify or retest",
        ),
    )
    for payload, expected_error in invalid:
        response = client.post("/api/v2/workflow-proposals", json=payload)
        assert response.status_code == 400
        assert response.get_json()["error"] == expected_error
    assert client.post(
        "/api/v2/workflow-proposals",
        json={"kind": "tool", "mission_id": "m", "id": "p", "tool": "nmap",
              "target": "192.0.2.10"},
        headers={"Origin": "https://attacker.invalid"},
    ).status_code == 403


def test_v2_followups_api_persists_only_a_reviewable_plan(tmp_path, monkeypatch):
    from whaxon.core.followups import FollowupProposal

    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("source", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    proposed_plan = WorkflowPlan("m", (
        WorkflowTask("followup", "fixture", "192.0.2.10"),
    ))

    def fake_compile(source_id, *, max_tasks):
        assert source_id == "source"
        assert max_tasks == 2
        return FollowupProposal(source_id, "followup-plan", proposed_plan, ())

    monkeypatch.setattr(core, "propose_workflow_followups", fake_compile)
    response = client.post(
        "/api/v2/workflows/source/followups",
        json={"max_tasks": 2, "save": True},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["created"] is True
    assert body["digest"] == proposed_plan.digest
    assert body["approval_granted"] is False
    assert body["execution_started"] is False
    assert core.store.get_workflow_plan("followup-plan")["digest"] == proposed_plan.digest
    assert core.workflow_approvals("followup-plan") == []
    assert core.workflow_run_queue_summary()["counts"]["queued"] == 0

    again = client.post(
        "/api/v2/workflows/source/followups",
        json={"max_tasks": 2, "save": True},
    )
    assert again.status_code == 200
    assert again.get_json()["created"] is False
    assert core.workflow_run_queue_summary()["counts"]["queued"] == 0


def test_v2_mission_report_api_uses_shared_evidence_and_preserves_partial_status(
    tmp_path, monkeypatch,
):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m-report", "authorized lab")
    core.save_workflow_plan("p-report", WorkflowPlan("m-report", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    expected = core.workflow_mission_report(
        "m-report", plan_ids=["p-report"], limit=10,
    )
    response = client.get("/api/v2/missions/m-report/report?plan_id=p-report&limit=10")
    assert response.status_code == 200
    assert response.get_json() == expected
    assert response.get_json()["status"] != "complete"
    assert client.get("/api/v2/missions/missing/report").status_code == 404

    for query in (
        "limit=0", "limit=1001", "limit=oops", "limit=-5",
        "plan_id=p-report&plan_id=p-report", "plan_id=other",
    ):
        assert client.get(
            "/api/v2/missions/m-report/report?" + query,
        ).status_code == 400
    assert client.post("/api/v2/missions/m-report/report").status_code == 405


def test_v2_report_and_audit_digest_api_match_shared_core(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m-audit", "controlled")
    core.save_workflow_plan("p-audit", WorkflowPlan("m-audit", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    report = client.get("/api/v2/workflows/p-audit/report?limit=10")
    assert report.status_code == 200
    assert report.get_json() == core.workflow_report("p-audit", limit=10)
    assert report.get_json()["status"] != "complete"

    snapshot = client.get("/api/v2/workflows/p-audit/audit-snapshot")
    assert snapshot.status_code == 200
    assert snapshot.get_json() == core.workflow_audit_snapshot("p-audit")
    digest = snapshot.get_json()["digest"]
    assert snapshot.get_json()["independent_anchor_verified"] is False
    verified = client.post(
        "/api/v2/workflows/p-audit/audit-verify",
        json={"expected_digest": digest},
    )
    assert verified.status_code == 200
    assert verified.get_json() == {
        "plan_id": "p-audit", "digest_matches": True,
        "independent_anchor_verified": False,
    }
    wrong = client.post(
        "/api/v2/workflows/p-audit/audit-verify",
        json={"expected_digest": "0" * 64 if digest != "0" * 64 else "f" * 64},
    )
    assert wrong.status_code == 200
    assert wrong.get_json()["digest_matches"] is False

    for value in ("0", "1001", "-1", "invalid", "9" * 5000):
        assert client.get(
            "/api/v2/workflows/p-audit/report", query_string={"limit": value},
        ).status_code == 400
    for payload in ({}, {"expected_digest": "bad"}, {"expected_digest": digest, "extra": 1}):
        assert client.post(
            "/api/v2/workflows/p-audit/audit-verify", json=payload,
        ).status_code == 400
    assert client.get("/api/v2/workflows/missing/report").status_code == 404
    assert client.get("/api/v2/workflows/missing/audit-snapshot").status_code == 404
    assert client.post(
        "/api/v2/workflows/p-audit/audit-verify",
        json={"expected_digest": digest},
        headers={"Origin": "https://attacker.invalid"},
    ).status_code == 403


def test_workflow_v2_read_only_routes_use_shared_persistence(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    assert client.get("/api/v2/missions").get_json()[0]["id"] == "m"
    assert client.get("/api/v2/missions/m/plans").get_json()[0]["id"] == "p"
    progress = client.get("/api/v2/workflows/p/progress")
    assert progress.status_code == 200
    assert progress.get_json()["total_tasks"] == 1
    assert client.get("/api/v2/workflows/p/events").get_json() == []
    readiness = client.get("/api/v2/workflows/p/readiness").get_json()
    assert readiness["ready_to_report_success"] is False
    assert client.get("/api/v2/workflows/p/reconciliation").get_json() == []


def test_workflow_v2_api_bounds_and_missing_plan(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    assert client.get("/api/v2/workflows/missing/progress").status_code == 404
    assert client.get("/api/v2/workflows/missing/readiness").status_code == 404
    assert client.get("/api/v2/workflows/missing/events?limit=0").status_code == 400
    assert client.get("/api/v2/missions?limit=0").status_code == 400


def test_workflow_v2_cancel_shares_persisted_stop_barrier(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    result = client.post("/api/v2/workflows/p/cancel")
    assert result.status_code == 200
    assert result.get_json()["cancellation_requested"] is True
    assert result.get_json()["external_effects_stopped"] is False
    assert core.store.claim_ready_workflow_task("p", "worker") is None
    assert client.post("/api/v2/workflows/p/cancel").get_json()["tasks_cancelled"] == 0


def test_workflow_v2_cancel_rejects_cross_origin(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/v2/workflows/p/cancel",
        headers={"Origin": "https://attacker.invalid"},
    )
    assert response.status_code == 403


def test_workflow_v2_diagnostics_routes_share_live_store(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    assert client.get("/api/v2/workflows/p/attempts").get_json() == []
    assert client.get("/api/v2/workflows/p/audit").get_json()["consistent"]
    resource = client.get("/api/v2/workflows/p/resources").get_json()
    assert resource["cost_usd"] is None
    assert client.get("/api/v2/workflows/p/limits").get_json()["limits"]["max_concurrency"] == 4
    assert client.get("/api/v2/workflows/p/attempts?limit=0").status_code == 400


def test_workflow_v2_control_routes_reject_invalid_budgets(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    assert client.post(
        "/api/v2/workflows/p/limits",
        json={"max_total_attempts": 3, "max_concurrency": 1},
    ).get_json()["limits"]["max_concurrency"] == 1
    assert client.post(
        "/api/v2/workflows/p/limits",
        json={"max_total_attempts": 4, "max_concurrency": 2},
    ).status_code == 400
    assert client.post(
        "/api/v2/workflows/p/limits", json={"max_total_attempts": -1},
    ).status_code == 400
    for value in (True, "2", 0):
        response = client.post(
            "/api/v2/workflows/p/limits",
            json={"max_total_attempts": value, "max_concurrency": 1},
        )
        assert response.status_code == 400
        assert response.get_json() == {
            "error": "workflow limits must be positive integers",
        }
    assert client.post(
        "/api/v2/workflows/p/deadline", json={"deadline_at": 1000000000.0},
    ).status_code == 200
    assert client.post(
        "/api/v2/workflows/p/deadline", json={"deadline_at": 2000000000.0},
    ).status_code == 400
    assert client.post(
        "/api/v2/workflows/p/rate-limit", json={"min_spacing_s": 5.0},
    ).status_code == 200
    assert client.post(
        "/api/v2/workflows/p/rate-limit", json={"min_spacing_s": 1.0},
    ).status_code == 400
    for value in (True, "2", 0):
        response = client.post(
            "/api/v2/workflows/p/rate-limit", json={"min_spacing_s": value},
        )
        assert response.status_code == 400
        assert response.get_json() == {
            "error": "min_spacing_s must be finite and positive",
        }
    assert client.post(
        "/api/v2/workflows/p/rate-limit", json=[],
    ).get_json() == {"error": "min_spacing_s required"}


def test_workflow_v2_control_routes_enforce_cross_origin_gate(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    for route in (
        "/api/v2/workflows/p/limits",
        "/api/v2/workflows/p/deadline",
        "/api/v2/workflows/p/rate-limit",
    ):
        assert client.post(route, headers={"Origin": "https://attacker.invalid"}).status_code == 403


def test_workflow_v2_mission_budget_is_shared_with_store(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    response = client.post("/api/v2/missions/m/budget", json={
        "max_total_attempts": 4, "max_concurrency": 2,
    })
    assert response.status_code == 200
    assert response.get_json()["max_total_attempts"] == 4
    assert core.store.get_mission_execution_limits("m")["max_concurrency"] == 2
    assert client.get("/api/v2/missions/m/budget").get_json()["enforced"] is True
    assert client.post("/api/v2/missions/m/budget", json={
        "max_total_attempts": 5, "max_concurrency": 2,
    }).status_code == 400
    response = client.post("/api/v2/missions/m/budget", json={
        "max_total_attempts": True, "max_concurrency": 1,
    })
    assert response.status_code == 400
    assert response.get_json() == {"error": "mission limits must be positive integers"}
    assert client.get("/api/v2/missions/missing/budget").status_code == 404


def test_mission_deadline_api_blocks_later_claims(tmp_path, monkeypatch):
    import time

    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.1"),
    )))
    response = client.post(
        "/api/v2/missions/m/deadline", json={"deadline_at": time.time() - 1},
    )
    assert response.status_code == 200
    assert response.get_json()["deadline_at"] <= time.time()
    assert core.store.get_mission_deadline("m") == response.get_json()["deadline_at"]
    assert core.store.claim_ready_workflow_task("p", "worker") is None
    assert client.post(
        "/api/v2/missions/m/deadline", json={"deadline_at": time.time() + 100},
    ).status_code == 400
    for value in (True, "123", 0):
        response = client.post(
            "/api/v2/missions/m/deadline", json={"deadline_at": value},
        )
        assert response.status_code == 400
        assert response.get_json() == {
            "error": "mission deadline_at must be a finite positive unix timestamp",
        }


def test_mission_cost_api_requires_explicit_cost_evidence(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    response = client.post("/api/v2/missions/m/cost", json={"max_cost_microusd": 100})
    assert response.status_code == 200
    assert response.get_json()["cap_microusd"] == 100
    assert client.get("/api/v2/missions/m/cost").get_json()["reported_attempts"] == 0
    for value in (True, "100", -1):
        response = client.post(
            "/api/v2/missions/m/cost", json={"max_cost_microusd": value},
        )
        assert response.status_code == 400
        assert response.get_json() == {
            "error": "max_cost_microusd must be a nonnegative integer",
        }
    assert client.post(
        "/api/v2/workflows/attempts/unknown/cost",
        json={"cost_microusd": 3, "source": "invoice"},
    ).status_code == 400


def test_v2_api_creates_mission_and_persists_plan_using_core(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    created = client.post("/api/v2/missions", json={"id": "m", "objective": "controlled"})
    assert created.status_code == 201
    assert created.get_json()["created"] is True
    plan = WorkflowPlan("m", (WorkflowTask("scan", "fixture", "192.0.2.10"),))
    saved = client.post("/api/v2/workflows", json={"id": "p", "plan": plan.to_dict()})
    assert saved.status_code == 201
    assert saved.get_json()["digest"] == plan.digest
    assert core.store.get_workflow_plan("p")["digest"] == plan.digest
    detail = client.get("/api/v2/workflows/p")
    assert detail.status_code == 200
    assert detail.get_json()["plan"]["mission_id"] == "m"
    assert len(detail.get_json()["tasks"]) == 1
    assert client.get("/api/v2/workflows/unknown").status_code == 404
    assert client.post("/api/v2/workflows", json={"id": "bad", "plan": {}}).status_code == 400
    assert client.post("/api/v2/missions", json={"id": 1, "objective": "x"}).status_code == 400


def test_v2_api_mission_rate_limit_shared_and_fail_closed(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("p1", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    core.save_workflow_plan("p2", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.11"),
    )))
    response = client.post("/api/v2/missions/m/rate-limit", json={"min_spacing_s": 3600})
    assert response.status_code == 200
    assert response.get_json()["min_spacing_s"] == 3600
    assert core.store.claim_ready_workflow_task("p1", "worker-1") is not None
    assert core.store.claim_ready_workflow_task("p2", "worker-2") is None
    assert client.get("/api/v2/missions/m/rate-limit").get_json()["last_claimed_at"] is not None
    assert client.post("/api/v2/missions/m/rate-limit", json={"min_spacing_s": 1}).status_code == 400
    assert client.get("/api/v2/missions/unknown/rate-limit").status_code == 404
    assert client.post(
        "/api/v2/missions/m/rate-limit", json={"min_spacing_s": 7200},
        headers={"Origin": "https://attacker.invalid"},
    ).status_code == 403
    assert client.post(
        "/api/v2/workflows", json={"id": "evil", "plan": {}},
        headers={"Origin": "https://attacker.invalid"},
    ).status_code == 403


def test_v2_api_run_submits_bounded_core_execution_without_claiming_success(
    tmp_path, monkeypatch,
):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    captured = []
    monkeypatch.setattr(
        "whaxon.interfaces.web.server.AsyncRunner.submit",
        lambda self, factory: captured.append(factory),
    )
    response = client.post(
        "/api/v2/workflows/p/run",
        json={"max_tasks": 1, "max_attempts": 1, "max_concurrency": 1},
    )
    assert response.status_code == 202
    assert response.get_json()["execution_submitted"] is True
    assert response.get_json()["execution_completed"] is False
    assert response.get_json()["durable_progress_url"] == "/api/v2/workflows/p/progress"
    assert len(captured) == 1
    assert core.workflow_progress("p")["total_tasks"] == 1
    assert client.post("/api/v2/workflows/missing/run", json={}).status_code == 404
    for value in (True, 0, -1, "1", 1.5):
        assert client.post(
            "/api/v2/workflows/p/run", json={"max_tasks": value},
        ).status_code == 400
    assert len(captured) == 1
    assert client.post(
        "/api/v2/workflows/p/run", json={},
        headers={"Origin": "https://attacker.invalid"},
    ).status_code == 403
    assert len(captured) == 1


def test_v2_api_approval_and_reconciliation_parity(tmp_path, monkeypatch):
    import time

    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10", impact="moderate"),
    )))
    assert client.post("/api/v2/workflows/p/approvals", json={
        "task_key": "scan", "approval_id": "approval-1",
        "actor": "forged-operator", "expires_at": time.time() + 300,
    }).status_code == 200
    approval = client.get("/api/v2/workflows/p/approvals").get_json()[0]
    assert len(client.get("/api/v2/workflows/p/approvals").get_json()) == 1
    assert approval["actor"] == "local"
    assert client.post(
        "/api/v2/workflows/p/approvals/approval-1/revoke",
        json={"actor": "forged-revoker"},
    ).status_code == 200
    revoked = [
        event for event in core.workflow_events("p")
        if event["event_type"] == "approval_revoked"
    ]
    assert len(revoked) == 1
    assert revoked[0]["detail"]["actor"] == "local"
    assert client.post(
        "/api/v2/workflows/p/reconcile", json={"stale_after_s": 60},
    ).status_code == 200
    assert client.post(
        "/api/v2/workflows/p/approvals", json={"task_key": "scan"},
    ).status_code == 400
    for value in (True, "later", float("inf")):
        response = client.post("/api/v2/workflows/p/approvals", json={
            "task_key": "scan", "approval_id": "approval-invalid",
            "expires_at": value,
        })
        assert response.status_code == 400
        assert response.get_json() == {
            "error": "approval expiry must be finite and in the future",
        }
    assert client.post(
        "/api/v2/workflows/p/reconcile", json={"stale_after_s": True},
    ).get_json() == {"error": "stale_after_s must be positive and finite"}
    invalid_reconciliation = client.post(
        "/api/v2/workflows/p/reconcile", json={
            "attempt_id": 1, "disposition": "unresolved",
            "evidence_ref": "evidence-1", "note": "operator reviewed",
        },
    )
    assert invalid_reconciliation.status_code == 400
    assert invalid_reconciliation.get_json() == {
        "error": "unknown workflow attempt for this plan",
    }
    assert client.post(
        "/api/v2/workflows/p/approvals", json={},
        headers={"Origin": "https://attacker.invalid"},
    ).status_code == 403


def test_v2_api_event_consumer_parity_and_validation(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    assert client.get("/api/v2/workflows/p/event-inbox").status_code == 400
    assert client.get(
        "/api/v2/workflows/p/event-inbox?consumer=worker",
    ).status_code == 200
    assert client.post(
        "/api/v2/workflows/p/event-ack", json={"consumer": "worker", "event_id": True},
    ).status_code == 400
    assert client.post(
        "/api/v2/workflows/p/event-ack", json={"consumer": "worker", "event_id": 0},
    ).status_code in (200, 400)
    assert client.post(
        "/api/v2/workflows/p/event-ack", json={"consumer": "worker", "event_id": 1},
        headers={"Origin": "https://attacker.invalid"},
    ).status_code == 403


def test_v2_api_mission_deadline_returns_persisted_cutoff_not_budget(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    response = client.post("/api/v2/missions/m/deadline", json={
        "deadline_at": 2000000000,
    })
    assert response.status_code == 200
    assert response.get_json() == {"mission_id": "m", "deadline_at": 2000000000}
    assert core.store.get_mission_deadline("m") == 2000000000
    assert client.post(
        "/api/v2/missions/m/deadline", json={"deadline_at": 2100000000},
    ).status_code == 400
    assert client.post(
        "/api/v2/missions/unknown/deadline", json={"deadline_at": 2000000000},
    ).status_code == 404


def test_v2_evidence_api_links_actual_job_and_never_fabricates_findings(tmp_path, monkeypatch):
    """An accepted workflow outcome is not automatically proof of scan evidence."""
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m-evidence", "authorized lab")
    core.save_workflow_plan("p-evidence", WorkflowPlan("m-evidence", (
        WorkflowTask("scan", "tool.nmap", "192.0.2.10"),
    )))
    empty = client.get("/api/v2/workflows/p-evidence/evidence")
    assert empty.status_code == 200
    assert empty.get_json()["all_evidence_recorded"] is False
    assert empty.get_json()["attempts"] == []

    attempt = core.store.claim_ready_workflow_task("p-evidence", "fixture-worker")
    assert attempt is not None
    core.store.finish_task_attempt(
        attempt["attempt_id"], "succeeded",
        result={"job_id": "job-1", "tool_id": "nmap", "target": "192.0.2.10"},
    )
    missing = client.get("/api/v2/workflows/p-evidence/evidence").get_json()
    assert missing["attempts"][0]["evidence_status"] == "job_not_verified"
    assert missing["all_evidence_recorded"] is False

    # Insert a real persisted legacy job and normalized finding, as the
    # existing ToolRunner event handlers would do after a successful scan.
    with core.store._conn() as connection:
        connection.execute(
            "INSERT INTO jobs (id, tool, target, status, exit_code) "
            "VALUES (?, ?, ?, ?, ?)",
            ("job-1", "nmap", "192.0.2.10", "finished", 0),
        )
        connection.execute(
            "INSERT INTO findings (job_id, seq, kind, severity, source, "
            "data_json, raw_line, verification_status, verification_reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("job-1", 0, "open_port", "info", "nmap",
             '{"port": 80}', "80/tcp open http", "candidate", "not independently verified"),
        )
    recorded = client.get("/api/v2/workflows/p-evidence/evidence").get_json()
    assert recorded["plan_digest"] == core.store.get_workflow_plan("p-evidence")["digest"]
    assert recorded["all_evidence_recorded"] is True
    assert recorded["attempts"][0]["finding_count"] == 1
    assert recorded["attempts"][0]["findings"][0]["verification_status"] == "candidate"
    assert recorded["attempts"][0]["findings"][0]["raw_line"] == "80/tcp open http"

    # Contradictory target identity invalidates the evidence linkage.
    with core.store._conn() as connection:
        connection.execute("UPDATE jobs SET target=? WHERE id=?", ("192.0.2.99", "job-1"))
    mismatch = client.get("/api/v2/workflows/p-evidence/evidence").get_json()
    assert mismatch["all_evidence_recorded"] is False
    assert mismatch["attempts"][0]["evidence_status"] == "job_not_verified"
    assert mismatch["attempts"][0]["findings"] == []


def test_v2_evidence_api_rejects_bad_bounds_and_unknown_plans(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    assert client.get("/api/v2/workflows/missing/evidence").status_code == 404
    core.create_mission("m", "authorized")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "tool.nmap", "192.0.2.10"),
    )))
    for limit in ("0", "-1", "1001", "invalid"):
        assert client.get(f"/api/v2/workflows/p/evidence?limit={limit}").status_code == 400


def test_v2_evidence_seal_survives_restart_and_rejects_modified_findings(tmp_path, monkeypatch):
    """Terminal job evidence is sealed atomically, then checked across Core restarts."""
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m-sealed", "authorized test")
    core.save_workflow_plan("p-sealed", WorkflowPlan("m-sealed", (
        WorkflowTask("scan", "tool.nmap", "192.0.2.44"),
    )))
    attempt = core.store.claim_ready_workflow_task("p-sealed", "operator")
    assert attempt is not None
    with core.store._conn() as connection:
        connection.execute(
            "INSERT INTO jobs (id, tool, target, status, exit_code) "
            "VALUES (?, ?, ?, ?, ?)",
            ("job-sealed", "nmap", "192.0.2.44", "finished", 0),
        )
        connection.execute(
            "INSERT INTO lines (job_id, seq, stream, text) VALUES (?, ?, ?, ?)",
            ("job-sealed", 0, "stdout", "80/tcp open http"),
        )
        connection.execute(
            "INSERT INTO findings (job_id, seq, kind, severity, source, "
            "data_json, raw_line, verification_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("job-sealed", 0, "open_port", "info", "nmap",
             '{"port": 80}', "80/tcp open http", "candidate"),
        )
    core.store.finish_task_attempt(
        attempt["attempt_id"], "succeeded",
        result={"job_id": "job-sealed", "tool_id": "nmap", "target": "192.0.2.44"},
    )
    verified = client.get("/api/v2/workflows/p-sealed/evidence").get_json()
    assert verified["all_evidence_recorded"] is True
    assert verified["all_evidence_integrity_verified"] is True
    assert verified["attempts"][0]["integrity_status"] == "verified"

    reopened = Core(data_dir=tmp_path)
    assert reopened.workflow_evidence("p-sealed")["all_evidence_integrity_verified"] is True
    with reopened.store._conn() as connection:
        connection.execute(
            "UPDATE findings SET raw_line=? WHERE job_id=? AND seq=0",
            ("80/tcp filtered", "job-sealed"),
        )
    changed = client.get("/api/v2/workflows/p-sealed/evidence").get_json()
    assert changed["all_evidence_recorded"] is False
    assert changed["all_evidence_integrity_verified"] is False
    assert changed["attempts"][0]["evidence_status"] == "integrity_mismatch"
    assert changed["attempts"][0]["integrity_status"] == "changed"
    assert changed["attempts"][0]["findings"] == []


def test_v2_evidence_cannot_seal_wrong_tool_or_wrong_target(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "authorized")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "tool.nmap", "192.0.2.10"),
    )))
    attempt = core.store.claim_ready_workflow_task("p", "worker")
    assert attempt is not None
    with core.store._conn() as connection:
        connection.execute(
            "INSERT INTO jobs (id, tool, target, status, exit_code) "
            "VALUES (?, ?, ?, ?, ?)",
            ("wrong-tool", "nikto", "192.0.2.10", "finished", 0),
        )
    core.store.finish_task_attempt(
        attempt["attempt_id"], "succeeded",
        result={"job_id": "wrong-tool", "tool_id": "nmap", "target": "192.0.2.10"},
    )
    result = client.get("/api/v2/workflows/p/evidence").get_json()
    assert result["all_evidence_integrity_verified"] is False
    assert result["attempts"][0]["integrity_status"] == "unsealed"
    with core.store._conn() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM workflow_evidence_seals"
        ).fetchone()[0] == 0

def test_provider_and_capability_api_share_core_inventory(tmp_path, monkeypatch):
    client, core = _client(tmp_path, monkeypatch)
    response = client.get("/api/v2/providers")
    assert response.status_code == 200
    assert response.get_json() == core.capability_inventory()
    manifests = client.get("/api/v2/capabilities")
    assert manifests.status_code == 200
    assert manifests.get_json() == [item.to_dict() for item in core.capabilities.list()]
    assert all("readiness" in item for item in response.get_json())



def test_e4_portfolio_audit_matches_cli_and_api(tmp_path, monkeypatch, capsys):
    """Read-only registry reconciliation has one contract across clients."""
    import json

    from whaxon.interfaces.cli.workflow_cmd import main as workflow_main

    client, core = _client(tmp_path, monkeypatch)
    api_response = client.get("/api/v2/providers/portfolio-audit")
    assert api_response.status_code == 200
    api_report = api_response.get_json()
    assert api_report["schema_version"] == "whaxon.portfolio-audit.v1"
    assert api_report["execution_enabled_by_audit"] is False
    assert core.capability_portfolio_audit() == api_report

    assert workflow_main(["--data-dir", str(tmp_path), "portfolio-audit"]) == 0
    cli_report = json.loads(capsys.readouterr().out)
    assert cli_report == api_report
    assert sum(cli_report["summary"].values()) == len(cli_report["rows"])
    assert client.post("/api/v2/providers/portfolio-audit").status_code == 405



def test_workflow_v2_api_records_manual_provider_effect_reconciliation(
    tmp_path, monkeypatch,
):
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled reconciliation")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10"),
    )))
    request = core.enqueue_workflow_run("p")
    run_claim = core.workflow_requests.claim("run-worker")
    task_claim = core.store.claim_ready_workflow_task(
        "p", "task-worker", max_attempts=2,
    )
    assert task_claim is not None
    attempt_id = task_claim["attempt_id"]
    assert core.store.mark_workflow_dispatch_started("p", attempt_id)
    core.store.finish_task_attempt(attempt_id, "uncertain", error="lost")
    assert core.workflow_requests.finish(
        request["id"], run_claim["lease_token"], status="uncertain",
    )

    response = client.post("/api/v2/workflows/p/reconcile", json={
        "attempt_id": attempt_id,
        "disposition": "no_effect_verified",
        "actor": "forged-operator",
        "evidence_ref": "case://api/17",
        "note": "Compared provider audit log to target capture.",
    })
    assert response.status_code == 200
    result = response.get_json()
    assert result["task_retryable"] is True
    assert result["automatic_replay"] is False
    assert result["run_requests_closed"] == 1
    assert result["actor_claimed"] == "local"
    conn = core.store._conn()
    try:
        assert conn.execute(
            "SELECT actor FROM workflow_attempt_reconciliations WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()["actor"] == "local"
    finally:
        conn.close()

    malformed = client.post("/api/v2/workflows/p/reconcile", json={
        "attempt_id": attempt_id, "disposition": "success",
    })
    assert malformed.status_code == 400


def test_v2_remote_workflow_approval_actor_uses_authenticated_username(
    tmp_path, monkeypatch,
):
    import base64
    import time

    from whaxon.interfaces.web.server import _hash_pw

    monkeypatch.setenv("WHAXON_AUTH_USER", "auditor-7")
    monkeypatch.setenv("WHAXON_AUTH_PASS_HASH", _hash_pw("correct-horse"))
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m", "controlled")
    core.save_workflow_plan("p", WorkflowPlan("m", (
        WorkflowTask("scan", "fixture", "192.0.2.10", impact="moderate"),
    )))
    authorization = "Basic " + base64.b64encode(
        b"auditor-7:correct-horse",
    ).decode("ascii")
    response = client.post(
        "/api/v2/workflows/p/approvals",
        json={
            "task_key": "scan", "approval_id": "remote-approval",
            "actor": "forged-admin", "expires_at": time.time() + 300,
        },
        headers={"Authorization": authorization},
        environ_base={"REMOTE_ADDR": "198.51.100.7"},
    )
    assert response.status_code == 200
    approval = client.get(
        "/api/v2/workflows/p/approvals",
        headers={"Authorization": authorization},
        environ_base={"REMOTE_ADDR": "198.51.100.7"},
    ).get_json()[0]
    assert approval["actor"] == "auditor-7"


def test_v2_ai_proposals_api_validates_and_never_submits_execution(tmp_path, monkeypatch):
    """The AI handoff is a proposal endpoint, not a second execution owner."""
    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m-ai", "authorized proposal")
    calls = []

    def fake_propose(received_core, **kwargs):
        assert received_core is core
        calls.append(kwargs)
        return {
            "status": "blocked", "reason": "provider unavailable",
            "approval_granted": False, "execution_submitted": False,
        }

    monkeypatch.setattr("whaxon.core.ai_bridge.propose_v2_workflow_plan", fake_propose)
    payload = {
        "mission_id": "m-ai", "id": "p-ai",
        "goal": "inspect authorized lab", "target": "192.0.2.10",
    }
    response = client.post("/api/v2/ai/proposals", json=payload)
    assert response.status_code == 200
    assert response.get_json()["status"] == "blocked"
    assert response.get_json()["approval_granted"] is False
    assert response.get_json()["execution_submitted"] is False
    assert response.get_json()["created"] is False
    assert len(calls) == 1
    assert core.store.get_workflow_plan("p-ai") is None

    for invalid in (
        {**payload, "save": "yes"},
        {**payload, "target": ""},
        {**payload, "goal": "x" * 10001},
    ):
        response = client.post("/api/v2/ai/proposals", json=invalid)
        assert response.status_code == 400
    assert client.post(
        "/api/v2/ai/proposals", json=payload,
        headers={"Origin": "https://attacker.invalid"},
    ).status_code == 403
    assert core.store.get_workflow_plan("p-ai") is None


def test_v2_ai_proposal_rejects_oversized_history_before_provider(tmp_path, monkeypatch):
    from whaxon.core.ai_bridge import propose_v2_workflow_plan

    client, core = _client(tmp_path, monkeypatch)
    core.create_mission("m-ai", "authorized proposal")
    for history in ([{}] * 33, [{"untrusted": "x" * 4097}]):
        try:
            propose_v2_workflow_plan(
                core, mission_id="m-ai", plan_id="p-ai",
                goal="inspect lab", target="192.0.2.10",
                history=history, step=len(history) + 1,
            )
        except ValueError as exc:
            assert "history exceeds allowed limits" in str(exc)
        else:
            raise AssertionError("oversized AI history accepted")
        response = client.post("/api/v2/ai/proposals", json={
            "mission_id": "m-ai", "id": "p-ai", "goal": "inspect lab",
            "target": "192.0.2.10", "history": history,
            "step": len(history) + 1,
        })
        assert response.status_code == 400
        assert "history exceeds allowed limits" in response.get_json()["error"]
    assert core.store.get_workflow_plan("p-ai") is None


def test_legacy_validation_routes_refuse_engine_v2_evidence(tmp_path, monkeypatch):
    from whaxon.core.findings import Finding

    monkeypatch.setenv("WHAXON_LEGACY_VALIDATION_ENABLED", "true")
    client, core = _client(tmp_path, monkeypatch)
    job_id = "0123456789ab"
    core.store.create(job_id)
    core.store.set_started(job_id, "verify_sqli", "http://192.0.2.10/search?id=1")
    core.store.append_finding(job_id, Finding(
        kind="sqli", severity="high", source="engine-v2-verifier",
        data={"parameter": "id"}, raw_line="verified finding",
    ), 0)
    core.store.update_verification(job_id, 0, "verified", by="engine-v2", reason="sealed result")
    core.store.mark_engine_v2_execution_job(job_id)

    before = core.store.get_findings(job_id)
    validate = client.post(f"/api/validate/{job_id}/0")
    retest = client.post(f"/api/retest/{job_id}/0")

    assert validate.status_code == 409
    assert retest.status_code == 409
    assert "plan-bound" in validate.get_json()["error"]
    assert "plan-bound" in retest.get_json()["error"]
    assert core.store.get_findings(job_id) == before
