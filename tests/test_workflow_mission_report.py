from __future__ import annotations

import json

import pytest

from whaxon.core import Core

_PLAN_STAGES = ("recon", "enumeration", "initial_access", "verification", "retest")
_STAGES = ("scope", "recon", "enumeration", "initial_access", "verification", "report", "retest")


def _core_for(stages, *, statuses=None):
    core = Core.__new__(Core)
    rows = [{"id": f"plan-{i}", "created_at": i} for i, _ in enumerate(stages)]
    capabilities = {
        "recon": "tool.nmap", "enumeration": "tool.gobuster",
        "initial_access": "lab.initial_access.samba_usermap",
        "verification": "tool.verify_sqli", "retest": "tool.retest_sqli",
    }
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    metadata = {}
    for i, stage in enumerate(stages):
        plan = WorkflowPlan(
            mission_id="mission-1", metadata={"release_stage": stage},
            tasks=(WorkflowTask(
                id=f"task-{i}", capability_id=capabilities[stage], target="127.0.0.1",
            ),),
        )
        metadata[f"plan-{i}"] = plan.to_dict()
    core.mission_workflow_plans = lambda mission_id: rows
    core.workflow_plan_details = lambda plan_id: {"plan": metadata[plan_id]}
    core.authorize_workflow_task_for_plan = lambda plan_id, task: True
    def report(plan_id, limit=100):
        stage = metadata[plan_id]["metadata"]["release_stage"]
        finding = (
            {"kind": "msf_session"} if stage == "initial_access"
            else {"kind": "sqli", "source": "engine-v2-verifier"}
            if stage in {"verification", "retest"}
            else {"kind": "open_port"}
        )
        return {
            "status": (statuses or {}).get(plan_id, "complete"),
            "plan_id": plan_id,
            "evidence": {
                "all_evidence_recorded": True,
                "all_evidence_integrity_verified": True,
                "attempts": [{
                    "capability_id": capabilities[stage],
                    "job_id": f"job-{int(plan_id.split('-')[1])}",
                    "evidence_status": "recorded", "integrity_status": "verified",
                }],
            },
            "readiness": {"ready_to_report_success": True},
            "truncated": False,
            "findings": [finding],
        }

    core.workflow_report = report
    class _Store:
        def get_findings(self, job_id):
            if job_id == "job-3":
                return [{
                    "kind": "sqli", "source": "engine-v2-verifier",
                    "verification_status": "verified", "verified_by": "engine-v2",
                    "data": {
                        "operation": "tool.verify_sqli", "status": "verified",
                        "source_job_id": "source-job", "source_finding_seq": 0,
                    },
                }]
            if job_id == "job-4":
                return [{
                    "kind": "sqli", "source": "engine-v2-verifier",
                    "verification_status": "still_vulnerable", "verified_by": "engine-v2",
                    "data": {
                        "operation": "tool.retest_sqli", "status": "still_vulnerable",
                        "source_job_id": "job-3", "source_finding_seq": 0,
                    },
                }]
            return []

    core.store = _Store()
    return core


def test_mission_report_requires_every_stage_in_order():
    core = _core_for(_PLAN_STAGES)
    report = Core.workflow_mission_report(core, "mission-1")
    assert report["status"] == "complete"
    assert report["stage_order_valid"] is True
    assert report["missing_stages"] == []
    assert [stage["stage"] for stage in report["stages"]] == list(_STAGES)
    assert report["stages"][0]["status"] == "complete"
    assert report["stages"][0]["plan_evidence"][0]["plan_bound_authorization"] is True
    assert report["stages"][-2]["source"] == "this mission aggregate"
    assert report["target_binding"] == {
        "status": "complete", "target": "127.0.0.1", "mismatched_plans": [],
        "rule": "every task in every plan must resolve to the same single target",
    }


def test_mission_report_rejects_cross_target_stage_chains():
    core = _core_for(_PLAN_STAGES)
    original = core.workflow_plan_details

    def other_target(plan_id):
        details = original(plan_id)
        if plan_id == "plan-3":
            details["plan"]["tasks"][0]["target"] = "127.0.0.2"
        return details

    core.workflow_plan_details = other_target
    report = Core.workflow_mission_report(core, "mission-1")
    assert report["status"] == "partial"
    assert report["target_binding"]["status"] == "partial"
    assert report["target_binding"]["target"] == "127.0.0.1"
    assert report["target_binding"]["mismatched_plans"] == [
        {"plan_id": "plan-3", "targets": ["127.0.0.2"]},
    ]


def test_mission_report_normalizes_url_and_ip_to_the_same_target():
    core = _core_for(_PLAN_STAGES)
    original = core.workflow_plan_details

    def target_url(plan_id):
        details = original(plan_id)
        if plan_id == "plan-1":
            details["plan"]["tasks"][0]["target"] = "http://127.0.0.1:8080/search?id=1"
        return details

    core.workflow_plan_details = target_url
    report = Core.workflow_mission_report(core, "mission-1")
    assert report["status"] == "complete"
    assert report["target_binding"]["target"] == "127.0.0.1"


def test_mission_report_rejects_out_of_order_or_missing_stage():
    reordered = _core_for(("recon", "initial_access", "enumeration", "verification", "retest"))
    report = Core.workflow_mission_report(reordered, "mission-1")
    assert report["status"] == "partial"
    assert report["stage_order_valid"] is False

    missing = _core_for(("recon", "enumeration", "verification", "retest"))
    report = Core.workflow_mission_report(missing, "mission-1")
    assert report["status"] == "partial"
    assert report["missing_stages"] == ["initial_access"]


def test_mission_report_fails_closed_when_scope_or_readiness_is_not_proven():
    core = _core_for(_PLAN_STAGES)
    core.authorize_workflow_task_for_plan = lambda plan_id, task: False
    report = Core.workflow_mission_report(core, "mission-1")
    assert report["status"] == "partial"
    assert report["stages"][0]["status"] == "partial"

    core = _core_for(_PLAN_STAGES)
    original = core.workflow_report
    def not_ready(plan_id, limit=100):
        value = original(plan_id, limit)
        value["readiness"]["ready_to_report_success"] = False
        return value
    core.workflow_report = not_ready
    assert Core.workflow_mission_report(core, "mission-1")["status"] == "partial"


@pytest.mark.parametrize(
    ("field", "value"),
    [("integrity_status", "unverified"), ("evidence_status", "pending")],
)
def test_mission_report_requires_exact_sealed_attempts(field, value):
    core = _core_for(_PLAN_STAGES)
    original = core.workflow_report

    def with_bad_seal(plan_id, limit=100):
        report = original(plan_id, limit)
        report["evidence"]["attempts"][0][field] = value
        return report

    core.workflow_report = with_bad_seal
    result = Core.workflow_mission_report(core, "mission-1")
    assert result["status"] == "partial"
    assert result["stages"][0]["status"] == "partial"


def test_mission_report_requires_each_plan_report_complete():
    core = _core_for(_PLAN_STAGES, statuses={"plan-2": "partial"})
    assert Core.workflow_mission_report(core, "mission-1")["status"] == "partial"


def test_mission_report_rejects_arbitrary_or_duplicate_plan_ids():
    core = _core_for(_PLAN_STAGES)
    with pytest.raises(ValueError, match="belong to the named mission"):
        Core.workflow_mission_report(core, "mission-1", plan_ids=["arbitrary-job"])
    with pytest.raises(ValueError, match="unique plan IDs"):
        Core.workflow_mission_report(core, "mission-1", plan_ids=["plan-0", "plan-0"])


def test_mission_report_cli_prints_json_and_nonzero_for_partial(monkeypatch, capsys):
    from whaxon.interfaces.cli import workflow_cmd

    class FakeCore:
        def __init__(self, data_dir):
            pass

        def workflow_mission_report(self, mission_id, *, plan_ids, limit):
            assert (mission_id, plan_ids, limit) == (
                "mission-1", ["plan-0", "plan-1"], 20,
            )
            return {"mission_id": mission_id, "status": "partial", "stages": []}

    monkeypatch.setattr(workflow_cmd, "Core", FakeCore)
    result = workflow_cmd.main([
        "--data-dir", ".", "mission", "report", "--id", "mission-1",
        "--plan-id", "plan-0", "--plan-id", "plan-1", "--limit", "20",
    ])
    assert result == 1
    assert json.loads(capsys.readouterr().out)["status"] == "partial"
