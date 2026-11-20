from __future__ import annotations

from whaxon.core import workflow_proposals
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


class _Store:
    def get_mission(self, mission_id):
        return {"id": mission_id}


class _Core:
    store = _Store()


def _proposal(mission_id, check):
    task = WorkflowTask(
        id="task-1", capability_id=f"recon.{check}", target="example.test",
        inputs={}, permissions=("network.scan",), impact="moderate",
        timeout_s=30, idempotency_key=f"{check}-key",
    )
    plan = WorkflowPlan(
        mission_id=mission_id,
        tasks=(task,),
        metadata={"provider_bindings": {"task-1": {
            "provider_id": f"provider.{check}",
            "manifest_fingerprint": "a" * 64,
        }}},
    )
    return {"status": "proposed", "plan": plan.to_dict()}


def test_default_recon_proposal_combines_ready_providers_and_lists_omissions(monkeypatch):
    builders = (
        "propose_passive_dns_plan",
        "propose_dns_full_posture_plan",
        "propose_tls_certificate_plan",
        "propose_passive_https_recon_plan",
        "propose_passive_headers_recon_plan",
        "propose_passive_redirect_observation_plan",
        "propose_passive_robots_recon_plan",
        "propose_passive_security_txt_recon_plan",
    )
    for name in builders:
        check = {
            "propose_passive_dns_plan": "dns",
            "propose_dns_full_posture_plan": "dns_full",
            "propose_tls_certificate_plan": "ssl",
            "propose_passive_https_recon_plan": "https",
            "propose_passive_headers_recon_plan": "headers",
            "propose_passive_redirect_observation_plan": "redirects",
            "propose_passive_robots_recon_plan": "robots",
            "propose_passive_security_txt_recon_plan": "security_txt",
        }[name]
        monkeypatch.setattr(
            workflow_proposals, name,
            lambda _core, *, mission_id, plan_id, target, check=check:
                _proposal(mission_id, check),
        )

    result = workflow_proposals.propose_passive_recon_plan(
        _Core(), mission_id="mission-1", plan_id="recon-1", target="example.test",
    )

    assert result["status"] == "proposed"
    assert result["execution_submitted"] is False
    assert result["approval_granted"] is False
    assert result["included_checks"] == [
        "dns", "dns_full", "ssl", "https", "headers", "redirects", "robots", "security_txt",
    ]
    assert [task["id"] for task in result["plan"]["tasks"]] == [
        "task-dns", "task-dns_full", "task-ssl", "task-https", "task-headers",
        "task-redirects", "task-robots", "task-security_txt",
    ]
    assert set(result["plan"]["metadata"]["provider_bindings"]) == {
        task["id"] for task in result["plan"]["tasks"]
    }
    assert [item["check"] for item in result["omitted_checks"]] == [
        "tech", "cookies", "waf",
    ]


def test_explicit_legacy_only_check_blocks_entire_proposal():
    result = workflow_proposals.propose_passive_recon_plan(
        _Core(), mission_id="mission-1", plan_id="recon-1",
        target="example.test", checks=["dns", "cookies"],
    )

    assert result["status"] == "blocked"
    assert "cookies" in result["reason"]
    assert result["execution_submitted"] is False


def test_explicit_unavailable_check_does_not_create_partial_plan(monkeypatch):
    monkeypatch.setattr(
        workflow_proposals, "propose_passive_dns_plan",
        lambda *_args, **_kwargs: {"status": "blocked", "reason": "provider is not ready"},
    )

    result = workflow_proposals.propose_passive_recon_plan(
        _Core(), mission_id="mission-1", plan_id="recon-1",
        target="example.test", checks=["dns"],
    )

    assert result["status"] == "blocked"
    assert "provider is not ready" in result["reason"]
    assert "plan" not in result
