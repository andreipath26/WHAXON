"""Transport-neutral, no-key AI advisory ledger: identity, lifecycle, no execution."""
from __future__ import annotations

import time

import pytest

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


@pytest.fixture
def core(tmp_path):
    instance = Core(tmp_path)
    instance.create_mission("mission", "local advisory fixture")
    instance.save_workflow_plan("plan", WorkflowPlan(
        "mission", (WorkflowTask("scan", "fixture", "192.0.2.10"),),
    ))
    return instance


def question(core, *, provider="deepseek", client="oauth-client-1", key="request-1",
             prompt="Summarize findings without executing anything", plan="plan"):
    return core.ai_advisories.create_request(
        mission_id="mission", provider_id=provider, client_id=client,
        request_key=key, prompt=prompt, plan_id=plan,
    )


def test_no_key_advisory_is_durable_idempotent_and_has_no_execution_power(core):
    request = question(core)
    assert request["status"] == "awaiting_reply"
    assert request["model_inference_verified"] is False
    assert request["execution_authorized"] is False
    assert question(core)["id"] == request["id"]
    reopened = Core(core.data_dir)
    response = reopened.ai_advisories.record_response(
        request["id"], provider_id="deepseek", client_id="oauth-client-1",
        response_id="reply-1", response="Untrusted model recommendation.",
    )
    assert response["status"] == "pending_review"
    assert reopened.ai_advisories.record_response(
        request["id"], provider_id="deepseek", client_id="oauth-client-1",
        response_id="reply-1", response="Untrusted model recommendation.",
    )["id"] == request["id"]
    review = core.ai_advisories.decide(
        request["id"], reviewer="operator-1", decision="reviewed",
    )
    assert review["execution_authorized"] is False
    assert review["status"] == "reviewed"
    assert reopened.ai_advisories.get(request["id"])["reviewer"] == "operator-1"
    assert [x["event"] for x in core.ai_advisories.events(request["id"])] == [
        "advisory_created", "advisory_received", "advisory_reviewed",
    ]
    assert core.workflow_progress("plan")["counts"]["pending"] == 1
    assert not core.workflow_run_queue_summary()["total"]


def test_identity_isolation_and_reply_conflicts_fail_closed(core):
    row = question(core)
    for provider, client in [
        ("other", "oauth-client-1"),
        ("deepseek", "other-client"),
    ]:
        with pytest.raises(ValueError, match="unknown advisory"):
            core.ai_advisories.record_response(
                row["id"], provider_id=provider, client_id=client,
                response_id="reply", response="Unauthorized.",
            )
        assert core.ai_advisories.get(
            row["id"], provider_id=provider, client_id=client,
        ) is None
    core.ai_advisories.record_response(
        row["id"], provider_id="deepseek", client_id="oauth-client-1",
        response_id="reply", response="Original.",
    )
    with pytest.raises(ValueError, match="conflicting or replayed"):
        core.ai_advisories.record_response(
            row["id"], provider_id="deepseek", client_id="oauth-client-1",
            response_id="reply", response="Poisoned replacement.",
        )
    with pytest.raises(ValueError, match="conflicting"):
        question(core, prompt="Different request under same key")
    assert core.ai_advisories.get(row["id"])["response_text"] == "Original."


def test_review_is_not_approval_and_is_irreversible(core):
    row = question(core)
    with pytest.raises(ValueError, match="no pending review"):
        core.ai_advisories.decide(
            row["id"], reviewer="operator-1", decision="reviewed",
        )
    core.ai_advisories.record_response(
        row["id"], provider_id="deepseek", client_id="oauth-client-1",
        response_id="reply", response="Please run a security tool.",
    )
    core.ai_advisories.decide(
        row["id"], reviewer="operator-1", decision="dismissed",
    )
    with pytest.raises(ValueError, match="no pending review"):
        core.ai_advisories.decide(
            row["id"], reviewer="operator-2", decision="reviewed",
        )
    assert core.workflow_progress("plan")["counts"]["pending"] == 1


def test_expired_request_or_cross_mission_plan_never_accepts_reply(core):
    row = question(core, key="expire")
    with core.store._lock:
        conn = core.store._conn()
        try:
            conn.execute(
                "UPDATE ai_advisory_requests SET expires_at=? WHERE id=?",
                (time.time() - 1, row["id"]),
            )
        finally:
            conn.close()
    with pytest.raises(ValueError, match="expired"):
        core.ai_advisories.record_response(
            row["id"], provider_id="deepseek", client_id="oauth-client-1",
            response_id="reply", response="Late result.",
        )
    core.create_mission("other-mission", "outside this mission")
    with pytest.raises(ValueError, match="not bound"):
        core.ai_advisories.create_request(
            mission_id="other-mission", provider_id="deepseek",
            client_id="oauth-client-1", request_key="bad-plan",
            prompt="Check the wrong source.", plan_id="plan",
        )


def test_invalid_transport_inputs_and_unknown_mission_rejected(core):
    for bad in ["", "  ", "x" * 12001, "command\x00hidden"]:
        with pytest.raises(ValueError):
            question(core, key="bad-" + str(len(bad)), prompt=bad)
    with pytest.raises(ValueError, match="unknown mission"):
        core.ai_advisories.create_request(
            mission_id="missing", provider_id="deepseek",
            client_id="oauth-client-1", request_key="missing",
            prompt="No mission.",
        )
    with pytest.raises(ValueError, match="ttl_seconds"):
        core.ai_advisories.create_request(
            mission_id="mission", provider_id="deepseek",
            client_id="oauth-client-1", request_key="badttl",
            prompt="No long-running phantom request.", ttl_seconds=999999,
        )
    assert core.ai_advisories.list_mission("mission") == []
