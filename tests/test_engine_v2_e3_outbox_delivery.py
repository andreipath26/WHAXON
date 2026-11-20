"""E3 outbox delivery is durable at-least-once, never exactly-once."""
from __future__ import annotations

import pytest

from whaxon.core import Core
from whaxon.core.outbox import WorkflowEventOutbox
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _ready(tmp_path):
    core = Core(tmp_path)
    core.create_mission("mission", "event outbox fixture")
    core.save_workflow_plan(
        "plan", WorkflowPlan("mission", (
            WorkflowTask("task", "fixture", "192.0.2.10"),
        )),
    )
    attempt = core.store.claim_ready_workflow_task("plan", "worker")
    core.store.finish_task_attempt(attempt["attempt_id"], "succeeded")
    return core


def test_at_least_once_delivery_acknowledges_each_event_after_success(tmp_path):
    core = _ready(tmp_path)
    emitted = []
    first = core.deliver_workflow_outbox_events(
        "plan", "reporter", lambda item: emitted.append(item["id"]),
    )
    assert first["delivered"] == 2
    assert first["delivery_guarantee"] == "at_least_once"
    assert first["receiver_deduplication_required"] is True
    assert emitted == sorted(emitted)
    assert first["last_event_id"] == emitted[-1]
    restarted = Core(tmp_path)
    assert restarted.deliver_workflow_outbox_events(
        "plan", "reporter", lambda _: pytest.fail("acknowledged event replayed"),
    )["delivered"] == 0
    assert restarted.deliver_workflow_outbox_events(
        "plan", "independent", lambda _: None,
    )["delivered"] == 2


def test_post_effect_publish_failure_replays_unacked_event(tmp_path):
    core = _ready(tmp_path)
    delivered = []

    def fails_after_effect(event):
        delivered.append(event["id"])
        raise RuntimeError("receiver stored event but lost response")

    with pytest.raises(RuntimeError, match="lost response"):
        core.deliver_workflow_outbox_events("plan", "sink", fails_after_effect)
    assert core.store.get_workflow_event_cursor("plan", "sink") == 0
    retried = []
    result = Core(tmp_path).deliver_workflow_outbox_events(
        "plan", "sink", lambda event: retried.append(event["id"]),
    )
    assert retried[0] == delivered[0]
    assert result["delivered"] == 2
    assert len(set(retried)) == 2


def test_partial_delivery_ack_survives_restart_without_skipping(tmp_path):
    core = _ready(tmp_path)
    first = core.deliver_workflow_outbox_events(
        "plan", "reporter", lambda _: None, limit=1,
    )
    assert first["delivered"] == 1
    followup = []
    second = Core(tmp_path).deliver_workflow_outbox_events(
        "plan", "reporter", lambda event: followup.append(event["id"]),
    )
    assert second["delivered"] == 1
    assert followup[0] > first["last_event_id"]


def test_inconsistent_lifecycle_audit_blocks_outbox_delivery(tmp_path):
    core = _ready(tmp_path)
    conn = core.store._conn()
    try:
        conn.execute(
            "DELETE FROM workflow_events WHERE plan_id='plan' "
            "AND event_type='task_succeeded'"
        )
    finally:
        conn.close()
    received = []
    with pytest.raises(ValueError, match="audit is inconsistent"):
        WorkflowEventOutbox(core.store).deliver(
            "plan", "reporter", lambda e: received.append(e),
        )
    assert received == []
    assert core.store.get_workflow_event_cursor("plan", "reporter") == 0


@pytest.mark.parametrize("limit", [True, False, 0, -1, 1001, 1.5])
def test_outbox_rejects_invalid_batch_limit(tmp_path, limit):
    core = _ready(tmp_path)
    with pytest.raises(ValueError, match="limit"):
        core.deliver_workflow_outbox_events(
            "plan", "reporter", lambda _: None, limit=limit,
        )


def test_outbox_rejects_missing_callback(tmp_path):
    core = _ready(tmp_path)
    with pytest.raises(TypeError, match="publish"):
        core.deliver_workflow_outbox_events("plan", "sink", None)


@pytest.mark.asyncio
async def test_async_publish_callback_cannot_ack_undelivered_event(tmp_path):
    core = _ready(tmp_path)

    async def publish(_event):
        return True

    with pytest.raises(TypeError, match="synchronous"):
        core.deliver_workflow_outbox_events("plan", "async-sink", publish)
    assert core.store.get_workflow_event_cursor("plan", "async-sink") == 0
