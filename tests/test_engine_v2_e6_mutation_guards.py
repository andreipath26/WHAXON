"""E6 shared API mutation boundary regressions independent of unfinished UI.

No browser, scanner, external target, or new execution path is involved.
"""
from __future__ import annotations

import pytest

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.web.server import AsyncRunner, JobRegistry, create_app


@pytest.fixture
def e6_client(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    monkeypatch.setenv("WHAXON_V2_EXTERNAL_WORKER", "1")
    core = Core(tmp_path)
    core.create_mission("m", "inert authorization regression")
    core.save_workflow_plan(
        "p",
        WorkflowPlan("m", (
            WorkflowTask("inert", "unsupported.fixture", "192.0.2.10"),
        )),
    )
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    return app.test_client(), core


@pytest.mark.parametrize(
    ("endpoint", "payload"),
    [
        ("/api/v2/missions", {"id": "unauthorized", "objective": "bad"}),
        ("/api/v2/workflows", {"id": "unauthorized", "plan": {}}),
        ("/api/v2/missions/m/rate-limit", {"min_spacing_s": 10}),
        ("/api/v2/missions/m/cost", {"max_cost_microusd": 100}),
        ("/api/v2/missions/m/deadline", {"deadline_at": 2200000000}),
        ("/api/v2/missions/m/budget", {
            "max_total_attempts": 1, "max_concurrency": 1,
        }),
        ("/api/v2/workflows/p/run", {}),
        ("/api/v2/workflows/p/cancel", {}),
        ("/api/v2/workflows/p/approvals", {
            "task_key": "inert", "approval_id": "unauthorized",
            "actor": "unknown", "expires_at": 2200000000,
        }),
        ("/api/v2/workflows/p/approvals/unknown/revoke", {"actor": "unknown"}),
        ("/api/v2/workflows/p/reconcile", {}),
        ("/api/v2/workflows/p/event-ack", {
            "consumer": "ui", "event_id": 1,
        }),
        ("/api/v2/workflows/p/limits", {
            "max_total_attempts": 1, "max_concurrency": 1,
        }),
        ("/api/v2/workflows/p/deadline", {"deadline_at": 2200000000}),
        ("/api/v2/workflows/p/rate-limit", {"min_spacing_s": 10}),
        ("/api/v2/workflow-runs/unknown/cancel", {}),
        ("/api/v2/workflows/attempts/unknown/cost", {
            "cost_microusd": 2, "source": "untrusted",
        }),
    ],
)
def test_e6_cross_origin_mutation_rejected_before_service_dispatch(
    e6_client, endpoint, payload,
):
    client, core = e6_client
    forbidden = client.post(
        endpoint,
        json=payload,
        headers={"Origin": "https://attacker.invalid"},
    )
    assert forbidden.status_code == 403
    assert core.workflow_run_queue_summary()["total"] == 0
    assert core.missions()[0]["id"] == "m"
    assert core.workflow_progress("p")["cancellation_requested"] is False
