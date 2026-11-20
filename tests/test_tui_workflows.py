"""TUI workflow controls use persisted V2 plans and durable request services."""
from __future__ import annotations

from textual.widgets import Button, DataTable, Input, Static

from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.tui.app import WhaxonApp
from whaxon.interfaces.tui.screens.workflows import WorkflowScreen


async def test_tui_reviews_approves_and_cancels_durable_v2_request(tmp_path, monkeypatch):
    app = WhaxonApp(data_dir=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        core = app.core
        core.create_mission("mission-tui", "review an authorized lab")
        plan = WorkflowPlan("mission-tui", (
            WorkflowTask("scan", "tool.nmap", "192.0.2.10"),
        ))
        core.save_workflow_plan("plan-tui", plan)

        screen = WorkflowScreen()
        app.push_screen(screen)
        await pilot.pause()

        missions = screen.query_one("#workflow-missions", DataTable)
        assert missions.row_count == 1
        missions.focus()
        missions.move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause()

        plans = screen.query_one("#workflow-plans", DataTable)
        assert plans.row_count == 1
        plans.focus()
        plans.move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause()

        tasks = screen.query_one("#workflow-tasks", DataTable)
        assert tasks.row_count == 1
        details = screen.query_one("#workflow-details")
        assert any(plan.digest in str(line) for line in details.lines)
        tasks.focus()
        tasks.move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause()

        screen._approve_task()
        approvals = core.workflow_approvals("plan-tui")
        assert len(approvals) == 1
        assert approvals[0]["task_key"] == "scan"
        assert screen.query_one("#workflow-submit", Button).disabled is False

        monkeypatch.setattr(core, "authorize_workflow_task_for_plan", lambda *_: True)

        async def leave_queued(**_kwargs):
            return 0

        monkeypatch.setattr(core, "drain_workflow_run_requests", leave_queued)
        worker = screen._submit_plan()
        await worker.wait()

        assert screen.run_request_id
        queued = core.workflow_run_request(screen.run_request_id)
        assert queued["status"] == "queued"
        assert "not reported as completed" in screen.query_one(
            "#workflow-status", Static,
        ).content

        screen._cancel_request()
        assert core.workflow_run_request(screen.run_request_id)["status"] == "cancelled"


async def test_tui_reconnects_to_active_durable_request_after_screen_restart(tmp_path):
    app = WhaxonApp(data_dir=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        core = app.core
        core.create_mission("mission-reconnect", "resume an authorized lab")
        plan = WorkflowPlan("mission-reconnect", (
            WorkflowTask("scan", "tool.nmap", "192.0.2.10"),
        ))
        core.save_workflow_plan("plan-reconnect", plan)
        request = core.enqueue_workflow_run("plan-reconnect")

        screen = WorkflowScreen()
        app.push_screen(screen)
        await pilot.pause()

        requests = screen.query_one("#workflow-requests", DataTable)
        assert requests.row_count == 1
        requests.focus()
        requests.move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause()

        assert screen.run_request_id == request["id"]
        assert screen.plan_id == "plan-reconnect"
        assert "Request " + request["id"] + ": queued" in str(
            screen.query_one("#workflow-status", Static).content,
        )


async def test_tui_creates_mission_and_saves_only_a_reviewable_plan(tmp_path, monkeypatch):
    app = WhaxonApp(data_dir=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = WorkflowScreen()
        app.push_screen(screen)
        await pilot.pause()

        screen.query_one("#workflow-mission-id", Input).value = "mission-new"
        screen.query_one("#workflow-objective", Input).value = "assess the authorized lab"
        screen._create_mission()

        plan = WorkflowPlan("mission-new", (
            WorkflowTask("task-1", "tool.nmap", "192.0.2.10"),
        ))
        from whaxon.core import workflow_proposals

        monkeypatch.setattr(
            workflow_proposals,
            "propose_tool_workflow_plan",
            lambda *_args, **_kwargs: {
                "status": "proposed", "plan": plan.to_dict(),
                "capability_id": "tool.nmap",
            },
        )
        screen.query_one("#workflow-new-plan-id", Input).value = "plan-new"
        screen.query_one("#workflow-tool-id", Input).value = "nmap"
        screen.query_one("#workflow-target", Input).value = "192.0.2.10"
        screen._propose_tool_plan()

        persisted = app.core.workflow_plan_details("plan-new")
        assert persisted["plan"]["mission_id"] == "mission-new"
        assert app.core.workflow_approvals("plan-new") == []
        assert screen.run_request_id is None

        verification_plan = WorkflowPlan("mission-new", (
            WorkflowTask(
                "verification-1", "tool.retest_sqli", "192.0.2.10",
                inputs={"source_job_id": "v2-job-1", "finding_seq": 3},
            ),
        ))
        monkeypatch.setattr(
            workflow_proposals,
            "propose_finding_verification_plan",
            lambda *_args, **_kwargs: {
                "status": "proposed", "plan": verification_plan.to_dict(),
                "capability_id": "tool.retest_sqli",
            },
        )
        screen.query_one("#workflow-new-plan-id", Input).value = "plan-verify"
        screen.query_one("#workflow-source-job-id", Input).value = "v2-job-1"
        screen.query_one("#workflow-finding-seq", Input).value = "3"
        screen.query_one("#workflow-verification-mode", Input).value = "retest"
        screen._propose_verification_plan()

        verified = app.core.workflow_plan_details("plan-verify")
        assert verified["plan"]["tasks"][0]["capability_id"] == "tool.retest_sqli"
        assert app.core.workflow_approvals("plan-verify") == []
        assert screen.run_request_id is None
