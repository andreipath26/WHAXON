"""Native TUI client for reviewing and submitting durable Engine V2 plans."""
from __future__ import annotations

import getpass
import sqlite3
import time
import uuid

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, RichLog, Static

from whaxon.core.workflow import WorkflowPlan


class WorkflowScreen(Screen):
    """Review mission plans, record explicit approvals, and queue V2 work."""

    BINDINGS = [("escape", "back", "Back")]

    def __init__(self, *, tool_id: str | None = None, target: str | None = None) -> None:
        super().__init__()
        self.mission_id: str | None = None
        self.plan_id: str | None = None
        self.task_id: str | None = None
        self.run_request_id: str | None = None
        self.proposed_tool_id = tool_id
        self.proposed_target = target

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "Engine V2 plans use the shared approval and durable request services. "
            "Review the exact task before approving it.",
            id="workflow-intro",
        )
        with Horizontal(id="workflow-mission-create"):
            yield Input(placeholder="Mission ID", id="workflow-mission-id")
            yield Input(placeholder="Assessment objective", id="workflow-objective")
            yield Button("Create mission", id="workflow-create-mission")
        with Horizontal(id="workflow-plan-propose"):
            yield Input(placeholder="New plan ID", id="workflow-new-plan-id")
            yield Input(placeholder="Tool ID", id="workflow-tool-id")
            yield Input(placeholder="Exact in-scope target", id="workflow-target")
            yield Button("Propose tool plan", id="workflow-propose-tool", disabled=True)
        with Horizontal(id="workflow-verification-propose"):
            yield Input(placeholder="V2 source job ID", id="workflow-source-job-id")
            yield Input(placeholder="Finding sequence", id="workflow-finding-seq", type="integer")
            yield Input(placeholder="verify or retest", id="workflow-verification-mode", value="retest")
            yield Button(
                "Propose sealed-evidence verification",
                id="workflow-propose-verification", disabled=True,
            )
        with Horizontal(id="workflow-browser"):
            with Vertical():
                yield Static("Missions")
                yield DataTable(id="workflow-missions", cursor_type="row")
                yield Static("Plans")
                yield DataTable(id="workflow-plans", cursor_type="row")
                yield Static("Active or uncertain durable requests")
                yield DataTable(id="workflow-requests", cursor_type="row")
            with Vertical():
                yield Static("Tasks")
                yield DataTable(id="workflow-tasks", cursor_type="row")
                yield RichLog(id="workflow-details", markup=False, wrap=True)
        with Horizontal(id="workflow-actions"):
            yield Button("Refresh", id="workflow-refresh")
            yield Button("Approve selected task", id="workflow-approve", disabled=True)
            yield Button("Submit approved plan", id="workflow-submit", disabled=True)
            yield Button("Refresh request", id="workflow-request-refresh", disabled=True)
            yield Button("Cancel request", id="workflow-cancel", disabled=True)
            yield Button("Back", id="workflow-back")
        yield Static("Loading Engine V2 missions…", id="workflow-status")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#workflow-missions", DataTable).add_columns("Mission", "Objective")
        self.query_one("#workflow-plans", DataTable).add_columns("Plan", "Stage", "Digest")
        self.query_one("#workflow-tasks", DataTable).add_columns(
            "Task", "Capability", "Target", "Impact", "State",
        )
        self.query_one("#workflow-requests", DataTable).add_columns(
            "Request", "Plan", "State",
        )
        self._load_missions()
        self._load_active_requests()
        if self.proposed_tool_id:
            self.query_one("#workflow-tool-id", Input).value = self.proposed_tool_id
            self.query_one("#workflow-target", Input).value = self.proposed_target or ""
            self._say(
                f"{self.proposed_tool_id} selected from the catalog. Create or select a "
                "mission, then propose and review its Engine V2 plan; nothing has run."
            )

    def _load_active_requests(self) -> None:
        table = self.query_one("#workflow-requests", DataTable)
        table.clear()
        try:
            summary = self.app.core.workflow_run_queue_summary()
            for request in summary.get("active_requests", []):
                request_id = str(request.get("id", ""))
                if not request_id:
                    continue
                table.add_row(
                    request_id, str(request.get("plan_id", "")),
                    str(request.get("status", "unknown")), key=request_id,
                )
        except (AttributeError, sqlite3.Error, TypeError, ValueError, RuntimeError) as exc:
            self._say(f"Durable requests could not be reloaded: {exc}", error=True)

    def _load_missions(self) -> None:
        table = self.query_one("#workflow-missions", DataTable)
        table.clear()
        for mission in self.app.core.missions(limit=100):
            table.add_row(
                mission.get("id", ""), mission.get("objective", ""),
                key=mission.get("id", ""),
            )
        self._say(f"Loaded {table.row_count} persisted mission(s).")

    @on(Button.Pressed, "#workflow-create-mission")
    def _create_mission(self) -> None:
        mission_id = self.query_one("#workflow-mission-id", Input).value.strip()
        objective = self.query_one("#workflow-objective", Input).value.strip()
        if not mission_id or not objective:
            self._say("Enter a mission ID and objective.", error=True)
            return
        try:
            self.app.core.create_mission(mission_id, objective)
            self.mission_id = mission_id
            self._load_missions()
            self._load_plans_for_mission(mission_id)
            self.query_one("#workflow-propose-tool", Button).disabled = False
            self.query_one("#workflow-propose-verification", Button).disabled = False
            self._say(f"Mission {mission_id} created. Add a reviewable tool plan when ready.")
        except (sqlite3.Error, TypeError, ValueError, RuntimeError) as exc:
            self._say(f"Mission was not created: {exc}", error=True)

    @on(DataTable.RowSelected, "#workflow-missions")
    def _mission_selected(self, event: DataTable.RowSelected) -> None:
        self.mission_id = str(event.row_key.value)
        self.plan_id = None
        self.task_id = None
        self.run_request_id = None
        self._load_plans_for_mission(self.mission_id)
        self.query_one("#workflow-propose-tool", Button).disabled = False
        self.query_one("#workflow-propose-verification", Button).disabled = False

    def _load_plans_for_mission(self, mission_id: str) -> None:
        plans = self.query_one("#workflow-plans", DataTable)
        plans.clear()
        self.query_one("#workflow-tasks", DataTable).clear()
        for plan in self.app.core.mission_workflow_plans(mission_id):
            digest = str(plan.get("digest", ""))
            plan_id = str(plan.get("id", ""))
            metadata = plan.get("plan", {}).get("metadata", {})
            plans.add_row(
                plan_id, str(metadata.get("release_stage", "plan")), digest[:12],
                key=plan_id,
            )
        self._say(f"Mission {self.mission_id}: loaded {plans.row_count} plan(s).")

    @on(Button.Pressed, "#workflow-propose-tool")
    def _propose_tool_plan(self) -> None:
        if not self.mission_id:
            self._say("Create or select a mission before proposing a plan.", error=True)
            return
        plan_id = self.query_one("#workflow-new-plan-id", Input).value.strip()
        tool_id = self.query_one("#workflow-tool-id", Input).value.strip()
        target = self.query_one("#workflow-target", Input).value.strip()
        if not plan_id or not tool_id or not target:
            self._say("Enter a plan ID, tool ID and exact in-scope target.", error=True)
            return
        try:
            from whaxon.core.workflow_proposals import propose_tool_workflow_plan

            proposal = propose_tool_workflow_plan(
                self.app.core,
                mission_id=self.mission_id,
                plan_id=plan_id,
                tool_id=tool_id,
                target=target,
            )
            if proposal.get("status") != "proposed":
                self._say(
                    f"No plan created: {proposal.get('reason', 'proposal was blocked')}.",
                    error=True,
                )
                return
            created = self.app.core.save_workflow_plan(
                plan_id, WorkflowPlan.from_dict(proposal["plan"]),
            )
            if not created:
                self._say(f"Plan ID {plan_id} already exists; no replacement was made.", error=True)
                return
            self._load_plans_for_mission(self.mission_id)
            self._say(
                f"Plan {plan_id} saved for review ({proposal['capability_id']}). "
                "No approval or execution was submitted."
            )
        except (AttributeError, sqlite3.Error, TypeError, ValueError, RuntimeError) as exc:
            self._say(f"Plan proposal failed: {exc}", error=True)

    @on(Button.Pressed, "#workflow-propose-verification")
    def _propose_verification_plan(self) -> None:
        if not self.mission_id:
            self._say("Create or select a mission before proposing verification.", error=True)
            return
        plan_id = self.query_one("#workflow-new-plan-id", Input).value.strip()
        source_job_id = self.query_one("#workflow-source-job-id", Input).value.strip()
        raw_seq = self.query_one("#workflow-finding-seq", Input).value.strip()
        mode = self.query_one("#workflow-verification-mode", Input).value.strip()
        if not plan_id or not source_job_id or not raw_seq:
            self._say("Enter a plan ID, V2 source job ID and finding sequence.", error=True)
            return
        try:
            finding_seq = int(raw_seq)
            from whaxon.core.workflow_proposals import propose_finding_verification_plan

            proposal = propose_finding_verification_plan(
                self.app.core,
                mission_id=self.mission_id,
                plan_id=plan_id,
                source_job_id=source_job_id,
                finding_seq=finding_seq,
                mode=mode,
            )
            if proposal.get("status") != "proposed":
                self._say(
                    f"No verification plan created: {proposal.get('reason', 'proposal was blocked')}.",
                    error=True,
                )
                return
            created = self.app.core.save_workflow_plan(
                plan_id, WorkflowPlan.from_dict(proposal["plan"]),
            )
            if not created:
                self._say(f"Plan ID {plan_id} already exists; no replacement was made.", error=True)
                return
            self._load_plans_for_mission(self.mission_id)
            self._say(
                f"Sealed-evidence {mode} plan {plan_id} saved for review "
                f"({proposal['capability_id']}). No approval or execution was submitted."
            )
        except (AttributeError, sqlite3.Error, TypeError, ValueError, RuntimeError) as exc:
            self._say(f"Verification proposal failed: {exc}", error=True)

    @on(DataTable.RowSelected, "#workflow-plans")
    def _plan_selected(self, event: DataTable.RowSelected) -> None:
        self.plan_id = str(event.row_key.value)
        self.task_id = None
        self.run_request_id = None
        self._load_plan_details()

    def _load_plan_details(self) -> None:
        if not self.plan_id:
            return
        details = self.app.core.workflow_plan_details(self.plan_id)
        plan = WorkflowPlan.from_dict(details["plan"])
        task_rows = details["tasks"]
        table = self.query_one("#workflow-tasks", DataTable)
        table.clear()
        by_id = {str(task["id"]): task for task in task_rows}
        for task in plan.tasks:
            row = by_id.get(task.id, {})
            table.add_row(
                task.id, task.capability_id, task.target, task.impact,
                str(row.get("status", "proposed")), key=task.id,
            )
        approvals = self.app.core.workflow_approvals(self.plan_id)
        log = self.query_one("#workflow-details", RichLog)
        log.clear()
        log.write(f"Plan: {self.plan_id}")
        log.write(f"Digest: {plan.digest}")
        for task in plan.tasks:
            log.write(
                f"{task.id}: {task.capability_id} → {task.target}; "
                f"impact={task.impact}; inputs={task.inputs!r}"
            )
        log.write(f"Recorded approval(s): {len(approvals)}")
        self.query_one("#workflow-approve", Button).disabled = not bool(plan.tasks)
        self.query_one("#workflow-submit", Button).disabled = not bool(plan.tasks)
        self._say("Plan loaded. Select a task to review its exact binding before approval.")

    @on(DataTable.RowSelected, "#workflow-requests")
    def _request_selected(self, event: DataTable.RowSelected) -> None:
        self.run_request_id = str(event.row_key.value)
        request = self.app.core.workflow_run_request(self.run_request_id)
        if request is None:
            self._say("The selected durable request is unavailable.", error=True)
            return
        self.plan_id = str(request["plan_id"])
        self.query_one("#workflow-request-refresh", Button).disabled = False
        self.query_one("#workflow-cancel", Button).disabled = request["status"] not in {
            "queued", "running",
        }
        self._load_plan_details()
        self._refresh_request_status()

    @on(DataTable.RowSelected, "#workflow-tasks")
    def _task_selected(self, event: DataTable.RowSelected) -> None:
        self.task_id = str(event.row_key.value)
        self.query_one("#workflow-approve", Button).disabled = False
        self._say(f"Selected task {self.task_id}; its capability, target, impact and inputs are shown above.")

    @on(Button.Pressed, "#workflow-refresh")
    def _refresh(self) -> None:
        self._load_missions()
        self._load_active_requests()
        self._say("Missions and active durable requests refreshed.")

    @on(Button.Pressed, "#workflow-approve")
    def _approve_task(self) -> None:
        if not self.plan_id or not self.task_id:
            self._say("Choose a plan and task before granting approval.", error=True)
            return
        try:
            created = self.app.core.grant_workflow_approval(
                self.plan_id,
                self.task_id,
                f"tui-{uuid.uuid4().hex}",
                getpass.getuser(),
                expires_at=time.time() + 900,
            )
            self._load_plan_details()
            self._say(
                f"Approval {'recorded' if created else 'already existed'} for "
                f"{self.task_id}; it expires in 15 minutes."
            )
        except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
            self._say(f"Approval was not recorded: {exc}", error=True)

    @on(Button.Pressed, "#workflow-submit")
    def _submit_clicked(self) -> None:
        self._submit_plan()

    @work(exclusive=True)
    async def _submit_plan(self) -> None:
        if not self.plan_id:
            self._say("Choose a persisted plan first.", error=True)
            return
        try:
            details = self.app.core.workflow_plan_details(self.plan_id)
            plan = WorkflowPlan.from_dict(details["plan"])
            for task in plan.tasks:
                if self.app.core.authorize_workflow_task_for_plan(self.plan_id, task) is not True:
                    raise ValueError(f"task {task.id} is not authorized and approved")
            request = self.app.core.enqueue_workflow_run(self.plan_id)
            self.run_request_id = request["id"]
            self._load_active_requests()
            self.query_one("#workflow-request-refresh", Button).disabled = False
            self.query_one("#workflow-cancel", Button).disabled = False
            self._say(
                f"Durable request {self.run_request_id} queued. Completion is not yet claimed."
            )
            await self.app.core.drain_workflow_run_requests(max_runs=1)
            self._refresh_request_status()
        except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
            self._say(f"Plan was not submitted: {exc}", error=True)

    @on(Button.Pressed, "#workflow-request-refresh")
    def _refresh_request(self) -> None:
        self._refresh_request_status()

    def _refresh_request_status(self) -> None:
        if not self.run_request_id:
            self._say("No durable request is selected.", error=True)
            return
        request = self.app.core.workflow_run_request(self.run_request_id)
        if request is None:
            self._say("The durable request is unavailable.", error=True)
            return
        self._say(
            f"Request {self.run_request_id}: {request['status']}. "
            "A running or uncertain request is not reported as completed."
        )
        self._load_active_requests()
        self.query_one("#workflow-cancel", Button).disabled = request["status"] not in {
            "queued", "running",
        }

    @on(Button.Pressed, "#workflow-cancel")
    def _cancel_request(self) -> None:
        if not self.run_request_id:
            self._say("No durable request is selected.", error=True)
            return
        try:
            result = self.app.core.cancel_workflow_run_request(self.run_request_id)
            self._say(
                f"Cancellation requested for {self.run_request_id}; "
                "external effects may still be running or uncertain. "
                f"Tasks closed: {result['tasks_cancelled']}."
            )
            self._refresh_request_status()
        except (TypeError, ValueError, RuntimeError) as exc:
            self._say(f"Cancellation request failed: {exc}", error=True)

    @on(Button.Pressed, "#workflow-back")
    def _back(self) -> None:
        self.action_back()

    def action_back(self) -> None:
        self.app.pop_screen()

    def _say(self, message: str, *, error: bool = False) -> None:
        self.query_one("#workflow-status", Static).update(message)
        self.query_one("#workflow-status", Static).set_classes("error" if error else "")
