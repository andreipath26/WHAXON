"""Main TUI screen: catalog table, target input, live output from the runner."""
from __future__ import annotations

import asyncio

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label, RichLog, Static,
)

from whaxon.core.events import (
    JobFailed, JobFinished, JobOutput, JobStarted, ToolDiscovered,
)


class ToolDiscoveredMsg(Message):
    def __init__(self, tool_id: str, name: str, category: str) -> None:
        self.tool_id = tool_id; self.name = name; self.category = category
        super().__init__()

class JobStartedMsg(Message):
    def __init__(self, job_id: str, tool_id: str, target: str) -> None:
        self.job_id = job_id; self.tool_id = tool_id; self.target = target
        super().__init__()

class JobOutputMsg(Message):
    def __init__(self, job_id: str, stream: str, line: str) -> None:
        self.job_id = job_id; self.stream = stream; self.line = line
        super().__init__()

class JobFinishedMsg(Message):
    def __init__(self, job_id: str, exit_code: int, duration_s: float) -> None:
        self.job_id = job_id; self.exit_code = exit_code; self.duration_s = duration_s
        super().__init__()

class JobFailedMsg(Message):
    def __init__(self, job_id: str, error: str) -> None:
        self.job_id = job_id; self.error = error
        super().__init__()


class MainScreen(Screen):
    BINDINGS = [
        ("ctrl+q", "graceful_quit", "Quit"),
        ("r", "run_selected", "Run"),
        ("c", "cancel_job", "Cancel"),
        ("escape", "focus_catalog", "Catalog"),
        ("i", "focus_target", "Target"),
        ("s", "save_report", "Save report"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.selected_tool_id: str | None = None
        self.current_job_id: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="left"):
                yield Label("Tool Catalog", classes="panel-title")
                yield DataTable(id="catalog", cursor_type="row", zebra_stripes=True)
                yield Label("History", classes="panel-title")
                yield DataTable(id="history", cursor_type="row", zebra_stripes=True)
            with Vertical(id="right"):
                yield Label("Target", classes="panel-title")
                yield Input(
                    placeholder="host or URL, e.g. 127.0.0.1",
                    id="target",
                )
                yield Input(
                    placeholder="extra args (optional)",
                    id="extra",
                )
                with Horizontal(id="actions"):
                    yield Button("Run", id="run", variant="success")
                    yield Button("Cancel", id="cancel", variant="error", disabled=True)
                yield Label("Output", classes="panel-title")
                yield RichLog(id="output", highlight=True, markup=True, wrap=True)
        yield Static("loading\u2026", id="status")
        yield Footer()

    def on_mount(self) -> None:
        try:
            self._on_mount_impl()
        except Exception as e:
            import traceback; traceback.print_exc()
            self.app.exit(reason=f"main screen failed: {e}")

    def _on_mount_impl(self) -> None:
        table = self.query_one("#catalog", DataTable)
        table.add_columns("ID", "Name", "Category")
        for tool in self.app.core.catalog.list():
            table.add_row(tool.id, tool.name, tool.category, key=tool.id)

        bus = self.app.core.bus
        bus.subscribe(ToolDiscovered, lambda e: self.post_message(
            ToolDiscoveredMsg(e.tool_id, e.name, e.category)))
        bus.subscribe(JobStarted, lambda e: self.post_message(
            JobStartedMsg(e.job_id, e.tool_id, e.target)))
        bus.subscribe(JobOutput, lambda e: self.post_message(
            JobOutputMsg(e.job_id, e.stream, e.line)))
        bus.subscribe(JobFinished, lambda e: self.post_message(
            JobFinishedMsg(e.job_id, e.exit_code, e.duration_s)))
        bus.subscribe(JobFailed, lambda e: self.post_message(
            JobFailedMsg(e.job_id, e.error)))

        self._set_status(
            f"ready \u2014 {len(self.app.core.catalog.list())} tools loaded. "
            "Select a tool, type a target, press r."
        )
        table.focus()
        if table.row_count:
            table.move_cursor(row=0)

        # History table
        hist = self.query_one("#history", DataTable)
        hist.add_columns("When", "Tool", "Target")
        self._refresh_history()

    def _refresh_history(self) -> None:
        try:
            hist = self.query_one("#history", DataTable)
        except Exception:
            return
        hist.clear()
        for j in self.app.core.store.history(limit=20):
            import datetime as _dt
            dur = j.get("duration_s") or 0
            hist.add_row(
                f"{dur:.1f}s",
                j.get("tool", ""),
                j.get("target", ""),
                key=j.get("id"),
            )

    @on(DataTable.RowSelected, "#history")
    def _on_history_row(self, event: DataTable.RowSelected) -> None:
        job_id = str(event.row_key.value)
        if not job_id:
            return
        job = self.app.core.store.get(job_id)
        if job is None:
            return
        log = self.query_one("#output", RichLog)
        log.clear()
        log.write(f"[bold blue]history[/] {job_id} \u2014 {job['tool']} \u2192 {job['target']}")
        for line in job.get("lines", []):
            if line["stream"] == "stderr":
                log.write(f"[red]{line['text']}[/]")
            else:
                log.write(line["text"])
        self._set_status(f"viewing {job_id}")

    @on(DataTable.RowSelected, "#catalog")
    def _on_row_selected(self, event: DataTable.RowSelected) -> None:
        self.selected_tool_id = str(event.row_key.value)
        tool = self.app.core.catalog.get(self.selected_tool_id)
        if tool:
            self._set_status(f"selected: {tool.name} \u2192 {tool.binary}")
            self.query_one("#target", Input).focus()

    @on(DataTable.RowHighlighted, "#catalog")
    def _on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.selected_tool_id = str(event.row_key.value)

    @on(Button.Pressed, "#run")
    def _on_run_pressed(self) -> None:
        self.action_run_selected()

    @on(Button.Pressed, "#cancel")
    def _on_cancel_pressed(self) -> None:
        self.action_cancel_job()

    @on(Input.Submitted, "#target")
    def _on_target_submitted(self) -> None:
        self.action_run_selected()

    def on_tool_discovered_msg(self, msg: ToolDiscoveredMsg) -> None:
        table = self.query_one("#catalog", DataTable)
        if msg.tool_id not in [str(k.value) for k in table.rows]:
            table.add_row(msg.tool_id, msg.name, msg.category, key=msg.tool_id)

    def on_job_started_msg(self, msg: JobStartedMsg) -> None:
        self.current_job_id = msg.job_id
        log = self.query_one("#output", RichLog)
        log.write(f"[bold green]\u25b6 job {msg.job_id} started[/] \u2014 "
                  f"[cyan]{msg.tool_id}[/] \u2192 [yellow]{msg.target}[/]")
        self.query_one("#cancel", Button).disabled = False
        self._set_status(f"running job {msg.job_id}\u2026")

    def on_job_output_msg(self, msg: JobOutputMsg) -> None:
        log = self.query_one("#output", RichLog)
        if msg.stream == "stderr":
            log.write(f"[red]{msg.line}[/]")
        else:
            log.write(msg.line)

    def on_job_finished_msg(self, msg: JobFinishedMsg) -> None:
        self._refresh_history()
        log = self.query_one("#output", RichLog)
        color = "green" if msg.exit_code == 0 else "yellow"
        log.write(f"[bold {color}]\u2714 job {msg.job_id} finished[/] \u2014 "
                  f"exit={msg.exit_code} in {msg.duration_s:.2f}s")
        self.current_job_id = None
        self.query_one("#cancel", Button).disabled = True
        self._set_status(f"done \u2014 exit {msg.exit_code} in {msg.duration_s:.2f}s")

    def on_job_failed_msg(self, msg: JobFailedMsg) -> None:
        log = self.query_one("#output", RichLog)
        log.write(f"[bold red]\u2718 job {msg.job_id} failed[/] \u2014 {msg.error}")
        self.current_job_id = None
        self.query_one("#cancel", Button).disabled = True
        self._set_status(f"failed \u2014 {msg.error}")

    def action_run_selected(self) -> None:
        if self.current_job_id:
            self._set_status("a job is already running \u2014 press c to cancel")
            return
        if not self.selected_tool_id:
            self._set_status("no tool selected \u2014 click a row first")
            return
        tool = self.app.core.catalog.get(self.selected_tool_id)
        if tool is None:
            self._set_status(f"tool {self.selected_tool_id} not in catalog")
            return
        target = self.query_one("#target", Input).value.strip()
        extra_args = self.query_one("#extra", Input).value.strip()
        if not target:
            self._set_status("enter a target first")
            self.query_one("#target", Input).focus()
            return
        self._run_tool(tool.id, target, extra_args)

    def action_cancel_job(self) -> None:
        if not self.current_job_id:
            self._set_status("nothing to cancel")
            return
        self._cancel_job(self.current_job_id)
        self._set_status(f"cancelling job {self.current_job_id}\u2026")

    async def action_graceful_quit(self) -> None:
        """Cancel any running job, wait for it, then exit cleanly."""
        if self.current_job_id:
            try:
                await self.app.core.runner.cancel(self.current_job_id)
            except Exception:
                pass
        # Give the event loop a moment to drain pending events
        await asyncio.sleep(0.1)
        self.app.exit()

    def action_save_report(self) -> None:
        try:
            hist = self.query_one("#history", DataTable)
        except Exception:
            return
        if hist.cursor_row < 0 or hist.cursor_row >= hist.row_count:
            self._set_status("no history row selected")
            return
        row_key = hist.coordinate_to_cell_key((hist.cursor_row, 0)).row_key
        job_id = str(row_key.value) if row_key else ""
        if not job_id:
            return
        from pathlib import Path as _P
        from whaxon.core.report import render_markdown
        job = self.app.core.store.get(job_id)
        if job is None:
            self._set_status(f"job {job_id} gone")
            return
        findings = self.app.core.store.get_findings(job_id) or []
        md = render_markdown(job, findings)
        out_dir = _P.home() / ".local" / "share" / "whaxon" / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{job_id}.md"
        out_path.write_text(md, encoding="utf-8")
        log = self.query_one("#output", RichLog)
        log.write(f"[bold green]saved report:[/] {out_path}")
        self._set_status(f"saved {out_path.name}")

    def action_focus_catalog(self) -> None:
        self.query_one("#catalog", DataTable).focus()

    def action_focus_target(self) -> None:
        self.query_one("#target", Input).focus()

    @work(exclusive=False)
    async def _run_tool(self, tool_id: str, target: str, extra_args: str = "") -> None:
        log = self.query_one("#output", RichLog)
        log.write(f"[dim]$ running {tool_id} against {target}[/]")
        try:
            await self.app.core.runner.run_tool(
                tool_id=tool_id, target=target, extra_args=extra_args, timeout_s=300,
            )
        except FileNotFoundError as e:
            log.write(f"[bold red]binary not found:[/] {e}")
            self._set_status(f"binary not found: {e}")
        except Exception as e:
            log.write(f"[bold red]error:[/] {e}")
            self._set_status(f"error: {e}")

    @work(exclusive=False)
    async def _cancel_job(self, job_id: str) -> None:
        await self.app.core.runner.cancel(job_id)

    def _set_status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)
