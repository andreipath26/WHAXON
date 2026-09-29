"""AI Runs screen for the TUI — reads from the store, no live updates.

Shown modally from MainScreen. Lists recent AI runs with their phase
and status. Read-only for now; approval and resume are future work.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static


class AiRunsScreen(Screen):
    """Modal screen listing recent AI runs."""

    BINDINGS = [("escape", "dismiss", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="ai-runs-body"):
            yield Static("Recent AI runs", classes="panel-title")
            yield DataTable(id="ai-runs-table", cursor_type="row",
                            zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#ai-runs-table", DataTable)
        table.add_columns("Run", "Goal", "Phase", "Status", "Steps")
        try:
            core = self.app.core  # type: ignore[attr-defined]
            store = core.store
            summaries = store.list_ai_runs(limit=50) or []
        except Exception as e:
            table.add_row("(error)", str(e)[:80], "", "", "")
            return
        if not summaries:
            table.add_row("(none)", "", "", "", "")
            return
        for summary in summaries:
            rid = summary.get("id", "")
            goal = (summary.get("goal") or "")[:40]
            status = summary.get("status", "")
            try:
                full = store.get_ai_run(rid) or {}
            except Exception:
                full = {}
            phase = full.get("phase") or summary.get("phase") or "recon"
            steps = len(full.get("steps") or [])
            table.add_row(str(rid), goal, str(phase), str(status), str(steps))

    def action_dismiss(self) -> None:
        self.app.pop_screen()