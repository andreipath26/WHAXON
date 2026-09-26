"""Main TUI screen. Placeholder until Phase 3 fleshes it out."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, RichLog

from whaxon.core.events import JobOutput, ToolDiscovered


class MainScreen(Screen):
    BINDINGS = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            yield DataTable(id="catalog")
            yield RichLog(id="output", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#catalog", DataTable)
        table.add_columns("ID", "Name", "Category")
        for tool in self.app.core.catalog.list():
            table.add_row(tool.id, tool.name, tool.category)

        self.app.core.bus.subscribe(ToolDiscovered, self._on_tool)
        self.app.core.bus.subscribe(JobOutput, self._on_output)

    def _on_tool(self, evt: ToolDiscovered) -> None:
        table = self.query_one("#catalog", DataTable)
        table.add_row(evt.tool_id, evt.name, evt.category)

    def _on_output(self, evt: JobOutput) -> None:
        log = self.query_one("#output", RichLog)
        log.write(f"[dim]{evt.job_id}[/] {evt.line}")
