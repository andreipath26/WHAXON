"""Modal for picking a report format in the TUI."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Center, Middle
from textual.screen import ModalScreen
from textual.widgets import Static

FORMATS = [("md", "Markdown (.md)"), ("html", "HTML (.html)"), ("pdf", "PDF (.pdf)"),
           ("json", "JSON (.json)"), ("whaxon", "Whaxon envelope (.whaxon)")]


class ReportFormatScreen(ModalScreen[str | None]):
    BINDINGS = [("1", "pick(\x27md\x27)", "Markdown"), ("2", "pick(\x27html\x27)", "HTML"),
                ("3", "pick(\x27pdf\x27)", "PDF"), ("4", "pick(\x27json\x27)", "JSON"),
                ("5", "pick(\x27whaxon\x27)", "Whaxon"), ("escape", "cancel", "Cancel")]

    def on_mount(self) -> None:
        self.set_focus(None)

    def __init__(self, job_id: str) -> None:
        super().__init__()
        self.job_id = job_id

    def compose(self) -> ComposeResult:
        with Middle(), Center(), Static(id="report-format-modal"):
            yield Static("[bold]Save report[/]", id="report-format-title")
            yield Static(f"\nJob: [bold]{self.job_id}[/]\n")
            for i, (_, label) in enumerate(FORMATS, start=1):
                yield Static(f"  [bold]{i}[/]  {label}")
            yield Static("\n[dim]Press 1-5 to pick, Escape to cancel.[/]")

    def action_pick(self, fmt: str) -> None:
        self.dismiss(fmt)

    def action_cancel(self) -> None:
        self.dismiss(None)
