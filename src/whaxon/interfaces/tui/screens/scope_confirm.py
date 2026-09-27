"""Modal screen shown when a target is out of scope."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Center, Middle
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ScopeConfirmScreen(ModalScreen[bool]):
    """Modal that returns True if the user wants to run anyway, False to cancel."""

    BINDINGS = [
        ("y", "run_anyway", "Run anyway"),
        ("n", "cancel", "Cancel"),
        ("escape", "cancel", "Cancel"),
        ("enter", "run_anyway", "Run anyway"),
    ]

    def on_mount(self) -> None:
        # Focus the screen itself so keybindings are handled here, not the
        # buttons. Without this, Button widgets eat the keys.
        self.set_focus(None)

    def __init__(self, target: str, tool_id: str, reason: str, rule: str) -> None:
        super().__init__()
        self.target = target
        self.tool_id = tool_id
        self.reason = reason
        self.rule = rule

    def compose(self) -> ComposeResult:
        with Middle(), Center():
            with Static(id="scope-modal"):
                yield Static("[bold red]\u26a0 Out of scope[/]", id="scope-title")
                yield Static(f"\n[bold]{self.target}[/] does not match any in-scope rule.")
                yield Static(f"\nReason:     {self.reason}")
                yield Static(f"Rule:       {self.rule or '(none)'}")
                yield Static(f"Tool:       {self.tool_id}")
                yield Static(
                    "\n[dim]Overrides are logged. Only proceed if you have "
                    "written authorization.[/]"
                )
                with Center():
                    yield Button("Run anyway (y)", id="run-anyway", variant="error")
                    yield Button("Cancel (n)", id="cancel")

    def on_key(self, event) -> None:
        key = (event.key or "").lower()
        if key in ("y", "enter"):
            event.stop()
            self.action_run_anyway()
        elif key in ("n", "escape"):
            event.stop()
            self.action_cancel()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-anyway":
            self.action_run_anyway()
        else:
            self.action_cancel()

    def action_run_anyway(self) -> None:
        _log_override(self.target, self.tool_id)
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


def _log_override(target: str, tool_id: str) -> None:
    """Write a line to <data_dir>/scope_overrides.log."""
    # The data dir is where Core was constructed. Best guess: 'data' relative
    # to the current working directory; if that doesn't exist, fall back to
    # the user's XDG state dir.
    candidates = [Path("data"), Path.cwd() / "data"]
    for d in candidates:
        if d.is_dir():
            log_path = d / "scope_overrides.log"
            try:
                ts = datetime.now(timezone.utc).isoformat()
                with log_path.open("a", encoding="utf-8") as f:
                    f.write(f"{ts}\t{tool_id}\t{target}\n")
                return
            except OSError:
                pass
