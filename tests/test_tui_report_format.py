"""Tests for the ReportFormatScreen modal.

Uses Textual's run_test() harness with a minimal App that just pushes
the modal. No Core, no MainScreen — the modal is self-contained.
"""
from __future__ import annotations

from textual.app import App

from whaxon.interfaces.tui.screens.report_format import (
    FORMATS,
    ReportFormatScreen,
)


class _Harness(App):
    """Minimal app that pushes a ReportFormatScreen and captures the result."""

    def __init__(self, job_id: str = "job-test") -> None:
        super().__init__()
        self._job_id = job_id
        self.result: str | None = "UNSET"

    def on_mount(self) -> None:
        self.push_screen(ReportFormatScreen(self._job_id), self._on_dismiss)

    def _on_dismiss(self, value: str | None) -> None:
        self.result = value


async def test_composes_five_formats():
    app = _Harness()
    async with app.run_test() as pilot:
        # Concatenate the renderable of every Static widget in the modal.
        st = app.screen.query("Static")
        text = "".join(w.content for w in st)
        for _, label in FORMATS:
            assert label in text, f"missing format label: {label}"


async def test_key_1_dismisses_with_md():
    app = _Harness()
    async with app.run_test() as pilot:
        await pilot.press("1")
        await pilot.pause()
    assert app.result == "md"


async def test_key_3_dismisses_with_pdf():
    app = _Harness()
    async with app.run_test() as pilot:
        await pilot.press("3")
        await pilot.pause()
    assert app.result == "pdf"


async def test_key_5_dismisses_with_whaxon():
    app = _Harness()
    async with app.run_test() as pilot:
        await pilot.press("5")
        await pilot.pause()
    assert app.result == "whaxon"


async def test_escape_dismisses_with_none():
    app = _Harness()
    async with app.run_test() as pilot:
        await pilot.press("escape")
        await pilot.pause()
    assert app.result is None


async def test_job_id_stored_on_screen():
    """The screen exposes the job_id it was constructed with."""
    screen = ReportFormatScreen("job-xyz")
    assert screen.job_id == "job-xyz"