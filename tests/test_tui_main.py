"""Tests for MainScreen — composition, bindings, and actions.

Uses WhaxonApp(data_dir=tmp_path) so the test never touches the repo's
real data/ directory. The screen wires itself to the app's real Core
during on_mount, so the tests run against an actual catalog + store;
those parts are cheap to construct and this is the closest we can get
to a real interaction without spawning subprocesses.

Scope:
  - Composition: expected widgets exist with expected IDs and initial state.
  - Key bindings: the app-level BINDINGS contains what the README claims.
  - Actions that don't spawn tools: focus, save-report-with-no-history,
    cancel-with-nothing-running, run-selected-without-tool,
    run-selected-without-target.
  - Event reactions: JobStartedMsg / JobFinishedMsg / JobFailedMsg update
    the cancel button and the status line.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from textual.widgets import Button, DataTable, Static

from whaxon.interfaces.tui.app import WhaxonApp
from whaxon.interfaces.tui.screens.main import (
    JobFailedMsg,
    JobFinishedMsg,
    JobStartedMsg,
    MainScreen,
)


async def _boot(tmp_path):
    """Return (app, pilot). Caller is responsible for exiting the context.

    Copies the repo's data/tools.json into the temp dir so the catalog loads.
    """
    import shutil
    repo_data = Path(__file__).resolve().parents[1] / "data"
    if (repo_data / "tools.json").exists():
        shutil.copy(repo_data / "tools.json", tmp_path / "tools.json")
    app = WhaxonApp(data_dir=tmp_path)
    return app


# ---------------------------------------------------------------- composition

async def test_main_screen_composes_expected_widgets(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        # After on_mount, the main screen is pushed.
        for wid in ("catalog", "history", "target", "extra", "run", "cancel",
                    "output", "search", "status"):
            # query_one raises if the id doesn't exist
            app.screen.query_one(f"#{wid}")


async def test_cancel_button_starts_disabled(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        cancel = app.screen.query_one("#cancel", Button)
        assert cancel.disabled is True


async def test_run_button_starts_enabled(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        run = app.screen.query_one("#run", Button)
        assert run.disabled is False


async def test_history_table_has_columns(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        hist = app.screen.query_one("#history", DataTable)
        # add_columns was called during _on_mount_impl
        assert len(hist.ordered_columns) == 3  # When, Tool, Target


async def test_catalog_table_has_columns(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one("#catalog", DataTable)
        assert len(table.ordered_columns) == 3  # ID, Name, Category


# ---------------------------------------------------------------- bindings

def test_main_screen_bindings_present():
    """BINDINGS list contains the user-facing key set."""
    keys = {b[0] if isinstance(b, tuple) else b.key for b in MainScreen.BINDINGS}
    for expected in ("r", "x", "s", "g", "i", "ctrl+q"):
        assert expected in keys, f"missing binding: {expected}"


# ---------------------------------------------------------------- actions

async def test_action_focus_catalog_moves_focus(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, MainScreen)
        screen.action_focus_catalog()
        await pilot.pause()
        assert app.focused is not None
        assert app.focused.id == "catalog"


async def test_action_focus_target_moves_focus(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, MainScreen)
        screen.action_focus_target()
        await pilot.pause()
        assert app.focused is not None
        assert app.focused.id == "target"


async def test_run_selected_without_tool_sets_status(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, MainScreen)
        screen.selected_tool_id = None
        screen.action_run_selected()
        await pilot.pause()
        status = app.screen.query_one("#status", Static)
        assert "no tool selected" in status.content


async def test_run_selected_without_target_sets_status(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, MainScreen)
        # pick a real tool from the catalog so we get past the tool check
        tools = app.core.catalog.list()
        if not tools:
            pytest.skip("catalog is empty in this environment")
        screen.selected_tool_id = tools[0].id
        # target is empty by default
        screen.action_run_selected()
        await pilot.pause()
        status = app.screen.query_one("#status", Static)
        assert "enter a target" in status.content


async def test_cancel_with_nothing_running_sets_status(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, MainScreen)
        screen.current_job_id = None
        screen.action_cancel_job()
        await pilot.pause()
        status = app.screen.query_one("#status", Static)
        assert "nothing to cancel" in status.content


# ---------------------------------------------------------------- event reactions

async def test_job_started_enables_cancel(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, MainScreen)
        screen.post_message(JobStartedMsg("j-test", "nmap", "127.0.0.1"))
        await pilot.pause()
        assert screen.current_job_id == "j-test"
        assert app.screen.query_one("#cancel", Button).disabled is False


async def test_job_finished_disables_cancel(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, MainScreen)
        # Simulate a run starting, then finishing
        screen.post_message(JobStartedMsg("j-test", "nmap", "127.0.0.1"))
        await pilot.pause()
        screen.post_message(JobFinishedMsg("j-test", 0, 0.1))
        await pilot.pause()
        assert screen.current_job_id is None
        assert app.screen.query_one("#cancel", Button).disabled is True


async def test_job_failed_disables_cancel(tmp_path):
    app = await _boot(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, MainScreen)
        screen.post_message(JobStartedMsg("j-test", "nmap", "127.0.0.1"))
        await pilot.pause()
        screen.post_message(JobFailedMsg("j-test", "boom"))
        await pilot.pause()
        assert screen.current_job_id is None
        assert app.screen.query_one("#cancel", Button).disabled is True
        assert "failed" in app.screen.query_one("#status", Static).content