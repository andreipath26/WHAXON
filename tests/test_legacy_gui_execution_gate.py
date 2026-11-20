"""The dormant Qt compatibility module cannot dispatch by default."""
from __future__ import annotations

import ast
from pathlib import Path

from whaxon.interfaces.legacy_execution import legacy_gui_execution_enabled


def test_legacy_gui_execution_is_default_denied_and_requires_explicit_opt_in(
    monkeypatch,
):
    monkeypatch.delenv("WHAXON_LEGACY_GUI_EXECUTION_ENABLED", raising=False)
    assert legacy_gui_execution_enabled() is False

    for value in ("1", "true", "YES", " true "):
        monkeypatch.setenv("WHAXON_LEGACY_GUI_EXECUTION_ENABLED", value)
        assert legacy_gui_execution_enabled() is True

    for value in ("", "false", "on"):
        monkeypatch.setenv("WHAXON_LEGACY_GUI_EXECUTION_ENABLED", value)
        assert legacy_gui_execution_enabled() is False


def test_legacy_qt_dispatch_checks_gate_before_toolrunner_call():
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "whaxon"
        / "interfaces"
        / "gui"
        / "main_window.py"
    )
    module = ast.parse(source.read_text(encoding="utf-8"))
    run_tool = next(
        node for node in ast.walk(module)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_run_tool"
    )
    calls = [
        node for node in ast.walk(run_tool)
        if isinstance(node, ast.Call)
    ]
    gate_lines = [
        node.lineno for node in calls
        if isinstance(node.func, ast.Name)
        and node.func.id == "legacy_gui_execution_enabled"
    ]
    dispatch_lines = [
        node.lineno for node in calls
        if isinstance(node.func, ast.Attribute)
        and node.func.attr == "run_tool"
    ]
    assert gate_lines and dispatch_lines
    assert min(gate_lines) < min(dispatch_lines)
