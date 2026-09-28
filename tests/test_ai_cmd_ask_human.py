"""whaxon ai CLI: stdin ask_human callback behavior."""
from __future__ import annotations

from whaxon.ai.actions import Action
from whaxon.interfaces.cli.ai_cmd import _stdin_ask_human


def _fake_input(value: str):
    def _in(_prompt: str = "") -> str:
        return value
    return _in


def test_stdin_ask_human_returns_y(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", _fake_input("y"))
    action = Action.ask_human("approve nmap?", confidence=0.8)
    assert _stdin_ask_human(action) == "y"


def test_stdin_ask_human_returns_n(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", _fake_input("n"))
    action = Action.ask_human("approve nmap?", confidence=0.8)
    assert _stdin_ask_human(action) == "n"


def test_stdin_ask_human_passes_freeform_through(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", _fake_input("try gobuster instead"))
    action = Action.ask_human("approve nmap?", confidence=0.8)
    assert _stdin_ask_human(action) == "try gobuster instead"


def test_stdin_ask_human_strips_whitespace(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", _fake_input("  y  "))
    action = Action.ask_human("approve nmap?", confidence=0.8)
    assert _stdin_ask_human(action) == "y"


def test_stdin_ask_human_eof_returns_skip(monkeypatch) -> None:
    def _raise_eof(_prompt: str = "") -> str:
        raise EOFError()
    monkeypatch.setattr("builtins.input", _raise_eof)
    action = Action.ask_human("approve nmap?", confidence=0.8)
    assert _stdin_ask_human(action) == "skip"