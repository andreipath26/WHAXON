"""Plugin discovery: external adapters via entry points."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from whaxon.adapters.base import Adapter
from whaxon.adapters.registry import (
    _ADAPTERS, get_adapter, list_adapters, register,
)


class FakePlugin(Adapter):
    tool_id = "fake-plugin"
    def parse(self, lines, ctx=None):
        return []


def test_entry_point_discovery_registers_adapter(monkeypatch):
    # Remove any existing registration
    _ADAPTERS.pop("fake-plugin", None)

    class FakeEP:
        name = "fake-plugin"
        def load(self):
            return FakePlugin

    fake_eps = [FakeEP()]

    # Patch entry_points before calling _discover_plugins
    import importlib.metadata as im
    monkeypatch.setattr(im, "entry_points", lambda **kw: fake_eps)

    from whaxon.adapters.registry import _discover_plugins
    _discover_plugins()

    assert "fake-plugin" in list_adapters()
    assert isinstance(get_adapter("fake-plugin"), FakePlugin)

    # cleanup
    _ADAPTERS.pop("fake-plugin", None)


def test_broken_plugin_does_not_crash(capsys, monkeypatch):
    class BrokenEP:
        name = "broken"
        def load(self):
            raise ImportError("nope")

    import importlib.metadata as im
    monkeypatch.setattr(im, "entry_points", lambda **kw: [BrokenEP()])

    from whaxon.adapters.registry import _discover_plugins
    _discover_plugins()  # should not raise

    captured = capsys.readouterr()
    assert "broken" in captured.err
