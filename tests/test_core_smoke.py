"""Phase 1 smoke test: core loads a catalog and emits events."""
from __future__ import annotations

import asyncio
import json

from whaxon.core import Core
from whaxon.core.events import ToolDiscovered


def _write_catalog(data_dir):
    (data_dir / "tools.json").write_text(json.dumps({
        "tools": [
            {"id": "nmap", "name": "Nmap", "category": "recon", "binary": "nmap"},
            {"id": "nikto", "name": "Nikto", "category": "web", "binary": "nikto"},
        ]
    }))


def test_catalog_emits_discovered_events(tmp_path):
    _write_catalog(tmp_path)
    core = Core(tmp_path)
    seen = []
    core.bus.subscribe(ToolDiscovered, seen.append)

    asyncio.run(core.initialize())

    assert len(seen) == 2
    assert {e.tool_id for e in seen} == {"nmap", "nikto"}


def test_catalog_list_after_load(tmp_path):
    _write_catalog(tmp_path)
    core = Core(tmp_path)
    asyncio.run(core.initialize())

    tools = core.catalog.list()
    assert len(tools) == 2
    assert core.catalog.get("nmap") is not None
    assert core.catalog.get("does-not-exist") is None


def test_catalog_reload_removes_deleted_tools(tmp_path):
    _write_catalog(tmp_path)
    core = Core(tmp_path)
    assert core.catalog.get("nmap") is not None

    (tmp_path / "tools.json").write_text(json.dumps({
        "tools": [
            {"id": "nikto", "name": "Nikto", "category": "web", "binary": "nikto"}
        ]
    }), encoding="utf-8")
    core.catalog.load()

    assert core.catalog.get("nmap") is None
    assert core.catalog.get("nikto") is not None


def test_missing_catalog_is_seeded_from_package(tmp_path):
    core = Core(tmp_path)

    assert (tmp_path / "tools.json").is_file()
    assert core.catalog.get("nmap") is not None
    assert core.catalog.get("echo") is not None
