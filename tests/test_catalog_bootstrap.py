"""Workspace catalog compatibility after retiring the checkout's duplicate seed."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from whaxon.core import Core


def test_new_workspace_bootstraps_packaged_catalog_outside_checkout(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    workspace = tmp_path / "operator" / "assessment"
    core = Core(workspace)
    asyncio.run(core.initialize(drain=False))

    packaged = Path(__file__).resolve().parents[1] / "src" / "whaxon" / "data" / "tools.json"
    assert core.catalog.path.read_bytes() == packaged.read_bytes()
    assert core.catalog.get("nmap") is not None
    assert core.catalog.get("hydra") is not None


def test_existing_operator_catalog_survives_startup_unchanged(tmp_path):
    catalog = tmp_path / "tools.json"
    contents = json.dumps({"tools": [{
        "id": "operator_tool", "name": "Operator's custom tool", "category": "test",
        "binary": "operator-unavailable-binary", "args": "{target}",
    }]}, indent=4) + "\n"
    catalog.write_text(contents, encoding="utf-8")

    for _ in range(2):
        core = Core(tmp_path)
        asyncio.run(core.initialize(drain=False))
        assert catalog.read_text(encoding="utf-8") == contents
        assert core.catalog.get("operator_tool") is not None
        assert core.catalog.get("nmap") is None


def test_gui_dependency_profile_matches_metadata_without_retired_qasync():
    import tomllib

    from whaxon.core.dependencies import load_dependency_manifest

    metadata_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with metadata_path.open("rb") as stream:
        metadata = tomllib.load(stream)
    gui_packages = metadata["project"]["optional-dependencies"]["gui"]
    assert all(not requirement.lower().startswith("qasync") for requirement in gui_packages)
    manifest = load_dependency_manifest()
    assert "qasync" not in manifest["profiles"]["gui"]
    assert not any(item["id"] == "qasync" for item in manifest["dependencies"])
    assert "PySide6" in manifest["profiles"]["gui"]
