"""Report includes an AI Runs section with phase information (session 28)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from whaxon.core import report as _report
from whaxon.core.store import JobStore


@pytest.fixture
def store(tmp_path: Path) -> JobStore:
    return JobStore(tmp_path / "db.sqlite")


def test_load_ai_runs_empty(store: JobStore) -> None:
    assert _report._load_ai_runs(store) == []


def test_load_ai_runs_includes_phase_and_history(store: JobStore) -> None:
    store.create_ai_run("ai-1", "enumerate 10.0.0.5", phase="recon")
    store.set_ai_run_phase("ai-1", "enumeration")
    store.set_ai_run_phase("ai-1", "vulnerability")
    runs = _report._load_ai_runs(store)
    assert len(runs) == 1
    r = runs[0]
    assert r["id"] == "ai-1"
    assert r["goal"] == "enumerate 10.0.0.5"
    assert r["phase"] == "vulnerability"
    hist = json.loads(r["phase_history"])
    assert len(hist) == 2
    assert hist[0]["phase"] == "enumeration"
    assert hist[1]["phase"] == "vulnerability"


def test_md_ai_runs_section_with_runs() -> None:
    md: list[str] = []
    runs = [{
        "id": "ai-x",
        "goal": "test goal",
        "status": "done",
        "phase": "enumeration",
        "phase_history": json.dumps([
            {"phase": "enumeration"}, {"phase": "vulnerability"},
        ]),
        "step_count": 4,
    }]
    _report._md_ai_runs(md, runs)
    text = "\n".join(md)
    assert "## AI Runs" in text
    assert "ai-x" in text
    assert "test goal" in text
    assert "enumeration" in text
    # Phase history line appears when >1 entries
    assert "enumeration -> vulnerability" in text


def test_md_ai_runs_omitted_when_empty() -> None:
    md: list[str] = []
    _report._md_ai_runs(md, [])
    assert md == []


def test_load_returns_ai_runs_key(store: JobStore) -> None:
    store.create_ai_run("ai-z", "goal z")
    data = _report._load(store, "default")
    assert "ai_runs" in data
    assert isinstance(data["ai_runs"], list)
    assert len(data["ai_runs"]) == 1
    assert data["ai_runs"][0]["id"] == "ai-z"


def test_to_markdown_includes_ai_runs_section(store: JobStore) -> None:
    store.create_ai_run("ai-m", "goal m")
    data = _report._load(store, "default")
    md = _report.to_markdown(data, chains=[], lookup=False)
    assert "## AI Runs" in md
    assert "ai-m" in md
    # Section sits before Job History
    assert md.index("## AI Runs") < md.index("## Job History")


def test_to_markdown_omits_ai_runs_when_none(store: JobStore) -> None:
    data = _report._load(store, "default")
    md = _report.to_markdown(data, chains=[], lookup=False)
    assert "## AI Runs" not in md