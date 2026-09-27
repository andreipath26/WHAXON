"""Suggester: adapter advice -> persisted suggestion findings."""
from __future__ import annotations

from pathlib import Path

from whaxon.adapters.base import Adapter
from whaxon.core.events import EventBus, JobFindings
from whaxon.core.store import JobStore
from whaxon.core.suggester import Suggester


class AdviceAdapter(Adapter):
    tool_id = "advice"
    def parse(self, lines, ctx=None):
        return []
    def suggest_next_steps(self, finding):
        return [("Try nikto", "nikto", ""), ("Try gobuster", "gobuster", "")]


def _mk_store(tmp_path: Path) -> JobStore:
    return JobStore(tmp_path / "db.sqlite")


def test_suggester_persists_advice(tmp_path: Path) -> None:
    bus = EventBus()
    store = _mk_store(tmp_path)
    store.create("j1")
    adapter = AdviceAdapter()
    s = Suggester(bus, store, lambda tid: adapter if tid == "advice" else None)
    s.attach()
    bus.publish(JobFindings(job_id="j1", findings=(
        {"kind": "open_port", "severity": "info", "source": "advice",
         "data": {"port": 80}, "raw_line": ""},
    )))
    fs = store.get_findings("j1") or []
    kinds = [f["kind"] for f in fs]
    assert kinds.count("suggestion") == 2
    tools = sorted(f["data"]["tool"] for f in fs if f["kind"] == "suggestion")
    assert tools == ["gobuster", "nikto"]


def test_suggester_no_adapter_is_noop(tmp_path: Path) -> None:
    bus = EventBus()
    store = _mk_store(tmp_path)
    store.create("j2")
    s = Suggester(bus, store, lambda tid: None)
    s.attach()
    bus.publish(JobFindings(job_id="j2", findings=(
        {"kind": "open_port", "severity": "info", "source": "ghost",
         "data": {}, "raw_line": ""},
    )))
    fs = store.get_findings("j2") or []
    assert all(f["kind"] != "suggestion" for f in fs)
