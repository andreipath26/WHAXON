"""LLMProvider payload slimming — step 27.

The planner prompt promises a slim CATALOG (id/name/category) and a
slim HISTORY (kind/tool_id/target/ok/summary/error). These tests lock
that shape in, since the code previously sent raw asdict entries and
full ActionResult dicts including the findings array.
"""
from __future__ import annotations

from whaxon.ai.providers.llm import (
    _slim_catalog,
    _slim_history,
    _HISTORY_KEEP,
    _TRUNCATE_CHARS,
)


def test_slim_catalog_keeps_only_promised_fields() -> None:
    fat = [{
        "id": "nmap", "name": "Nmap", "category": "scan",
        "args": "{target}", "binary": "/usr/bin/nmap",
        "outfile_flag": None, "extra": "noise",
    }]
    slim = _slim_catalog(fat)
    assert slim == [{"id": "nmap", "name": "Nmap", "category": "scan"}]


def test_slim_catalog_empty_and_none() -> None:
    assert _slim_catalog([]) == []
    assert _slim_catalog(None) == []


def test_slim_history_drops_findings_and_job_id() -> None:
    hist = [{
        "action": {"kind": "run_tool", "tool_id": "nmap", "target": "1.2.3.4"},
        "ok": True,
        "job_id": "ai-1-nmap",
        "summary": "nmap ran",
        "findings": [{"port": 80}] * 50,
        "error": "",
    }]
    slim = _slim_history(hist)
    assert len(slim) == 1
    e = slim[0]
    assert e["kind"] == "run_tool"
    assert e["tool_id"] == "nmap"
    assert e["target"] == "1.2.3.4"
    assert e["ok"] is True
    assert e["summary"] == "nmap ran"
    assert e["error"] == ""
    assert "findings" not in e
    assert "job_id" not in e


def test_slim_history_truncates_long_summary() -> None:
    long_summary = "x" * 500
    hist = [{
        "action": {"kind": "run_tool", "tool_id": "nmap", "target": "1.2.3.4"},
        "ok": True, "summary": long_summary, "error": "",
    }]
    slim = _slim_history(hist)
    assert len(slim[0]["summary"]) == _TRUNCATE_CHARS + 3  # 120 + "..."


def test_slim_history_keeps_last_n_with_omitted_sentinel() -> None:
    hist = [
        {"action": {"kind": "run_tool", "tool_id": f"t{i}", "target": "h"},
         "ok": True, "summary": f"s{i}", "error": ""}
        for i in range(10)
    ]
    slim = _slim_history(hist)
    # 1 sentinel + last _HISTORY_KEEP entries
    assert len(slim) == _HISTORY_KEEP + 1
    assert slim[0] == {"_omitted": 10 - _HISTORY_KEEP}
    # Order preserved: sentinel, then oldest-kept through newest
    assert slim[1]["tool_id"] == f"t{10 - _HISTORY_KEEP}"
    assert slim[-1]["tool_id"] == "t9"


def test_slim_history_under_limit_has_no_sentinel() -> None:
    hist = [
        {"action": {"kind": "run_tool", "tool_id": "nmap", "target": "h"},
         "ok": True, "summary": "s", "error": ""}
        for _ in range(3)
    ]
    slim = _slim_history(hist)
    assert len(slim) == 3
    assert all("_omitted" not in e for e in slim)


def test_slim_history_handles_missing_action() -> None:
    slim = _slim_history([{"ok": False, "summary": "", "error": "boom"}])
    assert len(slim) == 1
    assert slim[0]["kind"] is None
    assert slim[0]["tool_id"] is None
    assert slim[0]["error"] == "boom"


def test_slim_history_empty_and_none() -> None:
    assert _slim_history([]) == []
    assert _slim_history(None) == []