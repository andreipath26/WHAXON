"""Cross-run summary — deterministic, no LLM. Design ref: agent-arch §11."""
from __future__ import annotations

from typing import Any


def summarize(store, target: str, limit: int = 5) -> dict[str, Any]:
    empty = {"target": target, "run_count": 0,
             "tools_used": [], "successful_tools": [],
             "last_phase": "recon"}
    if not target:
        return empty
    try:
        from whaxon.core.targets import extract_target
    except Exception:
        extract_target = None
    try:
        runs = store.list_ai_runs(limit=limit * 3) or []
    except Exception:
        return empty
    matching = []
    for r in runs:
        goal = (r.get("goal") or "").strip()
        if not goal:
            continue
        if extract_target is not None:
            t = extract_target(goal)
            if t and t == target:
                matching.append(r)
        elif target in goal:
            matching.append(r)
        if len(matching) >= limit:
            break
    if not matching:
        return empty
    tools_used = set()
    successful_tools = set()
    last_phase = "recon"
    for r in matching:
        rid = r.get("id")
        if not rid:
            continue
        try:
            full = store.get_ai_run(rid) or {}
        except Exception:
            continue
        p = full.get("phase") or r.get("phase")
        if p:
            last_phase = p
        for step in (full.get("steps") or []):
            action = step.get("action") or {}
            if action.get("kind") != "run_tool":
                continue
            tool_id = action.get("tool_id")
            if not tool_id:
                continue
            tools_used.add(tool_id)
            if (step.get("result") or {}).get("ok"):
                successful_tools.add(tool_id)
    return {
        "target": target,
        "run_count": len(matching),
        "tools_used": sorted(tools_used),
        "successful_tools": sorted(successful_tools),
        "last_phase": last_phase,
    }
