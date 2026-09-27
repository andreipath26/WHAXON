"""whaxon ai <goal> — autonomous planner run."""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from whaxon.core import Core
from whaxon.core.ai_bridge import build_executor
from whaxon.ai.actions import Action, ActionResult


def _print_action(a: Action, step: int) -> None:
    tag = a.ai_source or "ai"
    print(f"[{step}] {tag} -> {a.kind}"
          + (f" {a.tool_id}@{a.target}" if a.tool_id else ""))
    if a.rationale:
        print(f"      reason: {a.rationale}")


def _print_result(r: ActionResult) -> None:
    if r.job_id:
        print(f"      job: {r.job_id}")
    if r.findings:
        print(f"      findings: {len(r.findings)}")
    if r.error:
        print(f"      error: {r.error}")


def main(args: list[str] | None = None) -> None:
    args = list(sys.argv[2:] if args is None else args)
    if not args or args[0] in ("-h", "--help"):
        print("usage: whaxon ai \"<goal>\" [--data DIR] [--max-steps N]")
        return
    goal = args[0]
    data_dir = Path(os.environ.get("WHAXON_DATA", "data"))
    max_steps = 12
    i = 1
    while i < len(args):
        if args[i] == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif args[i] == "--max-steps" and i + 1 < len(args):
            max_steps = int(args[i + 1]); i += 2
        else:
            i += 1

    core = Core(data_dir=data_dir)
    from whaxon.ai import ExecutorLimits
    import uuid as _uuid
    run_id = "ai-" + _uuid.uuid4().hex[:12]
    core.store.create_ai_run(run_id, goal)
    ex = build_executor(core, limits=ExecutorLimits(max_steps=max_steps),
                        on_action=lambda a: None)

    step_counter = {"n": 0}
    def on_action(a):
        step_counter["n"] += 1
        _print_action(a, step_counter["n"])
    def on_result(r):
        _print_result(r)
        core.store.append_ai_run_step(run_id, step_counter["n"], r.action.to_dict(), r.to_dict())
    ex.on_action = on_action
    ex.on_result = on_result

    print(f"goal: {goal}")
    print(f"run:  {run_id}")
    print(f"data: {data_dir}")
    print()
    try:
        history = asyncio.run(ex.run(goal, job_id_prefix=run_id))
        last_err = ""
        if history and not history[-1].ok:
            last_err = history[-1].error or ""
        core.store.set_ai_run_finished(run_id, status="done" if not last_err else "failed", error=last_err)
    except Exception as e:
        core.store.set_ai_run_finished(run_id, status="error", error=repr(e))
        raise
    print()
    print(f"done: {len(history)} step(s)")