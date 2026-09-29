"""whaxon ai <goal> — autonomous planner run, with --resume support."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from whaxon.core import Core
from whaxon.core.ai_bridge import build_executor
from whaxon.ai.actions import Action, ActionResult


def _print_action(a: Action, step: int) -> None:
    tag = a.ai_source or "ai"
    line = f"[{step}] {tag} -> {a.kind}"
    if a.tool_id:
        line += f" {a.tool_id}@{a.target}" if a.target else f" {a.tool_id}@session:{a.session_id}"
    print(line)
    if a.rationale:
        print(f"      reason: {a.rationale}")


def _print_result(r: ActionResult) -> None:
    if r.job_id:
        print(f"      job: {r.job_id}")
    if r.findings:
        print(f"      findings: {len(r.findings)}")
    if r.error:
        print(f"      error: {r.error}")


def _stdin_ask_human(action: Action) -> str:
    """Prompt the human for an answer. Returns y / n / skip / freeform text."""
    print()
    print(f"[ai] asking: {action.rationale or 'need input'}")
    if action.confidence:
        print(f"[ai] confidence: {action.confidence:.2f}")
    try:
        return input("[ai] approve? [y/n/skip/text] > ").strip()
    except EOFError:
        return "skip"


def _question_json(action: Action) -> str:
    """Serialise the pending ask_human Action for storage."""
    return json.dumps({
        "kind": action.kind,
        "rationale": action.rationale,
        "confidence": action.confidence,
        "proposed_phase": action.proposed_phase,
        "session_id": action.session_id,
    })


def _run_fresh(goal: str, data_dir: Path, max_steps: int, target_lock):
    from whaxon.ai import ExecutorLimits
    import uuid as _uuid
    core = Core(data_dir=data_dir)
    run_id = "ai-" + _uuid.uuid4().hex[:12]
    core.store.create_ai_run(run_id, goal)

    async def _ask(action: Action) -> str:
        return await asyncio.to_thread(_stdin_ask_human, action)

    ex = build_executor(core, limits=ExecutorLimits(max_steps=max_steps),
                        on_action=lambda a: None, target_lock=target_lock,
                        ask_human=_ask, ai_run_id=run_id)

    step_counter = {"n": 0}

    def on_action(a):
        step_counter["n"] += 1
        _print_action(a, step_counter["n"])

    def on_result(r):
        _print_result(r)
        core.store.append_ai_run_step(
            run_id, step_counter["n"], r.action.to_dict(), r.to_dict(),
        )

    ex.on_action = on_action
    ex.on_result = on_result

    print(f"goal: {goal}")
    print(f"run:  {run_id}")
    print(f"data: {data_dir}")
    if target_lock:
        print(f"lock: {target_lock}")
    print()
    try:
        history = asyncio.run(ex.run(goal, job_id_prefix=run_id))
    except Exception as e:
        core.store.set_ai_run_finished(run_id, status="error", error=repr(e))
        raise
    _finalise(core, run_id, history, ex)
    print()
    print(f"done: {len(history)} step(s)")
    return run_id


def _record_usage(core: Core, run_id: str, executor) -> None:
    """Write tokens + cost to the store if the provider tracked them."""
    if executor is None:
        return
    try:
        provider = executor.agent.provider
    except Exception:
        return
    usage = getattr(provider, "usage", None)
    if not isinstance(usage, dict):
        return
    tin = int(usage.get("tokens_in", 0) or 0)
    tout = int(usage.get("tokens_out", 0) or 0)
    if tin == 0 and tout == 0:
        return
    cost = None
    try:
        from whaxon.ai.costs import estimate_cost
        model = getattr(provider, "model_name", None) or getattr(
            getattr(provider, "backend", None), "model", "")
        if model:
            cost = estimate_cost(model, tin, tout)
    except Exception:
        cost = None
    try:
        core.store.set_ai_run_usage(run_id, tin, tout, cost)
    except Exception:
        pass


def _finalise(core: Core, run_id: str, history: list[ActionResult], executor=None) -> None:
    """Mark the run done, failed, or waiting based on the last step."""
    _record_usage(core, run_id, executor)
    if not history:
        core.store.set_ai_run_finished(run_id, status="done")
        return
    last = history[-1]
    if last.action.kind == "ask_human":
        core.store.set_ai_run_waiting(run_id, _question_json(last.action))
        print()
        print(f"paused: awaiting human input for {run_id}")
        print(f"resume with: whaxon ai --resume {run_id} --answer <y|n|skip|text>")
        return
    last_err = "" if last.ok else (last.error or "")
    core.store.set_ai_run_finished(
        run_id, status="done" if not last_err else "failed", error=last_err,
    )


def _run_resume(run_id: str, data_dir: Path, max_steps: int, answer: str):
    from whaxon.ai import ExecutorLimits
    core = Core(data_dir=data_dir)
    run = core.store.get_ai_run(run_id)
    if run is None:
        print(f"no such run: {run_id}", file=sys.stderr)
        sys.exit(1)
    goal = run.get("goal") or ""
    steps = run.get("steps") or []
    if not steps:
        print(f"run {run_id} has no steps to resume from", file=sys.stderr)
        sys.exit(1)

    # Build initial history from stored steps, converting each step's
    # action/result dicts back into ActionResult objects.
    initial: list[ActionResult] = []
    for s in steps:
        action = Action(**{k: v for k, v in (s.get("action") or {}).items()
                           if k in ("kind", "tool_id", "target", "extra_args",
                                    "rationale", "confidence", "ai_source",
                                    "proposed_phase", "session_id")})
        result = ActionResult(action=action,
                              ok=bool(s.get("result", {}).get("ok")),
                              job_id=s.get("result", {}).get("job_id"),
                              summary=s.get("result", {}).get("summary", ""),
                              findings=s.get("result", {}).get("findings") or [],
                              error=s.get("result", {}).get("error", ""))

        # The last stored step should be the ask_human that paused the run.
        # Convert it to the synthetic ack the loop expects, using the
        # supplied --answer, so the loop's next step sees the human's reply.
        if s is steps[-1] and action.kind == "ask_human":
            initial.append(result)
            ack = ActionResult(
                action=Action.stop(
                    rationale=f"human answered: {answer!r}",
                    ai_source="human"),
                ok=True,
                summary=answer,
            )
            initial.append(ack)
        else:
            initial.append(result)

    # The next real step number is len(initial) + 1 (the loop computes it).

    async def _ask(action: Action) -> str:
        # On resume, the first ask has already been answered from the
        # command line; subsequent asks prompt interactively.
        return await asyncio.to_thread(_stdin_ask_human, action)

    ex = build_executor(core, limits=ExecutorLimits(max_steps=max_steps),
                        on_action=lambda a: None,
                        ask_human=_ask, ai_run_id=run_id)

    step_counter = {"n": len(initial)}

    def on_action(a):
        step_counter["n"] += 1
        _print_action(a, step_counter["n"])

    def on_result(r):
        _print_result(r)
        core.store.append_ai_run_step(
            run_id, step_counter["n"], r.action.to_dict(), r.to_dict(),
        )

    ex.on_action = on_action
    ex.on_result = on_result

    print(f"resume: {run_id}")
    print(f"goal:   {goal}")
    print(f"answer: {answer!r}")
    print()
    try:
        history = asyncio.run(ex.run(goal, job_id_prefix=run_id,
                                     initial_history=initial))
    except Exception as e:
        core.store.set_ai_run_finished(run_id, status="error", error=repr(e))
        raise
    _finalise(core, run_id, history, ex)
    print()
    print(f"done: {len(history)} step(s)")


def main(args: list[str] | None = None) -> None:
    args = list(sys.argv[2:] if args is None else args)
    if not args or args[0] in ("-h", "--help"):
        print('usage: whaxon ai "<goal>" [--data DIR] [--max-steps N] [--target HOST]')
        print('       whaxon ai --resume <run_id> --answer <text> [--data DIR] [--max-steps N]')
        return

    data_dir = Path(os.environ.get("WHAXON_DATA", "data"))
    max_steps = 12
    target_lock = None
    resume_id: str | None = None
    answer: str | None = None
    goal: str | None = None

    i = 0
    while i < len(args):
        if args[i] == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif args[i] == "--max-steps" and i + 1 < len(args):
            max_steps = int(args[i + 1]); i += 2
        elif args[i] == "--target" and i + 1 < len(args):
            target_lock = args[i + 1]; i += 2
        elif args[i] == "--resume" and i + 1 < len(args):
            resume_id = args[i + 1]; i += 2
        elif args[i] == "--answer" and i + 1 < len(args):
            answer = args[i + 1]; i += 2
        elif not args[i].startswith("--") and goal is None:
            goal = args[i]; i += 1
        else:
            i += 1

    if resume_id is not None:
        if answer is None:
            print("--resume requires --answer <text>", file=sys.stderr)
            sys.exit(2)
        _run_resume(resume_id, data_dir, max_steps, answer)
        return

    if goal is None:
        print('usage: whaxon ai "<goal>" [--data DIR] [--max-steps N] [--target HOST]')
        return

    if target_lock is None:
        from whaxon.core.targets import extract_target
        target_lock = extract_target(goal)
    _run_fresh(goal, data_dir, max_steps, target_lock)