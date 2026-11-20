"""Create reviewable V2 plans or explicitly use legacy direct dispatch.

Usage:
    whaxon run <tool_id> <target> [options]

Options:
    --mission-id ID        mission for the V2 plan (generated if omitted)
    --plan-id ID            immutable V2 plan ID (generated if omitted)
    --legacy                use the old direct-dispatch path explicitly
    --extra "..."          extra arguments passed to the tool
    --data DIR             data directory (default: ./data)
    --timeout SEC          hard timeout in seconds (default: 300)
    --allow-out-of-scope   bypass the scope check for this run
    --quiet                suppress live output (just findings at the end)
    --verbose              print internal state, argv, and full untruncated findings
    --json                 emit findings as JSON to stdout at the end
"""
from __future__ import annotations

import asyncio
import json
import shlex
import sys
import uuid
from pathlib import Path

from whaxon.core import Core
from whaxon.core.events import JobFailed, JobFindings, JobFinished, JobOutput, JobStarted
from whaxon.core.scope import OutOfScopeError

EXIT_OK = 0
EXIT_TOOL_ERROR = 1
EXIT_OUT_OF_SCOPE = 2
EXIT_UNKNOWN_TOOL = 3
EXIT_USAGE = 64


def _usage() -> None:
    print("Usage: whaxon run <tool_id> <target> [--data DIR] "
          "[--mission-id ID] [--plan-id ID]")
    print()
    print("  Creates and saves a provider-pinned Engine V2 plan for operator review.")
    print("  V2: whaxon run --v2-plan <existing-plan-id> [--data DIR]")
    print("  V2 requires a persisted plan and task approvals; no legacy fallback.")
    print("  Legacy direct dispatch is explicit: whaxon run <tool_id> <target> --legacy")
    print("  Examples:")
    print("    whaxon run nmap 10.0.0.5")
    print("    whaxon run nmap 10.0.0.5 --legacy --quiet --json")
    print("    whaxon run nikto 10.0.0.5 --legacy --extra \"-p 80,443\"")


def _print_findings(findings, as_json: bool, verbose: bool = False) -> None:
    if as_json:
        print(json.dumps(findings, indent=2, default=str))
        return
    if not findings:
        print()
        print("[no findings]")
        return
    print()
    print(f"[{len(findings)} findings]")
    for f in findings:
        if hasattr(f, "to_dict"):
            f = f.to_dict()
        sev = (f.get("severity") or "info").upper()
        kind = f.get("kind") or "?"
        raw = (f.get("raw_line") or "").strip().replace("\n", " ")
        if not verbose:
            raw = raw[:120]
        print(f"  [{sev:8s}] {kind:20s} {raw}")


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        _usage()
        return

    # Positional: tool_id, target
    tool_id = args[0]
    if len(args) < 2 or args[1].startswith("--"):
        print("error: whaxon run requires a <tool_id> and a <target>", file=sys.stderr)
        _usage()
        sys.exit(EXIT_USAGE)
    target = args[1]

    extra_args = ""
    data_dir = Path("data")
    mission_id = None
    plan_id = None
    timeout_s = 300.0
    allow_out_of_scope = False
    quiet = False
    as_json = False
    verbose = False
    timeout_explicit = False
    legacy = False

    i = 2
    while i < len(args):
        a = args[i]
        if a == "--extra" and i + 1 < len(args):
            extra_args = args[i + 1]; i += 2
        elif a == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif a == "--timeout" and i + 1 < len(args):
            try:
                timeout_s = float(args[i + 1])
                timeout_explicit = True
            except ValueError:
                print(f"error: --timeout expects a number, got {args[i+1]!r}", file=sys.stderr)
                sys.exit(EXIT_USAGE)
            i += 2
        elif a == "--allow-out-of-scope":
            allow_out_of_scope = True; i += 1
        elif a == "--quiet":
            quiet = True; i += 1
        elif a == "--json":
            as_json = True; i += 1
        elif a == "--verbose":
            verbose = True; i += 1
        elif a == "--legacy":
            legacy = True; i += 1
        elif a == "--mission-id" and i + 1 < len(args):
            mission_id = args[i + 1]; i += 2
        elif a == "--plan-id" and i + 1 < len(args):
            plan_id = args[i + 1]; i += 2
        else:
            print(f"Unknown arg: {a}", file=sys.stderr)
            sys.exit(EXIT_USAGE)

    # Explicit migration bridge: execute only an already persisted V2 plan.
    # No implicit plan creation, approval, target inference or legacy fallback.
    if tool_id == "--v2-plan":
        if (legacy or extra_args or allow_out_of_scope or timeout_explicit or verbose
                or quiet or as_json or mission_id or plan_id):
            print("error: V2 execution refuses legacy argument/scope overrides", file=sys.stderr)
            sys.exit(EXIT_USAGE)
        from whaxon.interfaces.cli import workflow_cmd
        result = workflow_cmd.main([
            "--data-dir", str(data_dir), "plan", "run", "--id", target,
        ])
        if result:
            sys.exit(result)
        return

    if legacy and (mission_id or plan_id):
        print("error: --mission-id and --plan-id apply only to V2 plan creation", file=sys.stderr)
        sys.exit(EXIT_USAGE)

    if not legacy:
        if extra_args or allow_out_of_scope or timeout_explicit or verbose or quiet or as_json:
            print(
                "error: direct-dispatch options require --legacy; default `whaxon run` "
                "creates a reviewable V2 plan",
                file=sys.stderr,
            )
            sys.exit(EXIT_USAGE)
        mission_id = mission_id or f"mission-{uuid.uuid4().hex}"
        plan_id = plan_id or f"plan-{uuid.uuid4().hex}"
        if any(not value.strip() or value != value.strip() for value in (mission_id, plan_id)):
            print("error: mission and plan IDs must be normalized non-empty text", file=sys.stderr)
            sys.exit(EXIT_USAGE)
        core = Core(data_dir=data_dir)
        if core.catalog.get(tool_id) is None:
            available = sorted(tool.id for tool in core.catalog.list())
            print(f"error: unknown tool {tool_id!r}", file=sys.stderr)
            if available:
                print(f"  available: {', '.join(available)}", file=sys.stderr)
            sys.exit(EXIT_UNKNOWN_TOOL)

        async def _propose():
            await core.initialize(drain=False)
            core.create_mission(
                mission_id,
                f"Operator-requested {tool_id} assessment of {target}",
                metadata={"created_by": "whaxon run"},
            )
            from whaxon.core.workflow_proposals import propose_tool_workflow_plan
            proposal = propose_tool_workflow_plan(
                core,
                mission_id=mission_id,
                plan_id=plan_id,
                tool_id=tool_id,
                target=target,
            )
            if proposal.get("status") == "proposed":
                from whaxon.core.workflow import WorkflowPlan
                proposal["created"] = core.save_workflow_plan(
                    plan_id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            return proposal

        try:
            proposal = asyncio.run(_propose())
        except (OutOfScopeError, OSError, ValueError, TypeError, RuntimeError) as exc:
            print(f"error: unable to create Engine V2 plan: {exc}", file=sys.stderr)
            sys.exit(EXIT_TOOL_ERROR)
        if proposal.get("status") != "proposed" or not proposal.get("created"):
            print(json.dumps(proposal, indent=2, sort_keys=True))
            sys.exit(EXIT_TOOL_ERROR)
        next_commands = [
            shlex.join([
                "whaxon", "workflow", "--data-dir", str(data_dir),
                "plan", "show", "--id", plan_id,
            ]),
            shlex.join([
                "whaxon", "workflow", "--data-dir", str(data_dir),
                "plan", "approval", "grant", "--id", plan_id,
                "--task", "task-1", "--approval-id", "<approval-id>",
                "--actor", "<operator>", "--expires-at", "<unix-time>",
            ]),
            shlex.join([
                "whaxon", "run", "--v2-plan", plan_id,
                "--data", str(data_dir),
            ]),
        ]
        print(json.dumps({
            "status": "plan_saved_for_review",
            "mission_id": mission_id,
            "plan_id": plan_id,
            "digest": proposal["digest"],
            "capability_id": proposal["capability_id"],
            "provider_id": proposal["provider_id"],
            "execution_submitted": False,
            "approval_granted": False,
            "next": next_commands,
        }, indent=2, sort_keys=True))
        return

    core = Core(data_dir=data_dir)

    # Validate the tool before running
    tool = core.catalog.get(tool_id)
    if tool is None:
        available = sorted(t.id for t in core.catalog.list())
        print(f"error: unknown tool {tool_id!r}", file=sys.stderr)
        if available:
            print(f"  available: {', '.join(available)}", file=sys.stderr)
        sys.exit(EXIT_UNKNOWN_TOOL)

    if verbose:
        print(f"[verbose] tool_id={tool_id!r} target={target!r}", file=sys.stderr)
        print(f"[verbose] extra_args={extra_args!r}", file=sys.stderr)
        print(f"[verbose] timeout={timeout_s}s allow_out_of_scope={allow_out_of_scope}", file=sys.stderr)

    # Subscribe to job events for live streaming. We only care about the
    # job we're about to run; the runner will fire events through the bus.
    state: dict = {"job_id": None, "findings": []}

    def _on_started(e):
        state["job_id"] = e.job_id
        if not quiet:
            print(f"[run] {e.tool_id} → {e.target}  (job {e.job_id})", file=sys.stderr)

    def _on_output(e):
        if quiet:
            return
        stream = sys.stdout if e.stream == "stdout" else sys.stderr
        print(e.line, file=stream, flush=True)

    def _on_finished(e):
        if not quiet:
            print(f"[run] finished: exit={e.exit_code} in {e.duration_s:.2f}s",
                  file=sys.stderr)

    def _on_failed(e):
        print(f"[run] failed: {e.error}", file=sys.stderr)

    def _on_findings(e):
        state["findings"] = list(e.findings)

    core.bus.subscribe(JobStarted, _on_started)
    core.bus.subscribe(JobOutput, _on_output)
    core.bus.subscribe(JobFinished, _on_finished)
    core.bus.subscribe(JobFailed, _on_failed)
    core.bus.subscribe(JobFindings, _on_findings)

    async def _go():
        await core.initialize(drain=False)
        if verbose:
            try:
                match = core.scope.check(target) if core.scope else None
                if match is not None:
                    print(f"[verbose] scope: allowed={match.allowed} rule={match.matched_rule!r} reason={match.reason!r}", file=sys.stderr)
            except Exception as e:
                print(f"[verbose] scope check raised: {e!r}", file=sys.stderr)
        # Session-shaped targets skip the pre-dispatch scope check;
        # the transport does its own check on the extracted host.
        if (target.startswith("session:")
                or target.startswith("ssh:")
                or target.startswith("smb:")):
            if not allow_out_of_scope:
                print("[run] session target; scope is enforced by the session transport")
            result = await core.runner.run_in_session(
                tool_id, target, extra_args=extra_args,
                timeout_s=timeout_s,
            )
        else:
            if verbose:
                try:
                    argv = core.runner.build_argv(tool_id, target, extra_args=extra_args)
                    print(f"[verbose] argv: {argv!r}", file=sys.stderr)
                except Exception as e:
                    print(f"[verbose] build_argv raised: {e!r}", file=sys.stderr)
            result = await core.runner.run_tool(
                tool_id, target,
                extra_args=extra_args,
                timeout_s=timeout_s,
                allow_out_of_scope=allow_out_of_scope,
            )

        # EventBus delivers findings subscribers (including Automator) on this
        # loop. Give them a turn to persist any follow-up jobs before closing it.
        await asyncio.sleep(0)
        state["primary_job_id"] = state.get("job_id")
        state["primary_findings"] = list(state.get("findings") or [])
        # Drain only follow-ups caused by this source job. Global queue draining
        # here could claim unrelated work enqueued by another producer mid-run.
        automator = getattr(core, "automator", None)
        take_followups = getattr(automator, "take_queued_followups", None)
        followup_ids = (
            take_followups(state["primary_job_id"])
            if callable(take_followups) and state["primary_job_id"] else set()
        )
        from whaxon.core.worker import drain_async
        state["drained_jobs"] = await drain_async(
            core.store, core.runner, include_ids=followup_ids,
        )
        return result


    try:
        asyncio.run(_go())
    except OutOfScopeError as e:
        print(f"error: target out of scope: {e.reason}", file=sys.stderr)
        if e.matched_rule:
            print(f"  matched rule: {e.matched_rule}", file=sys.stderr)
        if e.overridable:
            print(f"  override with: whaxon run {tool_id} {target} --allow-out-of-scope",
                  file=sys.stderr)
        else:
            print("  this execution block cannot be overridden", file=sys.stderr)
        sys.exit(EXIT_OUT_OF_SCOPE)
    except FileNotFoundError as e:
        print(f"error: tool binary not found: {e}", file=sys.stderr)
        sys.exit(EXIT_TOOL_ERROR)
    except KeyboardInterrupt:
        print("[run] interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(EXIT_TOOL_ERROR)

    job_id = state.get("primary_job_id", state.get("job_id"))
    findings = state.get("primary_findings", state.get("findings") or [])
    drained = state.get("drained_jobs", 0)
    if drained and not quiet:
        print(f"[run] auto-chain: completed {drained} queued job(s)", file=sys.stderr)
    # Worker events may include other job IDs/findings; keep this command's
    # report attached to the initial tool execution.
    state["job_id"] = job_id
    state["findings"] = findings

    # Load findings from the store if the event didn't fire (e.g. tool
    # produced no findings, or the adapter errored)
    if job_id and not findings:
        findings = core.store.get_findings(job_id) or []

    _print_findings(findings, as_json, verbose)

    if job_id and not as_json:
        print()
        print(f"job: {job_id}")
        print(f"report: whaxon report {job_id}")


if __name__ == "__main__":
    main()
