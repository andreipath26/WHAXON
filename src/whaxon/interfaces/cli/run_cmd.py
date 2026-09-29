"""whaxon run <tool> <target> — execute a catalog tool from the CLI.

Streams stdout/stderr live as the tool runs. Persists to the store the
same way the TUI and web UI do. Prints a findings summary on finish.

Usage:
    whaxon run <tool_id> <target> [options]

Options:
    --extra "..."          extra arguments passed to the tool
    --data DIR             data directory (default: ./data)
    --timeout SEC          hard timeout in seconds (default: 300)
    --allow-out-of-scope   bypass the scope check for this run
    --quiet                suppress live output (just findings at the end)
    --json                 emit findings as JSON to stdout at the end
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from whaxon.core import Core
from whaxon.core.events import JobFailed, JobFinished, JobFindings, JobOutput, JobStarted
from whaxon.core.scope import OutOfScopeError


EXIT_OK = 0
EXIT_TOOL_ERROR = 1
EXIT_OUT_OF_SCOPE = 2
EXIT_UNKNOWN_TOOL = 3
EXIT_USAGE = 64


def _usage() -> None:
    print("Usage: whaxon run <tool_id> <target> [--extra \"...\"] [--data DIR] "
          "[--timeout SEC] [--allow-out-of-scope] [--quiet] [--json]")
    print()
    print("  Runs a catalog tool against a target, streaming output live.")
    print("  Examples:")
    print("    whaxon run nmap 10.0.0.5")
    print("    whaxon run nikto 10.0.0.5 --extra \"-p 80,443\"")
    print("    whaxon run nmap 10.0.0.5 --quiet --json")


def _print_findings(findings, as_json: bool) -> None:
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
        raw = (f.get("raw_line") or "").strip().replace("\n", " ")[:120]
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
    timeout_s = 300.0
    allow_out_of_scope = False
    quiet = False
    as_json = False

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
        else:
            print(f"Unknown arg: {a}", file=sys.stderr)
            sys.exit(EXIT_USAGE)

    core = Core(data_dir=data_dir)

    # Validate the tool before running
    tool = core.catalog.get(tool_id)
    if tool is None:
        available = sorted(t.id for t in core.catalog.list())
        print(f"error: unknown tool {tool_id!r}", file=sys.stderr)
        if available:
            print(f"  available: {', '.join(available)}", file=sys.stderr)
        sys.exit(EXIT_UNKNOWN_TOOL)

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
        await core.initialize()
        # Session-shaped targets skip the pre-dispatch scope check;
        # the transport does its own check on the extracted host.
        if (target.startswith("session:")
                or target.startswith("ssh:")
                or target.startswith("smb:")):
            if not allow_out_of_scope:
                print("[run] session target; scope is enforced by the session transport")
            return await core.runner.run_in_session(
                tool_id, target, extra_args=extra_args,
                timeout_s=timeout_s,
            )
        return await core.runner.run_tool(
            tool_id, target,
            extra_args=extra_args,
            timeout_s=timeout_s,
            allow_out_of_scope=allow_out_of_scope,
        )

    try:
        asyncio.run(_go())
    except OutOfScopeError as e:
        print(f"error: target out of scope: {e.reason}", file=sys.stderr)
        if e.matched_rule:
            print(f"  matched rule: {e.matched_rule}", file=sys.stderr)
        print(f"  override with: whaxon run {tool_id} {target} --allow-out-of-scope",
              file=sys.stderr)
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

    job_id = state.get("job_id")
    findings = state.get("findings") or []

    # Load findings from the store if the event didn't fire (e.g. tool
    # produced no findings, or the adapter errored)
    if job_id and not findings:
        findings = core.store.get_findings(job_id) or []

    _print_findings(findings, as_json)

    if job_id and not as_json:
        print()
        print(f"job: {job_id}")
        print(f"report: whaxon report {job_id}")


if __name__ == "__main__":
    main()