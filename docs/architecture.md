# Architecture

WHAXON is a headless core surrounded by three interface shells and a plugin layer for tool knowledge.

## Layers

    Interfaces
      TUI (Textual)   GUI (PySide6 + QWebEngineView)
      Web (Flask + SSE + Basic auth)
      CLI (15-subcommand dispatcher)
                |
          whaxon.core.Core
            EventBus       pub/sub, async
            ToolCatalog    reads data/tools.json -> Tool dataclasses
            ScopeManager   fail-closed policy, data/scope.json
            Settings       data/settings.json
            ToolRunner     build_argv + subprocess + stream pump
            JobStore       SQLite (data/whaxon.db): jobs, findings,
                           evidence, pivot_edges
            MSFClient      pymetasploit3 RPC
                |
          whaxon.adapters
            Adapter ABC   parse(lines, ctx) -> list[Finding]
            register()    module-level self-registration
            built-ins     nmap nikto sqlmap burp hashcat impacket msf

## Data flow - one job end to end

1. Interface calls core.runner.run_tool(tool_id, target, extra_args=...).
2. ScopeManager checks target. Out of scope and no allow_out_of_scope -> OutOfScopeError, no process spawned.
3. ToolRunner.build_argv looks up the Tool, formats its args template with {target}, appends extra_args.
4. ToolRunner.run spawns the subprocess via asyncio.create_subprocess_exec, pumps stdout/stderr line by line, publishes JobStarted, JobOutput, JobFinished / JobFailed.
5. JobStore subscribes to every event and persists job, lines, findings, evidence.
6. Runner._publish_findings looks up the adapter for tool_id, calls adapter.parse(lines, ctx={tool_id, extra_args, argv, target}), publishes JobFindings.
7. Interface renders. Web streams events via SSE at /api/jobs/<id>/stream.

## Adapter contract

Adapter.parse(lines, ctx):

- lines: list[tuple[str, str]] - (stream, text), stream in {stdout, stderr}
- ctx: dict - recognized keys: tool_id, extra_args, argv, target

Returns list[Finding]. Each Finding may carry severity, CVSS, CWE, impact, remediation, references, and a structured data dict.

Adapters autodetect by content or dispatch on ctx[extra_args]. The impacket adapter uses extra_args to select the subtool (secretsdump / smbclient / wmiexec), falling back to autodetect when ctx is empty.

See adapters.md.

## Persistence

SQLite at data/whaxon.db. Tables:

- jobs: id, tool_id, target, status, exit_code, started_at, duration_s
- job_lines: stream, text per job
- findings: job_id, seq, kind, severity, data (JSON), raw_line, cvss, cwe, impact, remediation, references
- evidence: job_id, seq, kind, note/filename, blob
- pivot_edges: from_kind, from_id, relation, to_kind, to_id, evidence

The store subscribes to the EventBus so writes happen consistently regardless of which interface started the job.

## Pivot chains

/api/pivot/graph walks pivot_edges to build chains. Each edge has a relation (from_exploit, from_session, from_loot) and an evidence string. Engagement reports render the tree under ## Pivot Chains.

## Fail-closed design

Two things are deliberately strict:

1. Scope - missing scope.json writes a strict default on load; unreadable scope.json raises. Never silently allows everything. See scope.md.
2. Reports - HTML output escapes markdown before wrapping in <pre>, so a tool that prints <script> cannot inject script into a browser viewing a report.

## Extending

- New tool: add an entry to data/tools.json (id, binary, args template).
- New adapter: subclass Adapter, implement parse, register(MyAdapter()) at module level, and import it from whaxon/adapters/__init__.py.
- New interface: import Core, subscribe to the EventBus, call runner.run_tool. No core changes needed.