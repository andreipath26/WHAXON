# Session-Based Execution

**Status:** Design document. No code in this file is implemented yet.
**Scope:** Post-exploitation primitives that run *inside* a session, not *against* a host.
**Non-goals:** Changing the pipeline, the executor's deterministic boundary, or the existing MSF module-execution path.

## 1. Purpose

Every tool WHAXON can run today executes the same way: build an argv, spawn a subprocess, capture stdout, parse findings. That model works for scanning a host. It does not work for acting *through* a host.

A Metasploit session is a live connection to a compromised machine. Once you have it, the useful operations are not new commands against a target — they are commands *inside* the session: `sysinfo`, `getuid`, `hashdump`, `enum_network`, `portfwd add`. These have no argv. They have a session id and a verb.

The runner has no concept of this. The AI planner has no concept of this. The catalog has no concept of this. That is the gap Phase E closes.

**v1 scope: Metasploit sessions only.** SSH, SMB, and WMI are deferred — the abstraction should accommodate them, but the first implementation reads from and writes to `MSFClient` and nothing else.

## 2. What exists today (factual)

Verified by reading the source, not from memory.

| Module | What it provides |
|---|---|
| `whaxon/core/msf.py` | `MSFClient` — RPC wrapper. `sessions()` lists sessions. `session_exec(sid, cmd, timeout)` writes a command and polls for output. `execute(type, name, options)` runs a module through a console. |
| `whaxon/core/msf_tracker.py` | Polls the RPC for session changes, fires `SessionStarted` / `SessionClosed` on the event bus. |
| `whaxon/core/pivot.py` | `pivot_edges` table. Kinds: `exploit`, `session`, `forward`. Relations: `from_exploit`, `tunnels_via`, `reached_through`. `chain_for_session()` walks descendants. |
| `whaxon/core/portfwd.py` | Local port forwarding through a raw shell session. `add_forward`, `remove_forward`, `list_live`. |
| `whaxon/core/autopivot.py` | Detects additional RFC1918 networks a session can reach. |
| `whaxon/adapters/msf.py` | Turns MSF module output into findings. Emits `msf_session`, `msf_loot`, `msf_chain`, `msf_chain_error`. Has an opt-in post-module autochain. |
| `whaxon/core/events.py` | `SessionStarted`, `SessionClosed`, `SessionOutput` events. |

**Critical current limitation:** the runner has no session-scoped path. Every tool invocation goes through `ToolRunner.run_tool(tool_id, target, ...)`, which builds an argv and calls `subprocess`. The MSF session-exec path is called **directly** by the `msf` adapter and by the web route `POST /api/msf/sessions/<id>/exec`. There is no catalog entry, no adapter contract, no AI planner visibility for "run a command in session N."

## 3. The new abstraction: a session-scoped tool

A **session-scoped tool** is a unit of work that takes a session id instead of a target. Its execution path is:

    session_id  ->  MSFClient.session_exec(session_id, command)  ->  stdout  ->  adapter.parse  ->  findings

Compare to a host-scoped tool:

    target  ->  ToolRunner.build_argv  ->  subprocess  ->  stdout  ->  adapter.parse  ->  findings

Same *shape*. Different *transport*. The adapter contract is unchanged — it takes lines and a context, returns findings. Only the dispatcher differs.

### 3.1 The catalog

Session-scoped tools live in the same `data/tools.json` catalog but carry a new required field:

    {
      "id": "msf_sysinfo",
      "name": "MSF sysinfo",
      "category": "session",
      "transport": "msf_session",
      "command": "sysinfo",
      "description": "Collect system information from the session",
      "package": ""
    }

Key changes to the schema:

- **`category`: `"session"`.** New category value. Existing values (`recon`, `web`, `vuln`, `test`) are host-scoped and unchanged.
- **`transport`: `"msf_session"`.** Required on session-scoped tools. Absent on host-scoped tools, meaning `"cli"` by default.
- **`command`**: for `msf_session` transport, the literal string written to the session. Replaces `args` (which would be argv).
- **No `binary` or `package`.** A session-scoped tool does not need an installed binary.

### 3.2 The Action

`Action` gains one new optional field:

    session_id: str | None = None

- When `session_id` is set, the tool_id must resolve to a `category == "session"` entry.
- When `session_id` is set, `target` is ignored and should be `None`.
- When `session_id` is not set, behavior is exactly as today.

This mirrors how `proposed_phase` was added in session 24: additive, optional, round-tripped through `to_dict`, no new `ActionKind`.

### 3.3 The runner path

`ToolRunner` gains a second public method:

    async def run_in_session(
        self,
        tool_id: str,
        session_id: str,
        job_id: str,
        timeout_s: float = 15.0,
    ) -> str:
        """Run a session-scoped tool. Returns the job id."""

Inside, it:

1. Looks up the catalog tool. Refuses if `transport != "msf_session"` or `category != "session"`.
2. Verifies the session exists via `MSFClient.sessions()`.
3. Writes `tool.command` to the session, collects output via `session_exec`.
4. Emits `JobStarted`, `JobOutput`, `JobFinished` on the bus — same events as a host-scoped run.
5. Runs the adapter's `parse()` on the collected output; publishes `JobFindings`.
6. Records the job in the store with the same schema.

The store schema does not change. `jobs.tool` holds the tool id, `jobs.target` holds the session id (as `"session:3"` — a namespaced value so host targets and session targets can be distinguished in the history table). This is a hack; a proper `jobs.session_id` column is v2 work.

### 3.4 The adapter

An adapter for a session-scoped tool is the same class as for a host-scoped tool. It overrides `parse(lines, ctx)` and receives the session output as `lines`. The `ctx` dict carries `session_id`, `job_id`, and `store` — same as host-scoped runs plus session specifics.

The MSF adapter already has per-module parsers in `msf_parsers.py` (`parse_sysinfo`, `parse_hashdump`, `parse_enum_network`, etc.). These are reusable. A new `SessionAdapter` can dispatch on `tool_id` to the right parser, or — cleaner — each session tool gets its own adapter module.

**v1 decision:** one `SessionAdapter` in `src/whaxon/adapters/session.py` that dispatches on `tool_id` to the existing `msf_parsers` functions. When a parser is missing, `parse()` returns `[]` and logs a warning. Splitting into per-tool adapters is v2.

### 3.5 The executor

`Executor._validate_and_run` gains a session branch:

- If `action.session_id` is set:
  - Refuse if `action.target` is also set (ambiguous).
  - Refuse if `action.tool_id` resolves to a host-scoped tool.
  - Verify the session exists via a new injected callable `session_check(session_id) -> bool`.
  - Call `run_in_session` instead of `run_tool`.
- Otherwise, unchanged.

The scope check does **not** run on the session id. Scope was checked when the session was established. Re-checking the session's target host is a v2 concern (session state can drift — a session that was in-scope when opened may not be after scope changes).

### 3.6 The planner

The catalog the LLM sees already gets slimmed by `_slim_catalog()` (session 27). Add `category` to the slim shape — it's already there. The model sees session-scoped tools marked `"category": "session"`.

The prompt needs a rule:

> To act inside an existing session, emit `run_tool` with `session_id` set to the session id and `target` omitted. Session ids appear in HISTORY as `msf_session` findings.

The `RulesProvider` learns one new ladder step: after a `msf_session` finding appears in history and the current phase is `post-access`, propose a session-scoped `sysinfo` against that session.

## 4. Objectives this enables

An **objective** that was previously impossible:

- `"enumerate the session on 10.0.0.5"` — the planner sees a `msf_session` finding with `session_id: "3"`, proposes `msf_sysinfo` on session 3, gets system info, proposes `msf_hashdump` next.

An objective that remains impossible:

- `"pivot to 10.0.0.7 through the session on 10.0.0.5"` — the pivot graph exists (`pivot.py`), but the runner has no path for "run a tool through a forward tunnel." That is Phase E.2 work, not this design.

## 5. Phases and session scope

The kill-chain phases (`recon`, `enumeration`, `vulnerability`, `initial-access`, `post-access`, `lateral`, `done`) already exist on `ai_runs.phase` (session 23). Session-scoped tools belong to `post-access` and `lateral`.

**v1: informational only.** Phase does not gate which tools the planner may propose — same as the existing design. **v2:** filter the catalog by phase so the planner only sees session-scoped tools when phase is `post-access` or later.

## 6. What "done" looks like

Three ways a session-scoped run ends:

1. The tool returns output. The adapter parses it into findings. The planner sees them in history on the next step.
2. The tool returns no output within `timeout_s`. The run records a `JobFailed` with `error="session timeout"`. This is a soft failure — the session may still be alive.
3. The session is gone (closed by Metasploit, target rebooted). `session_exec` returns an error string. The adapter produces a `session_lost` finding; the executor records a failure; on the next step the planner sees the session is unavailable.

## 7. Migration plan

| Step | Change | Scope |
|---|---|---|
| 1 | Add `transport` and `command` to the tools schema. Add `session` category. Update `data/tools.json` with the first three session tools (`msf_sysinfo`, `msf_getuid`, `msf_hashdump`). | `catalog.py`, `data/tools.json` |
| 2 | `Action` gains `session_id`. `to_dict` round-trips it. `run_tool` classmethod accepts it. | `ai/actions.py` |
| 3 | `ToolRunner.run_in_session()` — the session-scoped execution path. Refuses unknown transports, verifies session exists, writes command, collects output, emits events, records job. | `core/runner.py` |
| 4 | `SessionAdapter` dispatches on `tool_id` to `msf_parsers`. Register it. | `adapters/session.py` (new), `adapters/__init__.py` |
| 5 | `Executor` gains `session_check` callable and a session branch in `_validate_and_run`. `ai_bridge` wires it. | `ai/executor.py`, `core/ai_bridge.py` |
| 6 | Planner prompt: session rule. `RulesProvider`: post-access ladder step. | `ai/prompts/planner_v1.md`, `ai/providers/rules.py` |
| 7 | Report: session-scoped jobs render in Job History with `session:<id>` as the target; findings correlate normally. | `core/report.py` (likely no change needed) |

**Steps 1–5 are the v1 MVP.** After step 5, `whaxon run msf_sysinfo session:3` works from the CLI. After step 6, `whaxon ai "enumerate the session on 10.0.0.5"` works end-to-end.

**Steps 6–7 are v1.x.**

**v2 deferrals:** SSH/SMB/WMI transports, per-tool adapters, phase-gated catalog, proper `jobs.session_id` column, scope re-check on session target.

## 8. What this document does not answer

1. **Multi-session objectives.** "Enumerate all sessions" — the planner sees multiple `msf_session` findings and must iterate. The current single-action-per-step loop can do this, but the dedup guard will reject the second `msf_sysinfo` on a *different* session. Needs a dedup rule that treats `(tool_id, session_id)` as the uniqueness key, not `(tool_id, target)`.
2. **Session output size.** `sysinfo` on a Linux target is small. `hashdump` on a domain controller is megabytes. The current adapter contract assumes a `list[str]` of lines. Large output needs a cap or a streaming path.
3. **Long-running session tools.** `portfwd` and some post modules run indefinitely. The current `session_exec` has a 15-second timeout with a quiet-period heuristic. Tools that legitimately take minutes need a separate execution mode.
4. **Session errors vs. tool errors.** When the session dies mid-command, the output is an error string indistinguishable from a tool that produced no output. Needs a structured error channel.
5. **Interaction with `msf_tracker`.** The tracker fires `SessionClosed` when the session disappears. If the executor proposed a session action at the same instant, race conditions are possible. Needs a lock or an "is session alive" re-check between proposal and execution.
6. **The web UI.** `POST /api/msf/sessions/<id>/exec` already exists and works. Wiring it into the *job* model (as opposed to a raw exec) is a separate design.

## 9. What ships in v1 vs. what waits

**v1 (this design, ~4 sessions):**

- Session-scoped tool transport in the catalog and the runner
- `Action.session_id`
- `SessionAdapter` dispatching to existing MSF parsers
- Three built-in session tools (`sysinfo`, `getuid`, `hashdump`)
- Executor session branch with `session_check`
- CLI: `whaxon run msf_sysinfo session:3`
- Planner can see and propose session-scoped tools

**v2 (later):**

- SSH/SMB/WMI transports
- Per-tool adapters
- Phase-gated catalog
- Proper `jobs.session_id` column
- Scope re-check on session target
- Report integration for phase → session correlation

**v3 (Phase E.2):**

- Tools that run *through* a pivot (`portfwd` + host-scoped tools combined)
- Multi-session objectives

**Never in scope:**

- Sessions as a way to bypass scope
- Persisting on target systems beyond the engagement window
- Anything the MSF session model does not natively support

## 10. SMB and WMI transports (v2 design note)

SSH landed in v0.4.x as the second transport (`transport="ssh"`, session id format `ssh:user@host[:port]`). The pattern generalizes: a transport is any runner path that takes a session id and produces stdout-shaped output.

**SMB.** `impacket` already ships in the WHAXON optional deps. A `transport="smb"` tool would shell out to `impacket-smbclient` or `impacket-wmiexec` with the same `session_id` shape used for SSH (`smb:user:pass@host`). The runner's `_run_ssh_session` pattern (subprocess with auth args, scope check on the extracted host) maps directly.

Key open questions for the SMB design:
- **Credential handling.** SSH relies on the user's pre-existing key agent. SMB needs credentials passed in — either via env vars at session start or embedded in the session id. The latter is a security smell (credentials in strings that get logged). Recommend: session id is `smb:user@host`, credentials come from a separate env var (`WHAXON_SMB_PASS`) scoped to the runner process.
- **Pass-the-hash.** Impacket supports PTH directly. The session id could encode `smb:user@host#nthash` but that's the same logging problem. Defer to a credentials store, not the session id.
- **Output parsing.** impacket tools emit unstructured text. Existing impacket adapter (`adapters/impacket.py`) already has SAM/SMB parsing that could be reused.

**WMI.** Same shape as SMB — impacket's `wmiexec` and `atexec` produce stdout. Session id `wmi:user@host`, credentials from env. Functionally identical to SMB for our purposes; the same runner helper handles both.

**Effort estimate.** Two full sessions: one for SMB (runner path + adapter reuse + tests), one for WMI (much smaller, mostly copy-paste from SMB). Both blocked on a live SMB target for end-to-end verification, same blocker as the MSF session path.

**Not in scope for either:** interactive shells. The runner is command-in, output-out. Anything requiring a stateful interactive session (meterpreter, ssh interactive) is a different abstraction and would need a session-object model, not the current session-id-as-string model.

## 11. Phase E.2 — tools through a pivot (v2 design note)

The vision doc calls this the "next architectural gap" after session-based execution. It is.

**The problem.** A pivot is a route: `localhost:1080 -> session 3 -> target:22`. Once a pivot exists, a host-scoped tool (nmap, nikto) should be able to run *as if* it were on the far side of the tunnel. Currently the runner has no concept of this — `run_tool` executes on the local machine only, against whatever host it can reach.

**Why it's hard.**
- **Scope semantics.** Is the destination host in scope? It must pass `ScopeManager.check()` even though it's reachable only via the pivot. Yes — that check already exists and runs.
- **Which runner path?** Either (a) the pivot exposes a SOCKS proxy on localhost and host-scoped tools get a `--proxy` env var; or (b) the pivot forwards a specific port and the tool is pointed at `localhost:<forwarded>`.
- **Finding the right pivot.** For a given target host, which session/forward reaches it? `pivot.py` has the graph edges but no route resolver.
- **Reporting.** A finding produced through a pivot should be attributed to the target, not the pivot host. The `target` label in the job record needs to be the final host, with pivot metadata elsewhere.

**Proposed shape.**

Option (a) — SOCKS proxy:
- `MSFClient` gains `start_socks_proxy(session_id, lport)` using `socks_proxy` post module.
- The runner sets `ALL_PROXY=socks5://127.0.0.1:<lport>` in the tool's env when a pivot route exists.
- Many CLI tools honour `ALL_PROXY` (curl, some HTTP tools); most do not (nmap, nikto). So this only works for a subset.

Option (b) — port-forward per service:
- `portfwd` already exists (`core/portfwd.py`). A route is `(target_host, target_port) -> local_forward_port`.
- The runner rewrites the tool's `target` argument from `target_host` to `127.0.0.1:<forwarded_port>` for tools that accept a port. For tools that don't (nmap service scan), harder.
- Works for HTTP-focused tools (nikto, gobuster, ffuf, nuclei, sqlmap). Doesn't work for nmap.

**Recommendation.** Ship (b), scope it to HTTP tools. Document the limitation. nmap through a pivot is genuinely hard and probably out of scope.

**New abstraction needed.** A route resolver:
Populated from `portfwd` state + `pivot.py` graph. The runner consults it, rewrites `target`, tags the job with the original host.

**Effort estimate.** Three sessions. Session 1: route resolver + `portfwd` state integration. Session 2: runner integration for HTTP tools. Session 3: report tagging, tests, docs.

**Not in scope.** Tools that don't play well with a forwarded port (nmap full scan). Any interactive-through-pivot path.

## 10. SMB and WMI transports (v2 design note)

SSH landed in v0.4.x as the second transport. The pattern generalizes: a transport is any runner path that takes a session id and produces stdout-shaped output.

**SMB.** impacket already ships in optional deps. A `transport="smb"` tool would shell out to impacket-smbclient or impacket-wmiexec with session id `smb:user@host`. Credentials come from env vars (`WHAXON_SMB_PASS`) scoped to the runner process, not embedded in session ids — embedding credentials in strings that get logged is a smell. Pass-the-hash uses the same env-var channel.

**WMI.** Same shape. impacket's wmiexec and atexec produce stdout. Session id `wmi:user@host`. Reuse the SMB runner helper.

**Effort.** Two sessions. Both blocked on a live SMB target for end-to-end verification, same blocker as the MSF session path.

**Not in scope.** Interactive shells. The runner is command-in, output-out. Meterpreter and interactive SSH need a session-object model, not session-id-as-string.

## 11. Phase E.2 — tools through a pivot (v2 design note)

The vision doc calls this the next architectural gap after session-based execution.

**The problem.** A pivot is a route: localhost:1080 -> session 3 -> target:22. A host-scoped tool should be able to run as if on the far side of the tunnel. The runner has no concept of this.

**Why it's hard.** Scope semantics (destination must still pass check — it already does). Which runner path (SOCKS proxy vs per-service port-forward). Finding the right pivot for a target (pivot.py has the graph, no route resolver). Reporting (attribution goes to the target, not the pivot host).

**Recommendation.** Ship per-service port-forward (option b), scope it to HTTP tools. nmap through a pivot is genuinely hard; out of scope. Route resolver populated from portfwd state + pivot.py graph. Runner rewrites target to the forwarded port, tags the job with the original host.

**Effort.** Three sessions: route resolver, runner integration, report tagging.

**Not in scope.** Tools that don't play well with a forwarded port. Any interactive-through-pivot path.
