# Changelog

## 2026-09-28 (session 33)

### Added

- **`SessionAdapter`** (`src/whaxon/adapters/session.py`) — dispatches on `tool_id` to the existing `msf_parsers` functions. One instance registered per session tool (`msf_sysinfo`, `msf_getuid`, `msf_hashdump`). Converts each parser Result dict into a `Finding`, attaching `session_id` from `ctx`. `msf_getuid` has its own inline parser (`Server username: <user>` -> a `sysinfo` finding with `field=current_user`). `registry.py` autoloads the new module.
- **Executor session branch** (`src/whaxon/ai/executor.py`) — `_validate_and_run` now handles session actions **before** the host path. Refuses if `target` is also set, if the catalog tool is not `transport="msf_session"`, if the executor has no `run_in_session` callable, or if the session does not exist. Dispatches to `run_in_session` and attaches findings. `_already_ran` dedup now keys on `session_id` as well as `(tool_id, target)`, so a second action against a different session is not rejected as a repeat.
- **Executor gains `session_check` and `run_in_session` callables** — both optional. Defaults preserve existing behavior for callers that do not use session tools.
- **`ai_bridge.build_executor`** wires both: `session_check` builds an `MSFClient` and confirms the session id is in `sessions()`; `run_in_session` delegates to `core.runner.run_in_session`.
- **`tests/test_session_adapter.py`** — 6 tests: sysinfo kv parsing, hashdump ntlm parsing, getuid username parsing, empty on unrecognized output, session_id attached from ctx, all three registered.
- **`tests/test_executor_session.py`** — 5 tests: session path runs, rejects non-session tool, rejects missing session, rejects ambiguous (both target and session_id set), rejects when no runner callable.

### Fixed

- **Session branch ordering** — the initial patch inserted the session block *after* the existing `if not action.target` guard, so session actions (which have `target=None` by design) were rejected by the host path before reaching the session path. The block was moved above the target check. Caught by the new tests, not by the assert in the patch script. Lesson: an anchor assert proves the patch landed, not that the result is coherent.

### Notes

- **Steps 4 and 5 of 7** in the `docs/session-execution.md` migration plan. Remaining: step 6 (planner prompt + RulesProvider ladder), step 7 (report).
- **Session path is now testable end-to-end at the executor layer** — but only with a fake `run_in_session`. A real MSF session is needed for live verification, and there is no MSF daemon on this machine. Live check deferred.
- **CLI `whaxon run` still does not expose session tools.** That is step 6/7 territory; the executor branch is reachable today only through the AI loop.

### Tests

- 423 passing (was 412; +11).

## 2026-09-28 (session 32)

### Added

- **Session-scoped tool schema** — `Tool` gains `transport: str = "cli"` and `command: str = ""`. `ToolCatalog.load()` skips the `shutil.which(binary)` probe for `transport == "msf_session"` entries and marks them `available=True` (availability is a runtime MSF check, not a load-time PATH check). Three session tools added to `data/tools.json`: `msf_sysinfo`, `msf_getuid`, `msf_hashdump`. Catalog is now 16 tools (13 host-scoped + 3 session-scoped).
- **`Action.session_id`** (`src/whaxon/ai/actions.py`) — optional field, round-tripped through `to_dict`. New `run_in_session(tool_id, session_id, ...)` classmethod sets `target=None` and `session_id=<sid>`. Additive; existing `run_tool` calls unchanged.
- **`ToolRunner.run_in_session()`** (`src/whaxon/core/runner.py`) — the session-scoped execution path. Refuses tools whose `transport != "msf_session"`. Verifies the session exists via `MSFClient.sessions()`. Writes `tool.command` to the session, collects output via `session_exec`. Emits the same `JobStarted`/`JobOutput`/`JobFinished` events as a host-scoped run, with `target="session:<id>"`. Runs the adapter's `parse()` if one is registered; no-op otherwise.

### Notes

- **Steps 1-3 of 7** in the `docs/session-execution.md` migration plan. Remaining: step 4 (SessionAdapter), step 5 (Executor session branch + `session_check`), step 6 (planner integration), step 7 (report).
- **No adapter registered for the session tools yet.** `run_in_session` completes cleanly and publishes job events; findings will be empty until step 4 registers a `SessionAdapter`. That is intentional — the transport layer is testable without the parse layer.
- **No executor path to `run_in_session` yet.** The CLI `whaxon run` still routes through `run_tool`, and the AI executor has no session branch. That is step 5.

### Tests

- 412 passing (unchanged; the new path is additive and untested until step 4/5).

## 2026-09-28 (session 31)

### Added

- **`docs/session-execution.md`** — design document for session-scoped tool execution (Phase E, session 1 of ~5). No code changes; this session was pure design.
- **The abstraction:** a *session-scoped tool* takes a session id instead of a target. Same adapter contract, same event flow, same job store; different transport (MSF RPC instead of subprocess).
- **Catalog schema extension:** `category: "session"`, `transport: "msf_session"`, `command` field. Session tools do not need a binary.
- **Action extension:** `session_id: str | None`. Additive, mirrors how `proposed_phase` was added in session 24. No new `ActionKind`.
- **Runner extension:** `ToolRunner.run_in_session(tool_id, session_id, job_id, timeout_s)`. Reuses the same event bus, store, adapter parse contract.
- **Adapter plan:** one `SessionAdapter` dispatching on `tool_id` to the existing `msf_parsers` functions. Per-tool adapters deferred to v2.
- **Executor extension:** a session branch in `_validate_and_run` plus a `session_check(session_id)` callable. Scope is checked at session establishment, not re-checked per session action (v2 concern).
- **Migration plan, 7 steps.** Steps 1-5 are the v1 MVP (CLI: `whaxon run msf_sysinfo session:3`). Steps 6-7 are v1.x (planner integration, report).

### Scope decisions

- **v1 is Metasploit-only.** SSH, SMB, and WMI are explicitly deferred. The abstraction is designed to accommodate them, but the first implementation reads from and writes to `MSFClient` and nothing else.
- **Phase E.2 (tools that run *through* a pivot) is out of scope.** The pivot graph exists (`core/pivot.py`), but running a host-scoped tool over a forward tunnel is a separate design.
- **No changes to the executor boundary, the store schema, or the adapter ABC.** The session transport is additive.

### Open questions documented

Six items in §8, including: multi-session dedup keys, large-output handling, long-running session tools, session-error vs tool-error distinction, races with `msf_tracker`, and web UI integration.

### Notes

- **Phase E, session 1 of ~5.** Next sessions: catalog + runner plumbing (step 1-3), then adapter + executor (step 4-5), then planner integration (step 6), then report (step 7).
- **Design mirrors `docs/agent-architecture.md`.** Prescriptive with a numbered migration plan, same as session 19. The plan is meant to be executed, not just read.

### Tests

- 412 passing (unchanged — design only).

## 2026-09-28 (session 29)

### Changed

- **Rules provider proposes phase transitions** (`src/whaxon/ai/providers/rules.py`) — the deterministic ladder now emits `ask_human(proposed_phase="enumeration")` at step 2 when web ports are open and the current phase is `recon`. When phase is already `enumeration`, it falls through to the existing nikto branch. When the phase is past enumeration, existing stop logic applies. This makes the rules provider walk the same kill-chain transitions the LLM provider can, closing a gap left since session 24.
- **`docs/ai.md` performance section** — replaced the stale "Models larger than 3B are slow on CPU-only hardware (30-60s per step)" paragraph with the post-session-27 reality: `qwen2.5:1.5b` at ~4-5s/step warm, 30-60s cold-load cost. Prior number was for the fat payload.
- **`planner_v1.md` HISTORY description** — corrected from `{action, ok, summary, findings, error}` to `{kind, tool_id, target, ok, summary, error}`. The description was written before session 27 slimmed the payload; the prompt was documenting a shape the code no longer sends.
- **`planner_v1.md` worked example** — replaced with one that shows a repeat action being rejected (`ok: false, error: "repeated action"`) and the correct recovery: emit `ask_human` rather than retry. Small models ignore rule 5 ("never repeat") in the abstract; a concrete pattern gives them a template to match.

### Fixed

- **`tests/test_rules_provider.py`** — `test_step2_escalates_to_nikto_on_web_port` asserted old behavior (nikto at default phase). Replaced with two tests: `test_step2_proposes_enumeration_phase_on_web_port` (asserts the new ask_human with proposed_phase) and `test_step2_runs_nikto_when_already_in_enumeration` (asserts the fallthrough).

### Notes

- **No behavior change for the LLM provider.** All three changes target the deterministic rules provider and documentation.
- **Session 27's prompt contract now matches the code.** The prompt documented a slim HISTORY shape and the code sent it — but the prompt described the *old* fat shape. Corrected.
- **Session 24's phase transition capability now has two consumers.** The LLM can propose transitions; the rules provider now can too. Both go through the same executor validation.

### Tests

- 411 passing (was 410; +1 net, one replaced by two).

## 2026-09-28 (session 28)

### Added

- **AI Runs section in the engagement report** (`src/whaxon/core/report.py`) — `_load()` now calls `_load_ai_runs(store)` and adds an `ai_runs` key to the report dict. `to_markdown()` renders a compact `## AI Runs` table (run id, goal, current phase, status, step count) between the executive summary and the job history. A per-run phase-history line is appended when a run has more than one transition.
- **`_load_ai_runs(store, limit=20)`** — reads `list_ai_runs()` for the summary rows, then `get_ai_run(run_id)` per run so `phase_history` is included. Exceptions are swallowed (empty list on failure) so a broken AI-runs table cannot break report generation.
- **`_md_ai_runs(md, runs)`** — renders the section. Empty runs list means no section (clean fallback for engagements with no AI activity).
- **`to_json`** gains the field automatically — it dumps the report dict as-is, which now contains `ai_runs`.
- **`tests/test_report_ai_runs.py`** — 7 tests: `_load_ai_runs` empty, populated with phase and history, `_md_ai_runs` section render, section omitted when empty, `_load` returns the key, `to_markdown` includes the section, section omitted when no runs, section ordering before Job History.

### Fixed

- **Session 24's phase data is now visible.** `ai_runs.phase` and `ai_runs.phase_history` were being written since session 24 but nothing read them for presentation. The engagement report is the first consumer.

### Notes

- **Phase D, first slice.** Report rendering is done. The web UI (`/api/ai/runs` already returns phase, but no template reads it) and the TUI are separate sessions if wanted.
- **Report stays valid without AI runs.** `_load_ai_runs` returns `[]` on any exception or when the store has no runs, and `_md_ai_runs` skips the section entirely. Reports generated against stores without the `ai_runs` table (legacy data) still render.
- **Per-run `get_ai_run` call cost** — the report fires one extra query per AI run (up to 20 by default). Report generation is not hot-path; this is acceptable.

### Tests

- 410 passing (was 403; +7).

## 2026-09-28 (session 27)

### Added

- **Planner payload slimming** (`src/whaxon/ai/providers/llm.py`) — `LLMProvider.plan_step` now projects CATALOG and HISTORY before serialising them into the prompt, matching the shape the prompt template already documented.
  - `_slim_catalog()` — keeps only `{id, name, category}` per tool. Drops `args`, `binary`, `outfile_flag`, and everything else in the raw `Tool` asdict.
  - `_slim_history()` — keeps only `{kind, tool_id, target, ok, summary, error}` per step. **Drops the findings array**, which after an nmap scan can be dozens of entries and was the dominant cost. Caps the last 5 steps with a `{"_omitted": N}` sentinel.
  - `_truncate()` — caps summary and error strings at 120 chars each.
- **`tests/test_llm_payload.py`** — 8 tests locking in the slim shapes: catalog projection, findings dropped, truncation, last-N-with-sentinel, under-limit no sentinel, missing-action tolerance, empty/None handling.

### Measured

Payload size reduction, against the real 13-tool catalog and a realistic 5-step nmap history:

| | Before | After | Reduction |
|---|---|---|---|
| Catalog | 1635 B | 739 B | 55% |
| History (5 steps, 30 findings each) | 8515 B | 560 B | 93% |
| **Total per-step prompt saving** | | | **~8851 B** |

### Verified live on this hardware

Dell Latitude 7490 (i7, 16 GB, no GPU), Ollama + `qwen2.5:1.5b`, model pinned with `keep_alive=30m`:

    whaxon ai "enumerate 127.0.0.1" --max-steps 4
    real 22.26s — 5 executor steps, ~4-5s per step warm

The model behaves exactly as `docs/ai.md` predicts: it emits valid JSON every time, it repeats actions (nmap twice, whois twice), and the executor's dedup guard rejects every repeat. Step 5 was the executor's budget stop. No infinite loop, no invalid JSON, no hang.

### Corrects session 26's finding

Session 26 concluded that CPU-only inference was "too slow for interactive use" based on a 550s run against `huihui_ai/llama3.2-abliterate:1b`. That conclusion was **wrong** — the 550s was (a) cold model load, and (b) the CLI blocked on `ask_human` waiting for input that never came in a piped invocation. Warm inference on this hardware is ~4-5s per step. The slimming from this session makes the payload small enough that the number is stable.

### Notes

- **No behaviour change for other providers.** Only `LLMProvider` uses the helpers. `RulesProvider` and `NullProvider` are untouched.
- **The prompt template already documented the slim shape** — the code was just sending raw asdicts. This session brought the code in line with the documented contract.
- **Cold-start latency is real.** Ollama unloads the model after 5 minutes idle; the first call after that pays the reload (30-60s on this disk). For interactive use, either pin with `keep_alive` or accept the first-call cost.

### Tests

- 403 passing (was 395; +8).

## 2026-09-28 (session 26)

### Fixed

- **`GoogleBackend` auth for new-format API keys** (`src/whaxon/ai/providers/backends/google.py`) — the backend sent the API key via the `?key=` query param. That worked for the legacy `AIza...` key format, but Gemini API keys issued by AI Studio since May 2026 use the `AQ....` format and are rejected by both query-param and Bearer auth with `401 ACCESS_TOKEN_TYPE_UNSUPPORTED`. The backend now sends the key in the `x-goog-api-key` request header instead. This is the documented auth style for the current Gemini API.

### Added

- **`tests/test_google_backend.py`** — 2 tests locking in the request shape: the key goes in the `x-goog-api-key` header (not the query string, not `Authorization`), and the URL targets `/v1beta/models/{model}:generateContent` with no query params.

### Notes

- **Real-LLM end-to-end test blocked on this hardware.** Attempted three Ollama models against `whaxon ai "enumerate 127.0.0.1"` on a Dell Latitude 7490 (i7, 16 GB, no GPU):
  - `huihui_ai/llama3.2-abliterate:1b` — stalls on the full planner payload. Produces valid JSON for a minimal prompt, but does not complete a step when given the real system prompt + catalog + history.
  - `huihui_ai/qwen2.5-abliterate:0.5b-v3` and `qwen2.5:0.5b` — not attempted; `docs/ai.md` marks 0.5B as unusable (hallucinates targets, cannot follow the JSON contract).
  - `qwen2.5:1.5b` — the design's recommended floor; hangs on the first step at CPU-only speed beyond what's usable interactively.
  - **No code change follows from this.** The finding is documented, not patched. The planner payload is large — full catalog, full history, full scope — and shrinking it is the explicit purpose of session 27.
- **Gemini path blocked on credits.** Verified the backend fix is correct (curl with the new header returns 200 against a working key), but the account has no remaining credits for further end-to-end testing.
- **No regressions.** 395 passing (was 393; +2 from the new backend test file).

## 2026-09-28 (session 25)

### Added

- **`src/whaxon/ai/scope_policy.py`** — `POLICIES` tuple (`strict`, `inherited`, `recommended`), `DEFAULT_POLICY = "strict"`, `is_valid()`, `read_policy(env=None)`. Reads `WHAXON_AI_SCOPE_EXPANSION`. Unknown or non-strict values log a warning and fall back to strict (v1 implements strict only; inherited and recommended are v2 deferrals per design §9).
- **`Executor.scope_policy`** — new constructor param, default `"strict"`. Stored on the instance; no behavior change yet. This is the field a future v2 scope-checker will read.
- **`build_executor` reads the policy** and passes it to the `Executor`.
- **`tests/test_scope_policy.py`** — 8 tests: policy tuple matches design, `is_valid`, default-when-unset, strict accepted (incl. whitespace + case-insensitive), unknown falls back with warning, not-implemented falls back with warning, bridge end-to-end, bare-Executor default.
- **`README.md` env table** gains a `WHAXON_AI_SCOPE_EXPANSION` row.
- **`docs/scope.md`** gains an "AI scope expansion" section documenting the three policies, their v1 status, and the strict-for-v1 rationale.

### Notes

- **Step 6 of 7** in the design migration plan. Remaining: step 7 (`whaxon ai --resume`, v2 deferred in the design itself).
- **No behavior change.** `strict` is a no-op relative to today — the executor already calls the scope checker per action and rejects out-of-scope targets. The env var and the field are now in place for a v2 policy that actually branches on the value.
- **The doc follow-up from session 19 is now closed.** That CHANGELOG entry said "`README.md` and `docs/scope.md` should document `WHAXON_AI_SCOPE_EXPANSION` when the executor reads it (step 6 in the migration plan, not yet implemented)." Done.

### Tests

- 393 passing (was 385; +8).

## 2026-09-28 (session 24)

### Added

- **Phase transitions via `ask_human`** — `Action` gains a `proposed_phase` field (round-tripped through `to_dict`; new `ask_human` classmethod kwarg). When the human approves an `ask_human` whose action carries `proposed_phase`, the executor writes the new phase to `ai_runs.phase` and appends an entry to `ai_runs.phase_history`. Invalid phases (anything outside the §5 vocabulary) are rejected with a visible error and the phase is unchanged.
- **`src/whaxon/ai/phases.py`** — module-level `PHASES` tuple (recon, enumeration, vulnerability, initial-access, post-access, lateral, done), `DEFAULT_PHASE`, `is_valid()`. Exported from `whaxon.ai`.
- **`ai_runs.phase_history` column** — JSON array, default `[]`. Idempotent migration in `JobStore.__init__` alongside the existing `phase` migration.
- **`JobStore.set_ai_run_phase(run_id, phase, history_entry=None)`** — updates the current phase and appends a history entry (default `{phase, at}`).
- **Executor per-step phase read** — `Executor.__init__` gains `phase_get` and `phase_set` callables (both default to no-ops for backward compat). The loop reads the current phase per step instead of hard-coding `recon`. `build_executor` accepts `ai_run_id` and wires the callables to the store; the CLI passes `ai_run_id=run_id`.
- **LLM prompt guidance** — `LLMProvider` payload now includes a `PHASE_RULES` string instructing the model how to propose a transition via `ask_human` + `proposed_phase`.
- **`tests/test_phase_transitions.py`** — 6 tests: approved transition writes new phase, rejected transition keeps phase, invalid phase rejected, `ask_human` without `proposed_phase` is a no-op, `phase_history` accumulates, phases are isolated between runs.

### Notes

- **Step 5 of 7** in the design migration plan. Remaining: step 6 (`WHAXON_AI_SCOPE_EXPANSION`), step 7 (`whaxon ai --resume`, v2).
- **Rules provider does not yet propose transitions** — the ladder is still two steps (nmap, nikko-or-stop). Wiring it to propose recon→enumeration is a follow-up, not a bug.
- **Live-verified:** `whaxon ai "enumerate 127.0.0.1" --max-steps 3` under the rules provider writes `phase=recon, phase_history=[]` to the store. Read path proven end-to-end; transition path proven by unit tests.
- **No behavior change for callers that don't pass `ai_run_id`** — the default `phase_get`/`phase_set` no-ops preserve prior semantics. Web route will need a separate change to pass its run id when it adopts phase transitions.

### Tests

- 385 passing (was 379; +6).

## 2026-09-28 (session 23)

### Added

- **`ai_runs.phase` column** — `JobStore.__init__` runs an idempotent `ALTER TABLE ai_runs ADD COLUMN phase TEXT DEFAULT 'recon'` migration. `create_ai_run` accepts a `phase` keyword (default `recon`); `get_ai_run` returns it via `SELECT *`; `list_ai_runs` selects it explicitly. Verified on fresh, legacy, and production DBs.
- **Phase flows through the planner** — `Provider.plan_step` gains `phase: str = "recon"`. `Agent.next_action` accepts and forwards it. `LLMProvider` includes `"PHASE"` in the JSON payload sent to the model. `RulesProvider` accepts the kwarg (no behavior change yet).
- **`tests/test_phase_flow.py`** — 4 tests: default phase, custom phase round-trip, phase in `list_ai_runs`, and `Agent.next_action` forwarding phase to the provider (via a spy).
- **`tests/test_ai_runs.py`** gains a `phase == 'recon'` assertion on the round-trip test.

### Notes

- **Executor still hard-codes `phase="recon"`** in the `next_action` call. Reading phase per-step from the store is step 5 work (phase transitions). The plumbing is complete; only the source of truth for the current phase is deferred.
- **No behavior change anywhere.** Every caller uses the default. The 7 test-local `Provider` overrides across 4 files were updated to accept `phase` for signature compatibility — mechanical, no assertions changed.
- **Step 2 and 3 of 7** in the design migration plan, both landed together this session.

### Tests

- 379 passing (was 375; +4).

## 2026-09-28 (session 22)

### Added

- **CLI `ask_human` wiring** — `whaxon ai` now passes an interactive callback into the executor. When the planner emits an `ask_human` Action, the CLI prints the rationale and confidence, reads a line from stdin, and resumes the loop with the answer. Step 4 of the migration plan in `docs/agent-architecture.md` §13.
- **`build_executor` accepts `ask_human`** (`src/whaxon/core/ai_bridge.py`) — new keyword argument, forwarded to `Executor.__init__`. Callers that don't pass it get the pre-step-1 terminate-on-ask-human behavior.
- **`_stdin_ask_human`** (`src/whaxon/interfaces/cli/ai_cmd.py`) — synchronous callback; strips whitespace; returns `skip` on EOF. Wrapped in `asyncio.to_thread` so the blocking `input()` doesn't stall the async loop.
- **`tests/test_ai_cmd_ask_human.py`** — 5 tests: y, n, freeform passthrough, whitespace strip, EOF→skip.

### Notes

- **Answer semantics still not interpreted by the planner.** The callback returns the raw string; the executor records it in history; the planner sees it next step. Teaching the LLM/rules providers what `y` / `n` / `skip` / freeform mean is step 5 work.
- **Live-verified:** `whaxon ai "enumerate 127.0.0.1" --max-steps 2` runs to completion under the rules provider with the new callback wired in (no `ask_human` in that path, but proves the bridge signature change is sound end-to-end).
- **Step 4 of 7** in the design migration plan. Remaining: step 2 (phase column on `ai_runs`), step 3 (phase param through `Agent.next_action` and providers), step 5 (phase transitions via `ask_human`), step 6 (`WHAXON_AI_SCOPE_EXPANSION`), step 7 (`--resume`).

### Tests

- 375 passing (was 370; +5).

## 2026-09-28 (session 21)

### Added

- **`ask_human` pause/resume in the executor** (`src/whaxon/ai/executor.py`) — `Executor.__init__` gains an optional `ask_human: Callable[[Action], Awaitable[str]] | None` callback. When set, an `ask_human` Action pauses the loop, awaits the callback, records the answer as a synthetic `ActionResult` with `ai_source="human"`, and resumes at the next step. When unset, the loop terminates on `ask_human` exactly as before. Step 1 of the migration plan in `docs/agent-architecture.md` §13.
- **`tests/test_executor_ask_human.py`** — 3 tests: no-callback terminates (existing behavior preserved), callback yes resumes, callback no records the rejection in history.

### Fixed

- **`docs/ai.md` stagnation count** — doc said 3 consecutive failures; code halts at 2. Doc corrected.

### Notes

- **Step 1 of 7** in the design migration plan. Steps 2-7 (phase column, phase param, CLI wiring, phase transitions, scope expansion env, --resume) not in this session.
- **Answer semantics not yet interpreted.** Step 1 resumes the loop; it does not yet map y/n/skip/text to actions. That is step 4 (CLI).
- **Unrelated drift observed, not fixed:** unreachable code in `_default_model_for` in `src/whaxon/core/ai_bridge.py`. Logged for future cleanup.

### Tests

- 370 passing (was 367; +3).

## 2026-09-28 (session 20)



### Added

- **theHarvester adapter** (`src/whaxon/adapters/theharvester.py`) — parses theHarvester 4.x JSON output (`-f <file>`): hosts and emails. Normalizes the DuckDuckGo `2F` redirect artifact out of hostnames (`2Fdocs.kali.org` -> `docs.kali.org`) and rejects entries that don't survive a conservative hostname regex.
- **dnsrecon adapter** (`src/whaxon/adapters/dnsrecon.py`) — parses dnsrecon `-j <file>` JSON array: A, AAAA, MX, NS, SOA, TXT. Skips `ScanInfo` metadata records.
- **`Tool.outfile_flag`** in `src/whaxon/core/catalog.py` — optional per-tool flag. When set, `ToolRunner.run_tool` allocates `/tmp/whaxon-<jid>.json`, appends `<flag> <path>` to argv before user extra_args, and passes the path into the adapter via `ctx["outfile"]`.
- **25 new tests** (`tests/test_adapters_theharvester_dnsrecon.py`).

### Fixed

- **Silent zero-finding runs.** Both new adapters previously returned `[]` when their expected output file was missing, indistinguishable from a clean run with no results. They now log a WARNING (via `logging.getLogger(__name__)`) naming the expected path and the extra_args that produced it.
- **Missing outfile is now visible.** `ToolRunner.run` prints `[runner] <tool>: expected outfile not produced: <path>` on stderr when a tool declares `outfile_flag` but exits without writing its file.

### Changed

- **`ToolRunner.build_argv`** now takes an `outfile: Path | None` keyword. `ToolRunner.run` gains the same keyword. `_publish_findings` adds `ctx["outfile"]`.
- **Adapter `_json_path` precedence:** both new adapters now prefer `ctx["outfile"]` when present and fall back to the legacy `extra_args` regex. Existing adapters are unchanged.
- **`data/tools.json`** adds `theharvester` and `dnsrecon` with `outfile_flag` set (`-f` and `-j`). The earlier hardcoded `/tmp/whaxon-*.json` paths are removed from `args`.

### Notes

- **Known naming mismatch:** the CLI prints a store-assigned `job:` ID (e.g. `807a0b496eeb`), while the on-disk outfile uses a separate `run_tool`-local UUID (e.g. `whaxon-21ce92f79929.json`). Both are correct — they're just two ID spaces. Unifying them is a follow-up, not part of this session.
- **Live verification:** `whaxon run theharvester kali.org --allow-out-of-scope` returned 13 hostname findings (the `2F` artifact stripped correctly in production). `whaxon run dnsrecon kali.org --allow-out-of-scope` returned 37 DNS findings (6 SOA, 12 NS, 10 MX, 2 A, 2 AAAA, 5 TXT).

### Tests

- 367 passing (25 new).



### Added

- **docs/agent-architecture.md** — design document for the autonomous driving layer. No code changes; this session was pure design.

### Notes

- The single change the design requires to the existing executor is a new `ask_human` callback on `Executor.__init__`. When provided, `ask_human` Actions pause and resume the loop. When absent, existing terminate-on-ask-human behavior is preserved.
- v1 design: CLI-only human-in-the-loop, phase field informational, scope expansion strict-only, `whaxon ai "objective"` works end-to-end.
- v2 deferrals documented: persistent paused runs (`whaxon ai --resume`), web UI approval queue, inherited/recommended scope expansion, cross-run summaries, cost and rate limiting.
- Seven open questions explicitly listed in section 14 so future sessions know where the design stops.

### Follow-ups noted

- `README.md` and `docs/scope.md` should document `WHAXON_AI_SCOPE_EXPANSION` when the executor reads it (step 6 in the migration plan, not yet implemented).
- Cross-link from `whaxon_vision.md` to `docs/agent-architecture.md` when the vision file is located.

### Tests

- 342 passing (unchanged).

## 2026-09-28 (session 19)



## 2026-09-28 (session 18)

### Added

- **docs/plugins.md** — how to write a WHAXON adapter as a separate pip package. Covers the entry-point mechanism, the Adapter contract, the Finding dataclass fields, a complete worked example (masscan adapter with tests and pyproject.toml), the catalog integration, and publishing to PyPI. Verified end-to-end: building a minimal whaxon-masscan package and pip installing it into the venv registers the adapter alongside the 14 built-ins.

### Fixed

- **README.md and docs/interfaces.md subcommand count** — both said 16. Actual is 21. The list in interfaces.md was also missing run, findings, lookup, cve, and state. This drift existed because the docs list and the dispatch in cli.py are maintained independently with no enforcement that they agree.

### Notes

- The plugin entry-point mechanism (`whaxon.adapters.registry._discover_plugins`) works as documented. Tested with a real pip-installed plugin: before install, 14 adapters; after install, 15 including masscan; parse() returns a valid Finding.
- A future CI check should compare the subcommand count in docs/interfaces.md against the dispatch in cli.py to prevent this class of drift. Noted for the roadmap, not built.

### Tests

- 342 passing (unchanged).

## 2026-09-28 (session 17)

### Added

- **lookup_hint on Finding** — optional search string (e.g. "apache 2.4.7") set by adapters when a versioned service is detected. Round-trips through the store via the existing enrichment_json blob.
- **nmap adapter sets lookup_hint** for a conservative whitelist of services (apache, nginx, openssh, vsftpd, mysql, postgresql, redis, mongodb, tomcat, php, openssl, etc.). Only fires when a version number can be extracted from nmap output.
- **Known Vulnerabilities section in to_markdown()** — collects unique hints across all jobs, runs searchsploit --json once per hint (memoized per render), and prints a table of matching exploits per service with EDB-IDs, titles, and CVEs. Controlled by a new lookup=True parameter (default on).

### Notes

- Report-time lookup, not job-time. Reports are snapshots — the same engagement rendered twice may differ if the searchsploit mirror was updated between renders.
- Version regex truncates patch suffixes: OpenSSH 6.6.1p1 → "openssh 6.6.1". Acceptable for a first pass; searchsploit does not differentiate the patch level.
- Per-job reports (whaxon report <job_id>) do not include the section. Only engagement-level reports (--all / --engagement / --jobs) go through to_markdown(). Per-job uses render_markdown().

### Tests

- 342 passing (unchanged).

## 2026-09-28 (session 16)

### Added

- **whaxon cve** — new top-level CLI subcommand. NVD v2.0 lookup with a local SQLite cache at data/cve_cache.db. Two modes: exact ID lookup (whaxon cve CVE-2021-44228) and keyword search (whaxon cve --keyword "apache 2.4.7"). Flags: --json, --limit N, --no-cache, --refresh, --data DIR.
- tests/test_cve_cmd.py (14 tests). All network calls mocked via urllib patching.

### Notes

- Cache TTL is 7 days. Entries older than that are refetched. --refresh forces a refetch regardless of age.
- Rate limits respected: HTTP 403/429 exits with code 3 and a message pointing to NVD_API_KEY for the higher limit.
- CVSS is picked from cvssMetricV31 > cvssMetricV30 > cvssMetricV2, whichever is present.
- The second half of the CVE/exploit capability. whaxon lookup (session 4c) is the offline searchsploit half; whaxon cve is the online NVD half.

### Tests

- 342 passing (was 328).

## 2026-09-28 (session 15)

### Added

- **whaxon lookup** — new top-level CLI subcommand. Wraps searchsploit --json for offline exploit lookup. Three modes: search by query, search by CVE (--cve), details for one exploit (--id). Flags: --json, --copy (print exploit source to stdout, read-only), --save PATH, --limit N.
- tests/test_lookup_cmd.py (13 tests).

### Notes

- --copy is a read, not an exec. Exploit source is printed to stdout; nothing runs. If execution is added, it goes through the executor boundary AI proposals use.
- No new dependencies. searchsploit ships with Kali's exploitdb package.
- Read-only half of the CVE/exploit capability. NVD lookup is session 4d.

### Tests

- 328 passing (was 315).

## 2026-09-28 (session 14)

### Added

- **whois adapter** — wraps the existing parser, adds enrichment for domain_expiry (renewal risk), registrar (account-takeover path), and nameserver (DNS authority). All findings info severity.
- **dig adapter** — wraps the existing parser, adds impact text for A/AAAA/NS/MX records.
- **whatweb adapter** — new parser. Prefers JSON output (--log-json=FILE in extra_args), falls back to the text line format. Enrichment for WordPress, PHP, jQuery, Apache, nginx, OpenSSL with specific remediation text.
- tests/test_adapters_whois_dig_whatweb.py (11 tests).

### Fixed

- **core/findings.py + adapters/dig.py**: the dig parser classified every line ending with '.' as an NS record, including '10 mail.example.com.' which is an MX record. Added a priority-prefix regex (^\d+\s+\S+\.$) checked before the trailing-dot heuristic. Found by the new whatweb/dig/whois test file — the existing suite never asserted on MX output.

### Changed

- adapters/registry.py: _autoload tuple extended with whois, dig, whatweb. Adapter count is now 14.

### Tests

- 315 passing (was 304).

## 2026-09-28 (session 13)

### Added

- **gobuster adapter** — status-code mapped severity (200 low, 401/403 info, 404 filtered). CWE-200 for 200 responses, remediation per status.
- **ffuf adapter** — same shape; handles both default (with [Status: N, Size: M]) and silent-mode (path only) output. 404 filtered.
- **nuclei adapter** — parses [severity] [template-id] url. CVSS inferred from severity tier. CWE mapped from template id prefix (cve-, sqli, xss, rce, lfi, ssrf, xxe, csrf, cors, takeover, expos, disclos, misconfig, default-login, weak-).
- **wpscan adapter** — parses WordPress version (Insecure flag escalates to medium), vulnerability titles (high, CVSS 7.5, CWE-1395), plugins and themes as info.
- tests/test_adapters_gobuster_ffuf_nuclei_wpscan.py (9 tests).

### Changed

- adapters/registry.py: _autoload tuple extended with ffuf, nuclei, wpscan, hashcat. hashcat's adapter file existed but was never auto-loaded; now it registers on import. Full adapter list: burp, ffuf, gobuster, hashcat, impacket, msf, nikto, nmap, nuclei, sqlmap, wpscan (11).

### Tests

- 304 passing (was 295).

## 2026-09-28 (session 12)

### Added

- **whaxon init --demo** — try-it-now setup. Writes a minimal scope.json (127.0.0.1, ::1, scanme.nmap.org) and tools.json (nmap, echo). Prints a three-command hint. Refuses to overwrite existing data/ without --force. End-to-end verified against scanme.nmap.org.
- **ToolRunner.has_tool(tool_id)** — public method to check catalog membership.
- Two tests in test_automation.py: test_queue_nikto_skips_when_tool_missing, test_has_tool_returns_true_for_present_tool.
- README section: Try WHAXON in 60 seconds.

### Fixed

- **automation.py**: the automator tried to queue nikto against every web port nmap found, and crashed inside a daemon thread if nikto wasn't in the catalog. The traceback printed to stderr but the caller exited 0 — the failure was invisible. Now the automator calls runner.has_tool('nikto') and skips silently when it's absent. A missing tool is a config fact, not an error. Found by running the demo with a minimal tools.json.

### Changed

- README status line bumped v0.2 -> v0.3.

### Tests

- 295 passing (was 293).

## 2026-09-28 (session 11)

### Added

- **whaxon report --all-findings** — expands the detail section from critical+high to every severity. New all_findings parameter on to_markdown(). On the current engagement this grew the report from 20 KB (2 sections) to 74 KB (5 sections). Default behavior unchanged.
- **whaxon report --clipboard** — copies the rendered text to the system clipboard. Detection order: wl-copy, xclip, xsel. Refused for pdf (binary). Warns (exit 0) if no tool present.
- **whaxon report --open** — opens the report in the OS default viewer via xdg-open / open / start. Warns (exit 0) if no opener present.
- Both --open and --clipboard force a file write if --out was not given.
- tests/test_report_ergonomics.py (8 tests).

### Tests

- 293 passing (was 285).

## 2026-09-28 (session 10)

### Added

- **whaxon findings [target]** — cross-job target lookup. Without a target: summary table of every target the store has seen (jobs, findings). With a target: findings grouped by severity, with per-signature counts when a finding repeats across jobs. Filters: --severity (threshold), --kind, --source, --json, --limit.
- tests/test_findings_cmd.py (10 tests).

### Tests

- 285 passing (was 275).

## 2026-09-28 (session 9)

### Added

- **whaxon run <tool> <target>** — execute a catalog tool directly from the CLI. Streams stdout/stderr live, persists to the store, prints a findings summary and the report command on finish. Flags: --extra, --data, --timeout, --allow-out-of-scope, --quiet, --json. Exit codes: 0 OK, 1 tool error, 2 out of scope, 3 unknown tool, 64 usage error.
- tests/test_run_cmd.py (9 tests).

### Fixed

- run_cmd.py: added missing JobStarted import (caught by the first smoke test — the subscribe call raised NameError before any tool ran).

### Tests

- 275 passing (was 266).

## 2026-09-28 (session 8)

### Released

- **whaxon 0.3.0 published to PyPI** — https://pypi.org/project/whaxon/0.3.0/

### Added

- .github/workflows/release.yml — triggered on v* tags. Runs the full test suite, builds the wheel and sdist, publishes to PyPI via the PYPI_API_TOKEN repository secret.
- .gitignore now ignores dist/, build/, *.egg-info/ (Python build artifacts).

### Changed

- pyproject.toml: version 0.2.0 -> 0.3.0. License field switched to the PEP 639 string form (was the deprecated dict form). Added license-files = [LICENSE], 37 keywords, 11 classifiers, [project.urls] with Homepage/Repository/Issues/Changelog, and an explicit sdist allow-list that cuts the source distribution from 3.4 MB to 138 KB.
- whaxon/__init__.py: __version__ = 0.3.0.

### Fixed

- tools/state.py: build() now checks for pyproject.toml at REPO root and exits 1 with a clear message if missing. Previously, whaxon state crashed with FileNotFoundError when run from an installed wheel (where the source tree is not on disk). Found during the PyPI pre-flight smoke test.
- tests/test_state.py: no longer hardcodes the version string; reads whaxon.__version__.

### Tests

- 266 passing (unchanged from session 7).

## 2026-09-28 (session 7)

### Added

- tests/test_tui_report_format.py (6 tests): ReportFormatScreen composes all five format labels, keys 1/3/5 dismiss with md/pdf/whaxon respectively, escape dismisses with None, job_id is preserved on the screen.
- tests/test_tui_main.py (14 tests): MainScreen composes expected widget IDs (#catalog, #history, #target, #extra, #run, #cancel, #output, #search, #status), cancel button starts disabled, run button starts enabled, both tables have 3 columns, BINDINGS contains r/x/s/g/i/ctrl+q, focus actions move focus to the right widget, run-selected without tool/target sets status, cancel-with-nothing sets status, JobStartedMsg/JobFinishedMsg/JobFailedMsg toggle the cancel button and update the status line.

### Changed

- WhaxonApp.__init__ now accepts an optional data_dir parameter. Previously hardcoded to Path(__file__).parents[4] / "data". This lets tests, demos, and multi-profile runs point the TUI at a specific directory. No existing callers break (the parameter is optional).

### Tests

- 266 passing (was 246).

## 2026-09-28 (session 6)

### Added

- tests/test_msf_tracker.py (9 tests): _poll no-op when MSF is down, first sighting creates a session row and fires SessionStarted, second sighting does not refire, closing a session flips store status and fires SessionClosed, MSFUnavailableError mid-flight is swallowed, existing sessions get last_seen refreshed and info updated, start() spawns a daemon thread and stop() joins it, start() is idempotent, _loop swallows exceptions from a broken client.

### Tests

- 246 passing (was 237).

## 2026-09-28 (session 5)

### Added

- tests/test_runner.py (15 tests): ToolRunner.build_argv (no catalog, unknown tool, template substitution, default template, extra_args append, bad template), run_tool happy path (JobStarted/Output/Finished fire in order, stdout captured, stderr captured separately), scope enforcement (out-of-scope raises OutOfScopeError before spawn, allow_out_of_scope bypasses), missing binary (FileNotFoundError + JobFailed event), timeout (process killed + JobFailed with error=timeout), cancel (terminates running subprocess, unknown job is a no-op), and findings publication through the nmap adapter.

### Fixed

- core/events.py: JobFailed was missing the @dataclass(frozen=True, kw_only=True) decorator that every other Event subclass has. This made JobFailed(job_id=..., error=...) raise TypeError instead of instantiating. Affected the runner's tool-not-found and timeout paths, which had never been exercised by any prior test.

### Tests

- 237 passing (was 222).

## 2026-09-28 (session 4)

### Added

- tests/test_server_ai.py (18 tests): /api/ai/run (validation, 202 + store entry), /api/ai/runs (list), /api/ai/runs/<id> (found, not found, stream not found), evidence CRUD (list empty, add note, add missing body, delete, delete missing, download note returns 404), error paths (output.txt missing and present, findings.csv content type, findings.json shape, cancel unknown job returns ok=false).
- tests/test_server_portfwd.py (9 tests): GET list (empty, rows, error swallowed), POST add (missing fields, missing rhost, success with call-args assertion and pivot edge written, exception returns 500), DELETE (missing lport, success).

### Tests

- 222 passing (was 213).

### Server test coverage

- D2 complete. All Flask endpoints now have at least one test:
  - test_server.py       27 non-MSF, non-AI endpoints
  - test_server_msf.py   18 MSF endpoints
  - test_server_ai.py    18 AI + evidence + error paths
  - test_server_portfwd.py  9 portfwd endpoints
  - Total: 72 server tests covering ~46 HTTP routes.

## 2026-09-28 (session 3)

### Added

- tests/test_server_msf.py (18 tests): /api/msf/status (up/down), /api/msf/sessions (empty, live, msf-down), /api/msf/sessions/<id> (found, not found, msf-down), /api/msf/sessions/<id>/exec (missing command, msf-down, success with call-args assertion), /api/msf/modules/<type> (exploit, bad type, msf-down), /api/msf/run validation (missing module_path, bad module_type, out-of-scope target, in-scope acceptance).

### Deferred

- /api/msf/sessions/<id>/portfwd GET/POST/DELETE — deferred to session 4. Requires mocking client.connect().sessions.session(id) with .write()/.read() — deeper than FakeMSF covers.

### Tests

- 195 passing (was 177).

## 2026-09-28 (session 2)

### Added

- tests/test_server.py (27 tests): /api/health, /api/tools, /api/history, /api/jobs/<id> (detail, findings, per-job report md and fmt alias), /api/report (md, json, whaxon envelope, envelope integrity), /api/scope (get, check allowed, check denied), /api/loot, /api/tree, /api/pivot/graph, /api/settings, /ui, /, and the auth gate (required on non-loopback, accepted with correct Basic, rejected with wrong password, skipped on loopback).

### Found

- server.py defines two @app.get("/api/health") decorators. Flask keeps the first one (the readiness probe returning {status, checks}); the second ({ok, tools}) is unreachable. The shadowed route should be removed or renamed.

### Tests

- 177 passing (was 150).

## 2026-09-28 (session 1)

### Added

- tests/test_attach_chains.py (5 tests): empty store, no edges, non-from_exploit ignored, single chain, descendant traversal.
- tests/test_report_cmd.py (10 tests): engagement mode, --all alias, envelope shape, envelope integrity matches payload hash, --jobs filter, single-job paths, exit codes.
- tests/test_adapters_parse.py (9 tests): nmap severities, nikto dedup, sqlmap injectable parameter, burp XML, hashcat _find_hashes.
- WHAXON_AI_MAX_STEPS and WHAXON_AI_MIN_CONFIDENCE are now read at import time (were documented but ignored).
- Legacy ?fmt= accepted as an alias for ?format= on both report routes.
- archive/README.md explains that flask-legacy is dead code kept for context.

### Fixed

- pyproject.toml description said BACKFORGE; now says WHAXON. Author email filled in.
- cli.py: whaxon tui --help and whaxon gui --help now print usage instead of launching the interface.
- cli.py: whaxon --help no longer advertises the nonexistent forward subcommand.
- report_cmd.py: --format whaxon without --engagement now exits 2 with a clear message, matching the engagement-wide contract.
- report_cmd.py: envelope shape now matches /api/report?format=whaxon (format, version, generated, tool, engagement, integrity, payload).
- README env var table was missing WHAXON_AUTH_PASS_HASH, WHAXON_MSF_AUTOCHAIN, WHAXON_MSF_TIMEOUT, and the three provider host overrides.
- README test count was 54; correct value is 146.

### Changed

- server.py: extracted attach_chains helper into core/report.py; web route now calls it.
- server.py: envelope generated field reuses data.generated, so integrity is reproducible and verifiable against the payload.
- whaxon/__init__.py: __version__ = 0.2.0 (was empty); server and CLI both read it.

### Removed

- enterprise/, tools/, third_party/ (empty directories).
- src/whaxon/{plugins,reporting,api,catalog}/ (empty packages, no importers).
- v0.impacket git tag (local and remote).

### Tests

- 146 passing (was 122).

## Unreleased


## 2026-09-27

### Added

- Impacket adapter: secretsdump / smbclient / wmiexec. Wired through the web API. 5 unit tests.
- tests/test_impacket_adapter.py.

### Fixed

- TUI: deduplicate c binding (was colliding between cancel_job and show_chain). Now x = cancel, g = chain. Added missing textual.binding.Binding import.
- Report: to_markdown now calls _md_chains, so pivot chains actually render.
- Report: render_html now HTML-escapes markdown before wrapping in pre. A raw_line containing script tag no longer reaches the browser unescaped.

### Changed

- Scope default expanded: 127.0.0.0/8 (was 127.0.0.1), plus IPv6 link-local fe80::/10 and ULA fc00::/7.
- .gitignore deduplicated; data/scope_overrides.log untracked.
- runner._publish_findings now receives argv and target, passing them into adapter ctx.
- catalog.load() filters unknown keys from tools.json, so entries can carry metadata the Tool dataclass does not model.

### Tests

- 54 passing.
- Stale tests realigned: tests/test_report.py rewritten to match the actual per-job vs engagement contract; test_scope.py::test_missing_file_means_disabled replaced with a fail-closed assertion.

## Earlier

- feat: pivot chain graph, /api/pivot/graph, TUI g binding.
- feat: unified theme, GUI as web host, settings backend.
- feat(cli): whaxon init / up / down - no compose dependency.