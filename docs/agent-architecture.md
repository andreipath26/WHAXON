# Agent Architecture

**Status:** Design document. No code in this file is implemented yet.
**Scope:** The autonomous driving layer described in `whaxon_vision.md`.
**Non-goals:** Anything that changes the pipeline, the executor's deterministic boundary, or the adapter layer.

## 1. Purpose

WHAXON today runs one tool at a time. A human picks the tool, picks the
target, presses run, reads the output, and decides what to do next. The
AI layer (`whaxon/ai/`) can propose a single next action and a
deterministic executor will validate and run it — but only within a
bounded loop that stops at the first `ask_human` and never resumes.

This document describes how to grow that into an agent that can drive
a whole engagement: given an objective, plan a sequence of steps, run
them, react to results, and hand control to the human whenever it needs
to. **The human stays in charge at all times.** The agent proposes; the
executor disposes; the human decides what the executor is allowed to do.

## 2. What exists today (factual)

Verified by reading the source, not from memory.

| Module | What it provides |
|---|---|
| `whaxon/ai/actions.py` | `Action` (frozen dataclass, one of `run_tool` / `ask_human` / `stop`), `ActionResult` (per-step outcome fed back to the planner) |
| `whaxon/ai/agent.py` | `Agent.next_action()` — one step of planning; `Agent.audit()` — pre-run feasibility check |
| `whaxon/ai/provider.py` | `Provider` ABC: `plan_step(...)`, `audit_prompt(...)`. `NullProvider` returns stop immediately. |
| `whaxon/ai/providers/rules.py` | `RulesProvider` — deterministic ladder (nmap, then nikto if a web port is up, then stop) |
| `whaxon/ai/providers/llm.py` | `LLMProvider` — planner over any `LLMBackend` (Ollama, OpenAI, Anthropic, Google) |
| `whaxon/ai/executor.py` | `Executor.run()` — the loop. Validates each Action against catalog, scope, target_lock, dedup. Bounds: `ExecutorLimits(max_steps, max_wall_seconds, min_confidence)`. Halts on 2 consecutive failures. |
| `whaxon/core/ai_bridge.py` | The single sanctioned import point from `core/` into `whaxon/ai/`. Everything else in `core/` and `adapters/` is forbidden from importing `whaxon.ai` (enforced by `tests/test_ai_boundary.py` and CI). |

**Critical current limitation:** `Executor.run()` returns the moment an
`ask_human` Action is emitted. There is no resume. The loop cannot pause
and continue in a later process.

## 3. The four-layer model

```
┌─────────────────────────────────────────────────────┐
│  Human (in charge)                                  │
│    approves / rejects / adjusts / takes over        │
└─────────────────────────────────────────────────────┘
                    ▲
                    │ approvals, guidance, overrides
                    ▼
┌─────────────────────────────────────────────────────┐
│  Agent (planner)                                    │
│    proposes Action objects, tracks phases, asks     │
│    for help when uncertain                          │
└─────────────────────────────────────────────────────┘
                    ▲
                    │ Action objects
                    ▼
┌─────────────────────────────────────────────────────┐
│  Executor (deterministic)                           │
│    catalog check, scope check, target lock, dedup,  │
│    stagnation stop — the existing machinery         │
└─────────────────────────────────────────────────────┘
                    ▲
                    │ JobStarted / JobOutput / JobFindings
                    ▼
┌─────────────────────────────────────────────────────┐
│  Pipeline (existing WHAXON)                         │
│    catalog + runner + adapters + store + events +   │
│    correlation + reports                            │
└─────────────────────────────────────────────────────┘
```

**Nothing in the bottom two layers changes** for this design. The agent
is a new top layer. The pipeline is what makes it possible.

## 4. Objectives

An **objective** is a short natural-language sentence describing what
the run should accomplish. Examples:

- `"enumerate 10.0.0.5"` — reconnaissance only, no exploitation
- `"find a foothold on 10.0.0.5"` — recon through initial access
- `"test the vsftpd service on 10.0.0.5"` — narrow, tool-specific
- `"recon scanme.nmap.org"` — public-target practice

Objectives are **not**: "pwn X", "own the whole subnet", "get domain
admin". Those are outcomes, not tasks — they don't terminate in a
definable way, and they encourage the agent to attempt unauthorised
actions. The objective grammar is deliberately modest.

**How the agent knows it's been met.** Three signals:

1. **The LLM planner emits `stop`** with a rationale. Default case.
2. **The budget runs out** (max_steps). The run ends with a "budget exhausted" stop.
3. **Stagnation** — 2 consecutive failed steps. The run halts.

There is no verification that the objective *was* accomplished, only
that the agent *decided it was done*. That's honest: this is a
task-execution loop, not a goal-verification system. The human reads
the report and decides whether the objective is achieved.

## 5. Phases

A **phase** is a named stage of the kill chain with a scoped set of
tools and a definition of "enough has been done here."

| Phase | Tools | Definition of done |
|---|---|---|
| `recon` | nmap, masscan (plugin), whois, dig, subfinder (future) | Ports mapped; DNS records collected; subdomains enumerated |
| `enumeration` | gobuster, ffuf, whatweb, wpscan, nuclei (light mode), nikto | Endpoints discovered; web tech identified; low-severity issues logged |
| `vulnerability` | nuclei, sqlmap, nikto (deep), searchsploit lookups | Known CVEs identified for detected versions |
| `initial-access` | msf (exploit modules), impacket (protocol exploits) | At least one session obtained |
| `post-access` | msf (post modules), impacket (secretsdump, smbclient, wmiexec), hashcat | Credentials extracted; privilege level known; loot catalogued |
| `lateral` | netexec (plugin), impacket (with extracted creds), ligolo-ng (future) | Reachable hosts beyond the initial target mapped |
| `done` | — | Objective met or budget exhausted |

Phases are **suggested by the agent, confirmed by the human**. The agent
proposes a transition ("recon is complete, move to enumeration?") via an
`ask_human` Action. The human answers y/n. This is the phase-boundary
check.

**Where phase state lives.** The `ai_runs` table (in `data/whaxon.db`)
gains a `phase` column and a `phase_history` JSON column. Phase
transitions are appended to `phase_history` so the whole progression is
auditable after the run.

**v1 scope:** phases are informational. The agent proposes them, the
report shows them, but they don't restrict which tools can run in which
phase. **v2 scope:** tools are filtered by phase — the planner only
sees the tools relevant to its current phase, which both narrows the
search space and reduces the chance of the LLM proposing something
nonsensical ("run hashcat against 10.0.0.5 in the recon phase").

## 6. The loop

**Today:**

```
executor.run() calls agent.next_action() in a bounded for-loop.
ask_human -> loop ends.
No resume. No phase tracking. No persistence beyond ai_runs.
```

**Target (v1):**

```
executor.run(goal) {
    audit = agent.audit(goal)
    if not audit.feasible: return [stop]
    history = []
    for step in 1..max_steps:
        action = agent.next_action(goal, history, catalog, scope, step, phase)
        on_action(action)
        if action.kind == "stop":        return history
        if action.kind == "ask_human":
            answer = await self.ask_human(action)   # <-- new: pauses and resumes
            history.append(synthetic_result_from(answer))
            continue                                 # <-- new: loop continues
        if action.kind == "run_tool":
            result = await self._validate_and_run(action, history)
            history.append(result)
            on_result(result)
            if not result.ok: consecutive_failures += 1
            else:              consecutive_failures = 0
            if consecutive_failures >= 2:
                return history  # stagnation stop
    return history
}
```

The only new primitive is `await self.ask_human(action)`. Everything else
in the loop is unchanged from today.

**`ask_human` mechanism (v1):**

The Executor gains a new constructor argument:

```python
ask_human: Callable[[Action], Awaitable[str]] | None = None
```

If `None`, `ask_human` behaves as today (loop ends). If provided, the
executor awaits it. The interface (CLI, web route) provides the
implementation.

**CLI implementation:**

```python
async def _cli_ask_human(action: Action) -> str:
    print(f"[agent] {action.rationale}")
    return await asyncio.to_thread(lambda: input("> ").strip())
```

The `asyncio.to_thread` is because `input()` is blocking; the loop is
async. This keeps the executor's loop shape intact.

**Answer semantics:**

| Answer | Meaning |
|---|---|
| `y` / `yes` | Approve. If the action was `run_tool`, run it. If it was a phase transition, transition. |
| `n` / `no` | Reject. Feed back to the planner; next step sees the rejection in history. |
| `skip` | Drop the action, continue to the next step without running anything. |
| any other text | Freeform guidance. Appended to history as a synthetic result with the text as `summary`. |

**Persistence (v2):** `ai_runs` gains `status='waiting'` and a
`pending_question` JSON column. A new CLI subcommand:

```
whaxon ai --resume <run_id> --answer y
```

reconstructs the executor state from `ai_runs` and `ai_run_steps` and
resumes at the next step. This survives crashes and lets the human
answer hours later. **Out of scope for v1.**

## 7. State persistence

**Per-run state that must survive a crash (v2):**

| State | Where |
|---|---|
| Run id, goal, phase, current step | `ai_runs` row |
| Every step's Action + ActionResult | `ai_run_steps` rows (already exists) |
| Pending question (if `status='waiting'`) | `ai_runs.pending_question` |
| Phase history | `ai_runs.phase_history` (JSON) |
| Answer to the last question | Appended to `ai_run_steps` |

**Per-run state that may be in-memory only (v1):**

Everything. A crashed run is a lost run. The findings it produced are
still in `findings` (the store subscribes to the event bus), but the
agent's history is gone and the run cannot be resumed.

**v1 → v2 transition:** adding the `pending_question` column and a
`--resume` subcommand. The `ai_runs` schema already exists and has
`status`; the change is small.

## 8. Human-in-the-loop protocol

**Who the human is (v1):** the person running `whaxon ai "..."` in a
terminal. One human, one run, blocking. No queue. No web UI. No
concurrency.

**When the human is asked:**

1. **When the planner is uncertain.** LLM confidence below
   `WHAXON_AI_MIN_CONFIDENCE` (default 0.55) → automatic demotion to
   `ask_human`. This is already in `Agent.next_action`.
2. **When the planner asks.** LLM explicitly emits `ask_human` with a
   rationale.
3. **At phase boundaries.** The planner proposes a transition; human
   confirms.
4. **When an action fails twice in a row.** The run halts; the human
   gets a `stop` with the failure reason. Not a resume — a fresh run.

**What the human sees:**

```
[agent] Step 4 of 12. Phase: enumeration.
[agent] Proposing: run gobuster against 10.0.0.5 with extra_args
        "-u http://10.0.0.5 -w /usr/share/wordlists/dirb/common.txt"
[agent] Rationale: nmap found port 80 open; gobuster will enumerate
        endpoints on the web service.
[agent] Confidence: 0.72
[agent] Approve? [y/n/skip/text]
>
```

**What the human answers:** see section 6.

**What happens when the human never answers:** the CLI blocks. There is
no timeout in v1. If you walk away, the run waits. `Ctrl+C` cancels the
run cleanly; the store still has every finding produced so far.

**Where the human CANNOT intervene:** mid-run, the human cannot change
the executor's `ExecutorLimits`, cannot add targets to scope, cannot
change the objective. Any of these requires killing the run and starting
a fresh one. This is deliberate. v2 may add a "pause and reconfigure"
verb.

## 9. Scope expansion policy

**The problem.** The agent runs nmap on `10.0.0.5`. nmap's output
reveals a DNS name (`db.internal`), a second IP (`10.0.0.6`), and a
SMB share name. Does the agent get to scan `10.0.0.6`? Scan
`db.internal`? Look for the share?

**Three policies, must pick one:**

| Policy | Behavior | Legal posture |
|---|---|---|
| **Strict** | Only explicitly-listed targets. Discovered hosts are never automatically in scope. The agent may propose adding one; the human must approve. | Safest. Most pentest contracts are written for explicitly-listed targets. |
| **Inherited** | Any host that resolves from an in-scope domain, and any host in the same RFC1918 subnet as an in-scope host, is in scope. | Common in internal pentests. Riskier if the discovered range includes systems outside the written scope. |
| **Recommended** | As inherited, but every auto-expansion is logged and the human can veto before the first action against the discovered host. | Middle ground. |

**v1 ships `strict`.** Every discovered host is out of scope until the
human adds it to `data/scope.json` and re-runs. The agent may *propose*
expansion via `ask_human`, but the executor will reject any action
against an out-of-scope target regardless of the answer. Scope is
enforced at the executor's check, not at the LLM's.

**Why strict for v1:**

1. Scope enforcement is the safety property the whole tool rests on.
   Loosening it is a policy change, not a feature.
2. Discovery-driven expansion makes the tool's behavior hard to predict.
   An autonomous agent that scans a subnet it found is a legal and
   operational liability.
3. Adding inherited or recommended later is a small change to the scope
   checker plus a config flag. Starting strict and moving to looser is
   easy. Starting loose and trying to tighten is a rewrite.

**Config:**

```
WHAXON_AI_SCOPE_EXPANSION=strict|inherited|recommended
```

Default `strict`. Documented in `README.md` and `docs/scope.md`. Any
value other than `strict` prints a startup warning.

## 10. LLM authority

**The LLM may decide on its own:**

- Which tool to run next (within its current phase's tool set)
- What extra args to pass
- When to stop
- When to ask a question

**The LLM may propose but not execute:**

- Expanding the scope (subject to `ask_human` and executor check)
- Transitioning phases (subject to `ask_human`)
- Running a tool not in the catalog (**never allowed** — executor refuses)
- Running against a target outside scope (**never allowed** — executor refuses)
- Running the same action twice successfully (**never allowed** — dedup check)
- Exceeding the step budget (**never allowed** — bounded loop)

**The LLM may never:**

- Write to the store
- Modify `data/scope.json`
- Spawn a subprocess (only the executor does this)
- Read raw tool output (only structured findings and summaries)
- Access the filesystem except through the pipeline's own tools
- Reach any tool that isn't in `data/tools.json`

These are enforced by the executor, not by prompting. The LLM cannot
talk its way past a check that happens after it emits an Action.

## 11. Cross-run learning

**v1: none.** Every run starts from scratch. The agent's history is
empty at step 1. Nothing from previous runs is visible.

**Rationale:** cross-run learning requires the agent to read the store,
which violates the "planner sees only structured findings, never the
store" boundary. Opening that boundary is a meaningful change to the
threat model and should be done deliberately, with a separate design.

**Future direction (v2+):** the agent is given a *summary* of prior
runs — "in the last 5 runs against this target, gobuster found X, Y, Z;
no new findings were produced" — computed by a deterministic function,
not read directly from the store. That keeps the boundary intact while
letting the planner benefit from history.

## 12. What "done" looks like

Three ways a run ends:

1. **The LLM emits `stop`.** Default, common case. The report shows the
   final rationale.
2. **The step budget is exhausted.** `for step in 1..max_steps` falls
   through. The last entry in `ai_run_steps` is a synthetic stop.
3. **Stagnation.** Two consecutive failed steps. The executor halts with
   a "halting on stagnation" result.

**The report** includes a run summary at the top: phase history, number
of steps, findings count, and whether the run stopped naturally or was
cut off. The human reads this and decides whether the objective was
achieved.

## 13. Migration plan

What code changes, in what order, to get from today to the v1 design.

| Step | Change | Scope |
|---|---|---|
| 1 | `Executor` gains `ask_human: Callable[[Action], Awaitable[str]] | None`. When set, `ask_human` Actions pause and resume instead of terminating. When unset, existing behavior is preserved. | 1 file, `executor.py`. Tests for both paths. |
| 2 | `ai_runs` gains a `phase` column, default `"recon"`. `store.create_ai_run` and `get_ai_run` round-trip it. | `store.py` and a small migration. Tests. |
| 3 | `Agent.next_action` gains a `phase` parameter, passed through to `provider.plan_step`. `LLMProvider` includes the phase in its prompt. | `agent.py`, `provider.py`, `providers/llm.py`. |
| 4 | `whaxon ai` CLI (`ai_cmd.py`) uses the new `ask_human` callback. Prints the question, reads stdin, resumes the loop. | `interfaces/cli/ai_cmd.py`. |
| 5 | Phase transitions become `ask_human` Actions emitted by the LLM when it decides a phase is complete. Phase string is stored in `ai_runs.phase`. | Design done; implementation is a small addition to `LLMProvider` + the store field. |
| 6 | `WHAXON_AI_SCOPE_EXPANSION` env var, read by `ai_bridge.build_executor`. Passed to the executor's scope check. | `ai_bridge.py`, `scope.py`, `executor.py`. |
| 7 | **`whaxon ai --resume <run_id>`** — persistence of paused runs. `ai_runs.pending_question` column. | Out of scope for v1; see section 6. |

**Steps 1–4 are the v1 MVP.** After step 4, `whaxon ai "enumerate 10.0.0.5"`
works, the human approves each step, and the loop runs to completion
or the human kills it.

**Steps 5–6 are v1.x.** Phase awareness and configurable scope policy.

**Step 7 is v2.** Persistent, resumable runs.

## 14. What this document does not answer

Honest list of open questions deferred to future sessions:

1. **Multi-user concurrency.** If two humans run `whaxon ai` at once
   against the same store, do they see each other's runs? Probably not,
   but the store is shared. Deferred.
2. **Cost tracking.** LLM calls cost real money. Nothing in the current
   code tracks per-run cost. Needed before the agent runs unattended
   for hours. Deferred.
3. **Rate limiting the LLM.** Same problem as NVD rate limits — a
   run that fires 50 LLM calls in 30 seconds will hit provider rate
   limits and fail. Not handled today. Deferred.
4. **What an LLM's "confidence" actually means.** Today it's a float
   the model emits. It has no calibration. In practice it's noise below
   0.5 and reliable above 0.9. The threshold of 0.55 is a first guess,
   not a tuned value. Needs empirical work.
5. **Structured objectives.** "Enumerate 10.0.0.5" is parsed by the
   LLM, not by a grammar. A stricter objective grammar would make the
   audit step more reliable but less flexible. Trade-off not resolved.
6. **Interaction with `/api/ai/run`.** The web route already submits
   runs asynchronously. When the executor's `ask_human` blocks, does
   the web route block too? Needs a "pause into DB" primitive, which
   is the v2 work. Deferred.
7. **The safety implications of the phase model.** Some phases
   (initial-access, lateral, post-access) can cause real harm to real
   systems if authorised incorrectly. The doc treats phases as
   informational. Whether the tool should refuse to enter those phases
   without additional warnings is a policy question, not a technical
   one. Deferred.

## 15. What ships in v1 vs. what waits

**v1 (this design, ~4 sessions):**

- `ask_human` becomes a pause/resume instead of a terminate
- CLI-only human-in-the-loop
- Phase field on `ai_runs`, no enforcement
- Scope expansion: strict only
- `whaxon ai "objective"` works end-to-end

**v2 (later):**

- Persistent paused runs (`--resume`)
- Web UI for approval
- Inherited / recommended scope expansion
- Cross-run summaries
- Cost and rate limiting

**v3 (Phase 4 in the vision):**

- Phase-scoped tool filtering
- ML-driven severity re-scoring
- Report narrative synthesis

**Never in scope:**

- Fully unattended runs against non-consenting targets
- Operations that persist on target systems beyond the engagement window
- Circumventing the executor boundary in any way
## 16. Approval queue and multi-user (v2 design note)

v1 ships single-user, single-run, blocking. `whaxon ai --resume` (session 36) makes paused runs persistable, but the approval loop is still synchronous stdin in the same terminal.

**Multi-user model.** Two problems appear when N humans share a WHAXON instance:
1. Multiple paused runs at once. Each has a `pending_question` (session 36). The CLI prompt doesn't scale.
2. Who approved what. The executor currently records `ai_source="human"` with no user identity.

**Proposed shape.**
- `ai_runs` gains an `owner` column (default `"local"`). Set at `create_ai_run` from an env var or CLI flag.
- `ai_runs` gains an `approvals` table: `(run_id, seq, user, answer, at, note)`. Every human answer is a row, not a mutation of the run's status.
- A new route `GET /api/ai/pending` lists all runs with `status='waiting'`, filtered by owner unless the caller is admin.
- Web UI gains a queue view: table of pending questions, each with approve/reject/skip buttons and a free-text field. Clicking submits `POST /api/ai/runs/<id>/answer`.
- The existing CLI `--resume` becomes one frontend for the same answer API.

**Authority boundary.** The queue does not change what the LLM may propose — the executor's validation is still the last word. The queue changes *who* can approve. Authorization for approvals is a policy decision: any authenticated user, or only the run's owner, or a role with an approval permission. Recommended: owner-only by default, admin override.

**What this does NOT need.**
- No change to the executor's loop. The `ask_human` callback contract stays the same.
- No change to the store's `ai_run_steps` schema.
- No change to the LLM provider interface.

**Effort estimate.** Two sessions. Session 1: schema (`owner` + `approvals` table), `/api/ai/pending`, `POST /api/ai/runs/<id>/answer`, tests. Session 2: web UI queue view, tests, docs. The CLI keeps working unchanged throughout — this is additive.

**Blocking dependency.** None. Can be built anytime.

## 17. GUI slice of Phase D (deferred)

The report (session 28), web UI (session 30), and TUI (session 36) all show AI runs with phase and status. The GUI (PySide6) does not.

**Why deferred, not built.** Two reasons:
1. The GUI is a thin wrapper around the web interface — `interfaces/gui/embed.py` loads the web UI in a WebEngineView. Anything visible in the web UI is visible in the GUI, already.
2. Building a native PySide6 AI-runs panel would mean duplicating logic that already exists in three places (report, web, TUI). The value is aesthetic, not functional.

**If it becomes worth doing.** The minimal version is a `QTableView` bound to `core.store.list_ai_runs()`, refreshed on a timer. Roughly 150 lines. Not worth a dedicated session unless someone actually wants a native app feel; the web-in-GUI embedding already covers the use case.

**Recommendation.** Do nothing. If a user complains the GUI lacks AI visibility, redirect to the web UI tab (which is what the GUI renders anyway).

## 16. Approval queue and multi-user (v2 design note)

v1 ships single-user, single-run, blocking. Multi-user breaks the CLI stdin model.

**Proposed shape.**
- ai_runs gains an owner column (default "local").
- New approvals table: (run_id, seq, user, answer, at, note). Every answer is a row, not a status mutation.
- New route GET /api/ai/pending lists waiting runs, filtered by owner.
- Web UI queue view with approve/reject/skip buttons.
- Existing CLI --resume becomes one frontend for the same answer API.

**Authority.** Queue does not change what the LLM may propose. It changes who can approve. Recommend owner-only by default, admin override.

**No changes needed to.** The executor loop, ai_run_steps schema, LLM provider interface.

**Effort.** Two sessions: schema + API, then web UI. CLI keeps working throughout.

## 17. GUI slice of Phase D (deferred)

Report (28), web UI (30), and TUI (36) all show AI runs with phase and status. GUI does not.

**Why deferred.** The GUI is a thin wrapper around the web interface — interfaces/gui/embed.py loads the web UI in a WebEngineView. Anything visible in the web UI is visible in the GUI already. Building a native PySide6 panel duplicates logic that exists in three places.

**If it becomes worth doing.** QTableView bound to core.store.list_ai_runs(), refreshed on a timer. ~150 lines. Not worth a session unless someone wants native-app feel.

**Recommendation.** Do nothing.


## 18. Resolved / deferred status of §14 questions

Reviewed after sessions 39-47. Every item is now either answered or deferred with rationale.

| # | Question | Status | Where |
|---|---|---|---|
| 1 | Multi-user concurrency | **Partial.** Approval queue + owner column handle multi-user approvals. Per-owner run visibility in the web UI deferred. | sessions 39, 40 |
| 2 | Cost tracking | **Answered.** tokens_in/out/cost_usd, LLMProvider.usage, _record_usage. | session 38 |
| 3 | LLM rate limiting | **Deferred.** No backoff on 429/503. Attempted session 47; reverted. | — |
| 4 | Confidence calibration | **Deferred.** Empirical, not code. | — |
| 5 | Structured objectives | **Deferred.** Grammar trade-off unresolved. | — |
| 6 | /api/ai/run interaction | **Partial.** Resume mechanism exists. Web route pause attempted session 47; reverted. | — |
| 7 | Phase safety implications | **Deferred.** Policy question. | — |
