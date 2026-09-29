cd ~/Documents/workhole/"exploit database py with vnc support"/securelab_portable && cat >> docs/autonomous-loop.md << 'EOF'
# Autonomous Loop

**Status:** Design document. No code in this file is implemented yet.
**Scope:** Phase H of `whaxon_vision.md` — persistent, resumable, objective-driven autonomy.
**Non-goals:** Multi-target engagements, cost budgets, rate limiting, anything that touches the executor boundary.

## 1. Purpose

Today's `whaxon ai` loop is:

- **Interactive.** Every `ask_human` stops the process and waits for stdin.
- **Single-process.** A paused run cannot be resumed by a fresh process without reconstructing state by hand.
- **Unaware of objectives.** It follows the goal string as a hint, not as a definable success state it can track against.

Phase F gave us the human-in-the-loop machinery: approvals persist, overrides are recorded, resumes are locked. Phase H turns that machinery into a loop that can run unattended *when the human allows it*, and can be paused and resumed across process boundaries *by default*.

**The human is still in charge.** `--auto` is opt-in, gated behind `WHAXON_AI_AUTO_ALLOW=1`. Default behavior is unchanged: the loop pauses on every `ask_human` and waits.

## 2. What exists today (factual)

Verified by reading the source at v0.8.0.

| Component | Current behavior |
|---|---|
| `Executor.run(goal, job_id_prefix, target_lock, initial_history)` | Bounded loop. Calls `agent.next_action` per step. Emits `on_action`/`on_result`. Halts on `stop`, `ask_human` (if no callback), budget, or 2 consecutive failures. |
| `ask_human` callback | Async callable. If `None`, loop terminates on `ask_human`. If set, loop awaits it and appends a synthetic `ActionResult(ai_source="human")` to history. |
| `ai_runs` schema | `id, goal, provider, status, started_at, finished_at, error, phase, phase_history, pending_question, tokens_in, tokens_out, cost_usd, owner`. |
| `--resume` | Reads stored `ai_run_steps`, rebuilds history as `ActionResult` objects, appends a synthetic ack with the supplied answer, runs a fresh executor with `initial_history`. |
| Phase transitions | `Action.ask_human` with `proposed_phase` set. Executor validates the phase against the fixed vocabulary; on `y` writes to `ai_runs.phase` and `phase_history`. |
| Approval queue | `approvals` table: `(run_id, seq, user, answer, note, at)`. Web UI and CLI both write to it. |

**What's missing:**

1. **Objective tracking.** The loop has no notion of "have we made progress toward the goal." It stops when the model says stop, or when the budget runs out. No verification that the objective was met.
2. **Cross-process state.** A paused run needs the whole process to keep living, or a human to reconstruct. `--resume` approximates this but starts a fresh executor with carried-over history — not a continuation of the same logical loop.
3. **Unattended phase decisions.** Every phase transition fires an `ask_human`. In `--auto` mode this needs a policy so the loop can cross from recon to enumeration without a human at the keyboard.
4. **Auto-answer policy.** The loop has no way to answer its own questions. Every `ask_human` either blocks or (with no callback) terminates.

EOF
wc -l docs/autonomous-loop.md

cd ~/Documents/workhole/"exploit database py with vnc support"/securelab_portable && cat >> docs/autonomous-loop.md << 'EOF'
## 3. The three questions

Phase H is fundamentally three design questions, not one big one. Each gets its own answer.

### 3.1 Objective tracking

**What it means.** Given a goal like `"enumerate 10.0.0.5"`, does the loop know when the objective has been met?

**Why it matters.** Without an objective, "stop" is entirely the model's judgment. A model that stops too early leaves work undone. A model that never stops burns the step budget. Neither is verifiable after the fact.

**Three options:**

| Option | Definition | Trade-off |
|---|---|---|
| **A. Grammar** | Objectives parsed by a fixed grammar: `verb target [constraint]`. Supported verbs: `enumerate`, `scan`, `recon`, `foothold`, `test`. Each verb maps to a definition of done. | Deterministic, auditable, but rigid — free-text goals must be rephrased. |
| **B. Heuristic** | Each phase has a "done" signal. `recon` done when open ports recorded. `enumeration` done when endpoints or versions found. `vulnerability` done when CVEs matched. Combined with a step budget as a backstop. | Flexible, but the heuristics are guesses. |
| **C. LLM judgment** | The planner decides when the objective is met, and the executor verifies that the stop decision is *reasoned*, not just asserted. | Matches how humans evaluate — but the source-of-truth problem returns. |

**Recommendation: B, with A as an optional gate.**

Heuristics per phase, evaluated deterministically against findings in the store:

- **`recon` done** when `nmap` has produced at least one `open_port` finding against the target, OR when the recon step budget (default 3) is exhausted with no ports found.
- **`enumeration` done** when at least one endpoint, version, or service fingerprint has been recorded, OR enumeration budget (default 4) exhausted.
- **`vulnerability` done** when a vuln-scanner has run against each discovered service, OR the vuln budget (default 3) is exhausted.
- **`initial-access` done** when any session exists for the target, OR the initial-access budget (default 3) is exhausted with no session.
- **`post-access` done** when at least one loot-kind finding has been recorded from inside a session, OR post-access budget exhausted.
- **`lateral` done** when either a new host has been discovered through the pivot, OR the lateral budget is exhausted.

The heuristic answers "is the *phase* done," not "is the *objective* done." The objective is done when the phase the loop is in is the terminal phase for the objective's verb:

| Verb | Terminal phase |
|---|---|
| `recon` | `recon` |
| `enumerate` | `enumeration` |
| `test` | `vulnerability` |
| `foothold` | `initial-access` |
| `exploit` | `post-access` |

If the goal doesn't parse to a known verb, the loop runs until the model emits `stop` or the budget runs out — the current behavior, unchanged.

### 3.2 Cross-process persistence

**What it means.** A run pauses. The process exits. A new process resumes it. The loop continues as if it never stopped.

**What "resumption" needs to preserve:**

- The goal (already stored: `ai_runs.goal`)
- The full history (`ai_run_steps` — already stored)
- The current phase (`ai_runs.phase` — already stored)
- The step budget consumed so far (`len(ai_run_steps)` — derivable)
- The consecutive-failure counter (`ai_runs.consecutive_failures` — **new column needed**)
- Whether the run is in `--auto` mode (`ai_runs.auto` — **new column needed**)

**The mechanism.** Today's `--resume` rebuilds history from steps and starts a fresh loop. That's *approximate* resumption. The design change is small: two new columns carry the state that isn't derivable. `Executor.run` gains an optional `resume_state: dict | None` parameter that seeds `consecutive_failures` from the store when provided.

**Why not a full state machine?** Because the store already *is* the state machine. Every Action, every Result, every phase transition is persisted. Rebuilding history from `ai_run_steps` produces the same loop the previous process was running. The only thing not captured is the failure counter — a small addition.

**Resumability is not "rehydrate Python objects."** It's "replay stored state through the same deterministic loop." The loop is deterministic; the store is durable; resumption is just replay.

### 3.3 Unattended phase decisions

**What it means.** In `--auto` mode, the loop should cross phase boundaries without a human answering each transition.

**The policy.** `--auto` mode answers with one of:

1. **Auto-approve** if the proposed phase is in `WHAXON_AI_AUTO_PHASES` (comma-separated env var).
2. **Auto-deny** if the proposed phase is not in the list, or if the env var is unset. Deny means: append a synthetic answer of `"n"`, the loop continues from the current phase.
3. **Auto-ask** if the proposed phase is in the list but `WHAXON_AI_AUTO_CONFIRM=1` — this re-enables the interactive prompt for transitions even in auto mode.

**Default `WHAXON_AI_AUTO_PHASES` is empty.** With no phases listed, `--auto` mode crosses no boundaries. The loop can still do multi-step work within a phase, but a phase change is refused. This is the safest default.

**The dangerous list.** The three high-risk phases — `initial-access`, `post-access`, `lateral` — should never be in `WHAXON_AI_AUTO_PHASES` by default, and their inclusion should log a warning at run start.

### 3.4 Auto-answer policy

**What it means.** In `--auto` mode, the loop answers its own `ask_human` questions that aren't phase transitions.

**The general case.** A non-transition `ask_human` has no `proposed_phase`. The loop can:

- **Answer `skip`** — the loop drops the pending action, continues. Default in auto mode.
- **Answer `stop`** — the loop terminates cleanly with a rationale.

**Recommendation: `skip`.** Least-committal answer. Drops the ambiguous step and continues, letting the model try a different approach on the next step. If the model keeps producing `ask_human`s, the step budget will exhaust naturally.

**Never in auto mode:**

- The loop never emits a raw tool action on the human's behalf when the answer was ambiguous.
- The loop never auto-approves a scope expansion.
- The loop never auto-approves a run against an out-of-scope target. That's the executor's check, not the answerer's job.

EOF
wc -l docs/autonomous-loop.md

cd ~/Documents/workhole/"exploit database py with vnc support"/securelab_portable && cat >> docs/autonomous-loop.md << 'EOF'
## 4. The mode

**New flag:** `whaxon ai "<goal>" --auto`.

**New env vars:**

| Env | Default | Meaning |
|---|---|---|
| `WHAXON_AI_AUTO_ALLOW` | `0` | Master switch. `--auto` refuses to run if this is not `1`. Prevents accidental unattended runs. |
| `WHAXON_AI_AUTO_PHASES` | `` (empty) | Comma-separated phases the loop may cross unattended. |
| `WHAXON_AI_AUTO_CONFIRM` | `0` | If `1`, phase transitions in the allowed list still prompt. |
| `WHAXON_AI_AUTO_MAX_STEPS` | `50` | Step budget for `--auto` runs. Separate from the interactive default of 12. |

**Precedence:**

1. If `--auto` is not passed: current behavior, no changes.
2. If `--auto` is passed and `WHAXON_AI_AUTO_ALLOW != 1`: exit with a clear error.
3. If `--auto` is passed and `WHAXON_AI_AUTO_ALLOW == 1`: the auto-answer callback replaces `_stdin_ask_human`.

**The run record.** `ai_runs.auto` (new column, 0/1) records whether the run was started in auto mode. A resumed run inherits the mode from the stored flag.

**Interruption.** `--auto` can be interrupted with Ctrl+C. The run is marked `status='paused'` and can be resumed with `--resume` in either mode.

## 5. The loop after Phase H

    Executor.run(goal, initial_history, resume_state) {
        audit = agent.audit(goal)
        if not feasible: return [stop]

        history = initial_history or []
        consecutive_failures = resume_state.get("consecutive_failures", 0)
        start_step = len(history) + 1
        for step in start_step..max_steps:
            action = agent.next_action(goal, history, catalog, scope, step, phase, prior_runs)
            on_action(action)

            if action.kind == "stop":
                on_result(...); return history

            if action.kind == "ask_human":
                on_result(...)
                if ask_human is None: return history
                answer = await ask_human(action)
                history.append(synthetic_ack(answer))
                on_result(synthetic_ack)
                if action.proposed_phase and answer_was_yes(answer):
                    phase_set(action.proposed_phase)
                if phase_is_terminal_for_objective(goal):
                    history.append(synthetic_stop("objective met"))
                    return history
                continue

            if action.kind == "run_tool":
                result = await validate_and_run(action, ...)
                history.append(result); on_result(result)
                if result.ok: consecutive_failures = 0
                else:
                    consecutive_failures += 1
                    store.set_ai_run_consecutive_failures(run_id, consecutive_failures)
                    if consecutive_failures >= 2:
                        history.append(synthetic_stop("stagnation"))
                        return history
        return history
    }

**Two new lines compared to today:** the objective-completion check after phase transitions, and the `consecutive_failures` persist.

## 6. Migration plan

| Step | Change | Scope |
|---|---|---|
| 1 | `ai_runs` gains `consecutive_failures INTEGER DEFAULT 0` and `auto INTEGER DEFAULT 0`. Idempotent migration. | `store.py` |
| 2 | `JobStore.set_ai_run_consecutive_failures`, `JobStore.get_ai_run` returns the fields. | `store.py` |
| 3 | `Executor.run` accepts `resume_state: dict | None`. Seeds `consecutive_failures` from it. Persists the counter via an injected callable. | `ai/executor.py` |
| 4 | `ai/objectives.py` — verb parser and `is_terminal_phase(goal, phase)` helper. | new file |
| 5 | `ai/auto_answers.py` — policy module: `answer_question(action, goal, env) -> str`. Returns `y` / `n` / `skip` based on phase list, env vars, action kind. | new file |
| 6 | `ai_cmd.py` — `--auto` flag, mode gate, wire the auto-answer callback, thread `resume_state` through `_run_fresh` and `_resume_body`. | `ai_cmd.py` |
| 7 | `--resume` reads `auto` from the store and reconstructs the same mode. | `ai_cmd.py` |

**Steps 1–4 are prerequisites for step 6.** Step 5 is independent. Step 7 is a small addition.

**Estimated: 3 sessions.** Session 1: steps 1–3 (store + executor). Session 2: steps 4–5 (objectives + auto_answers). Session 3: steps 6–7 (CLI wiring) plus tests.

EOF
wc -l docs/autonomous-loop.md

cd ~/Documents/workhole/"exploit database py with vnc support"/securelab_portable && cat >> docs/autonomous-loop.md << 'EOF'
## 7. What this document does not answer

1. **Multi-target engagements.** The loop tracks one goal, one target. "Enumerate 10.0.0.0/24" is not supported; the loop would need to fan out per host and aggregate. Deferred.
2. **Cost budgets.** `--auto` runs have a step budget but not a cost budget. A run that hits 50 steps on `gpt-4o` costs real money. Enforcement is deferred; the tokens and cost are already recorded, so enforcement can be added later without schema changes.
3. **Rate limiting.** The loop makes one LLM call per step. At 50 steps in a fast loop, that's 50 calls in a short window. Provider rate limits may fire. Retry-with-backoff was attempted in session 47 and reverted; a proper design is still missing.
4. **Concurrent runs.** The lock file prevents two resumes of the *same* run. Nothing prevents two `--auto` runs against the same target. Deferred.
5. **What an auto-answered run reports.** The report currently shows the human answer in history; in auto mode the answers are `"skip"` and `"y"` with `ai_source="human"` — misleading, because no human answered. Should the `ai_source` be `"auto"` instead? Design decision deferred.
6. **The safety of the terminal-phase heuristic.** If the objective's terminal phase is wrong, the loop stops early or runs long. The heuristics in §3.1 are the first guess, not a validated set.
7. **What happens when the objective is met but the model disagrees.** If the heuristic says "recon done" but the model wants to keep running, who wins? Recommendation: heuristic wins — it's deterministic. But this is a policy choice, not a technical one.

## 8. What ships in v1 of Phase H vs. what waits

**v1 (this design, ~3 sessions):**

- `ai_runs.consecutive_failures` and `ai_runs.auto` columns
- `Executor.run` accepts `resume_state`
- `ai/objectives.py` with the five-verb grammar and terminal-phase mapping
- `ai/auto_answers.py` with the env-var-driven policy
- `whaxon ai --auto` gated on `WHAXON_AI_AUTO_ALLOW=1`
- `--resume` inherits the mode from the store
- Tests for objectives, auto_answers, resume_state, and the full loop

**v2 (later):**

- Cost budget enforcement
- Multi-target fan-out
- Concurrent run isolation
- `ai_source="auto"` in history for auto-answered steps

**Never in scope:**

- Unattended runs against non-consenting targets
- Auto-approval of scope expansion
- Circumventing the executor boundary
- Any behavior that changes what the LLM may propose

## 9. Closing note

Phase H is the last phase the vision doc names. What it delivers is not "the AI does everything on its own" — it's "the AI can keep working without a human at the keyboard, *when the human has explicitly allowed it*." The default stays interactive. `--auto` is a mode, not the new normal.

The human is still in charge. The store is still the source of truth. The executor's boundary still holds. Phase H changes who answers the questions, not what the questions are or who they're answered for.
EOF
wc -l docs/autonomous-loop.md && head -5 docs/autonomous-loop.md && git status --short