# AI Layer

WHAXON includes an optional planner/executor AI layer that can drive tool selection and chaining autonomously. It is **disabled by default**.

## Enabling

    export WHAXON_AI_ENABLED=true
    export WHAXON_AI_PROVIDER=ollama          # or rules, openai, anthropic, google
    export WHAXON_AI_MODEL=qwen2.5:1.5b       # or any model your backend serves
    whaxon ai "assess 10.0.0.5 for web services"

## Providers

| Value | Backend | Notes |
| --- | --- | --- |
| `null` | none | Default. Planner stops immediately. |
| `rules` | deterministic | Regex target extraction, fixed 2-step ladder. No LLM. |
| `ollama` | local | Requires `ollama serve` on `127.0.0.1:11434`. |
| `openai` | OpenAI | Requires `OPENAI_API_KEY`. |
| `anthropic` | Anthropic | Requires `ANTHROPIC_API_KEY`. |
| `google` | Gemini | Requires `GOOGLE_API_KEY` (or `GEMINI_API_KEY`). |

## Model recommendations

Tested on a Dell Latitude 7490 (i7, 16 GB RAM, CPU only).

| Model | Params | Verdict |
| --- | --- | --- |
| `qwen2.5:0.5b` | 0.5B | **Too small.** Hallucinates targets, repeats actions, cannot follow the JSON contract reliably. Do not use. |
| `qwen2.5:1.5b` | 1.5B | **Recommended floor.** Emits valid JSON, picks real catalog tools, respects scope. Still repeats actions, but the executor guards contain it. |
| `qwen2.5:7b` and up | 7B+ | Reliable multi-step state tracking. Requires more RAM/CPU than the Latitude can offer at interactive speed. |

Models larger than 3B are slow on CPU-only hardware (30-60s per step). For interactive use on a laptop, 1.5B is the practical ceiling.

## Safety

The AI never executes anything. It emits an **Action** (a JSON proposal: run_tool / ask_human / stop). The executor validates every action against the catalog and scope before running any tool.

Four guardrails, all enforced in deterministic code:

1. **Catalog check** - `tool_id` must exist in `data/tools.json`.
2. **Scope check** - the target must pass `ScopeManager.check()`.
3. **Dedup guard** - an identical (tool, target, args) action that already ran successfully is rejected before the tool is invoked.
4. **Stagnation stop** - after 3 consecutive `ok=False` steps the loop halts, even if the step budget is not exhausted.

## Known limitations

- **Small models hallucinate targets.** `qwen2.5:0.5b` has been observed proposing `10.0.0.5` for a goal that named `127.0.0.1`. The action passes scope (RFC1918 is in-scope by default) and runs, but scans the wrong host.
- **Small models repeat actions.** `qwen2.5:1.5b` will propose the same tool repeatedly even after a successful run. The dedup guard rejects the repeats; the stagnation stop terminates the loop.
- **No streaming.** The plan is returned as one response per step.
- **No tool output feedback to the model.** The model sees finding summaries, not raw tool output.

## Configuration

| Env | Default | Notes |
| --- | --- | --- |
| `WHAXON_AI_ENABLED` | `false` | Master switch. |
| `WHAXON_AI_PROVIDER` | `null` | Backend selector. |
| `WHAXON_AI_MODEL` | per-backend | See `_default_model_for` in `core/ai_bridge.py`. |
| `WHAXON_OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama endpoint. |
| `WHAXON_AI_MAX_STEPS` | `12` | Step budget per run. |
| `WHAXON_AI_MIN_CONFIDENCE` | `0.55` | Actions below this go to `ask_human`. |

## Audit trail

Every run is persisted to the `ai_runs` and `ai_run_steps` tables. Query via:

    GET /api/ai/runs
    GET /api/ai/runs/<run_id>

Each step records the Action (proposed by the model) and the ActionResult (enforced by the executor). This is the ground truth for what happened, regardless of what the model said it would do.
