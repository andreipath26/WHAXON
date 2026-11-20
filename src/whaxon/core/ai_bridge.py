"""The one door between whaxon.core and whaxon.ai.

This module is the ONLY place in core that imports from whaxon.ai.
Everything else in core and all of adapters stays clean; the
boundary test whitelists this file explicitly.

Responsibility: build a fully-wired Executor from a Core instance,
binding the six callables the executor needs to real Core methods.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from whaxon.ai import Agent, Executor, ExecutorLimits, Provider
from whaxon.ai.phases import filter_catalog as _filter_catalog_by_phase
from whaxon.ai.provider import NullProvider
from whaxon.ai.scope_policy import read_policy as read_scope_policy

from . import Core


def propose_v2_workflow_plan(
    core: Core,
    *,
    mission_id: str,
    plan_id: str,
    goal: str,
    target: str,
    provider: Provider | None = None,
    history: list[dict[str, Any]] | None = None,
    step: int = 1,
) -> dict[str, Any]:
    """Turn one AI action into a reviewable, provider-pinned V2 plan.

    This is a planning handoff only: it does not grant approval, enqueue a run,
    or dispatch a tool. Unsupported actions, uninstalled providers, dynamic
    arguments and target drift fail closed.
    """
    import uuid

    from whaxon.ai import Agent
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    for name, value in (("mission_id", mission_id), ("plan_id", plan_id),
                        ("goal", goal), ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise ValueError(f"{name} must be normalized non-empty text")
    if isinstance(step, bool) or not isinstance(step, int) or step < 1:
        raise ValueError("step must be a positive integer")
    if history is None:
        history = []
    if not isinstance(history, list) or any(not isinstance(item, dict) for item in history):
        raise ValueError("AI proposal history must be an array of objects")
    # Bound untrusted history before passing it to any configured AI provider.
    # Nested payloads are limited as well as the number of prior steps.
    import json
    if len(history) > 32 or any(
        len(json.dumps(item, ensure_ascii=False, allow_nan=False)) > 4096
        for item in history
    ):
        raise ValueError("AI proposal history exceeds allowed limits")
    if step != len(history) + 1:
        raise ValueError("AI proposal step must follow the supplied history")
    if core.store.get_mission(mission_id) is None:
        raise ValueError(f"unknown mission: {mission_id}")
    try:
        initial_scope = core.scope.check(target)
    except Exception:
        return {
            "status": "blocked",
            "reason": "scope evaluation failed; no AI proposal was created",
            "execution_submitted": False,
            "approval_granted": False,
        }
    if not getattr(initial_scope, "allowed", False):
        return {
            "status": "blocked",
            "reason": f"target is outside current scope: {getattr(initial_scope, 'reason', '')}",
            "execution_submitted": False,
            "approval_granted": False,
        }

    if provider is None:
        import os
        enabled = os.environ.get("WHAXON_AI_ENABLED", "false").lower() in (
            "1", "true", "yes",
        )
        provider = _load_provider_from_env() if enabled else NullProvider()
    agent = Agent(provider=provider)
    audit = agent.audit(goal)
    if not isinstance(audit, dict) or audit.get("feasible") is not True:
        return {
            "status": "blocked",
            "reason": str(
                audit.get("reason") if isinstance(audit, dict) and audit.get("reason")
                else "AI provider rejected the goal"
            ),
        }

    from .providers import SEMANTIC_OPERATION_IDS

    inventory = {
        (item.get("capability_id"), item.get("provider_id")): item
        for item in core.capability_inventory()
        if isinstance(item, dict)
    }
    candidates: dict[str, Any] = {}
    catalog: list[dict[str, Any]] = []
    for tool in core.catalog.list():
        capability_id = SEMANTIC_OPERATION_IDS.get(tool.id, f"tool.{tool.id}")
        try:
            manifest = core.providers.manifest_for(capability_id)
        except (LookupError, ValueError, TypeError):
            continue
        readiness = inventory.get((capability_id, manifest.provider_id))
        if (
            not readiness
            or readiness.get("selected_for_execution") is not True
            or readiness.get("installed") is not True
            or readiness.get("executable") is not True
            or manifest.impact != "moderate"
            or manifest.input_schema.get("properties") != {}
            or manifest.input_schema.get("required", []) != []
            or manifest.input_schema.get("additionalProperties") is not False
        ):
            continue
        try:
            candidate = WorkflowTask(
                id="ai-preview", capability_id=capability_id, target=target,
                inputs={}, permissions=manifest.permissions, impact=manifest.impact,
                timeout_s=manifest.timeout_s,
            )
            core.providers.resolve_task(candidate, require_installed=True)
        except (LookupError, ValueError, TypeError, RuntimeError):
            continue
        candidates[tool.id] = manifest
        catalog.append({
            "id": tool.id,
            "name": tool.name,
            "category": tool.category,
            "capability_id": capability_id,
            "impact": manifest.impact,
            "target_types": list(manifest.target_types),
            "inputs": "fixed provider defaults only; no caller-supplied arguments",
        })
    if not catalog:
        return {
            "status": "blocked",
            "reason": "no installed, selected V2 provider matches this target",
        }

    action = agent.next_action(
        goal=goal,
        history=history,
        catalog=catalog,
        scope_summary={
            "enabled": bool(core.scope.enabled),
            "target": target,
            "execution": "requires separate V2 approval and run submission",
        },
        step=step,
        phase="recon",
    )
    if action.kind != "run_tool":
        return {
            "status": "needs_human" if action.kind == "ask_human" else "stopped",
            "action": action.to_dict(),
        }
    selected_manifest = candidates.get(action.tool_id or "")
    if selected_manifest is None:
        return {"status": "blocked", "action": action.to_dict(),
                "reason": "AI action is not an installed, selected V2 capability"}
    if action.session_id or not isinstance(action.extra_args, str) or action.extra_args.strip():
        return {"status": "blocked", "action": action.to_dict(),
                "reason": "V2 proposal supports neither session actions nor dynamic arguments"}
    if action.target != target:
        return {"status": "blocked", "action": action.to_dict(),
                "reason": "AI-proposed target does not exactly match the operator-supplied target"}
    try:
        verdict = core.scope.check(target)
    except Exception:
        return {"status": "blocked", "action": action.to_dict(),
                "reason": "scope revalidation failed; no AI proposal was created"}
    if not getattr(verdict, "allowed", False):
        return {"status": "blocked", "action": action.to_dict(),
                "reason": f"target is outside current scope: {getattr(verdict, 'reason', '')}"}

    task_id = "task-1"
    task = WorkflowTask(
        id=task_id,
        capability_id=selected_manifest.capability_id,
        target=target,
        inputs={},
        permissions=selected_manifest.permissions,
        impact=selected_manifest.impact,
        timeout_s=selected_manifest.timeout_s,
        idempotency_key=uuid.uuid5(
            uuid.NAMESPACE_URL, f"whaxon:ai-proposal:{mission_id}:{plan_id}",
        ).hex,
    )
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError) as exc:
        return {"status": "blocked", "action": action.to_dict(),
                "reason": f"V2 provider revalidation failed: {exc}"}
    plan = WorkflowPlan(
        mission_id=mission_id,
        metadata={"provider_bindings": {task_id: {
            "provider_id": selected_manifest.provider_id,
            "manifest_fingerprint": selected_manifest.fingerprint,
        }}},
        tasks=(task,),
    )
    return {
        "status": "proposed",
        "action": action.to_dict(),
        "plan_id": plan_id,
        "plan": plan.to_dict(),
        "digest": plan.digest,
        "provider_id": selected_manifest.provider_id,
        "manifest_fingerprint": selected_manifest.fingerprint,
        "execution_submitted": False,
        "approval_granted": False,
    }


def _catalog_all(core: Core, phase_get=None, gating: bool = False) -> list[dict[str, Any]]:
    tools = [asdict(t) for t in core.catalog.list()]
    if gating and phase_get is not None:
        try:
            phase = phase_get() or "recon"
        except Exception:
            phase = "recon"
        tools = _filter_catalog_by_phase(tools, phase)
    return tools


def _catalog_lookup(core: Core, tool_id: str) -> dict[str, Any] | None:
    tool = core.catalog.get(tool_id)
    return asdict(tool) if tool is not None else None


def _scope_check(core: Core, target: str) -> tuple[bool, str]:
    m = core.scope.check(target)
    return bool(m.allowed), str(m.reason or "")


def _scope_summary(core: Core) -> dict[str, Any]:
    try:
        enabled = bool(core.scope.enabled)
    except Exception:
        enabled = True
    return {"enabled": enabled}


async def _run_tool(core: Core, tool_id: str, target: str,
                    extra_args: str, job_id: str,
                    phase: str = "") -> str:
    return await core.runner.run_tool(
        tool_id=tool_id,
        target=target,
        job_id=job_id,
        extra_args=extra_args,
        allow_out_of_scope=False,
        phase=phase,
    )


def build_executor(
    core: Core,
    provider: Provider | None = None,
    limits: ExecutorLimits | None = None,
    on_action=None,
    on_result=None,
    target_lock: str | None = None,
    ask_human=None,
    ask_human_source: str = "human",
    ai_run_id: str | None = None,
) -> Executor:
    """Wire an Executor to a Core. Returns a ready-to-run object.

    Default provider is NullProvider: the loop audits the prompt and
    stops immediately, running nothing. Wire a real provider and flip
    WHAXON_AI_ENABLED=true to enable autonomy.
    """
    import os
    enabled = os.environ.get("WHAXON_AI_ENABLED", "false").lower() in ("1", "true", "yes")
    if provider is None:
        provider = NullProvider() if not enabled else _load_provider_from_env()
    agent = Agent(provider=provider)

    def _phase_get() -> str:
        if ai_run_id is None:
            return "recon"
        run = core.store.get_ai_run(ai_run_id)
        return (run or {}).get("phase") or "recon"

    def _phase_set(new_phase: str) -> None:
        if ai_run_id is None:
            return
        core.store.set_ai_run_phase(ai_run_id, new_phase)

    scope_policy = read_scope_policy()
    import os as _os
    phase_gating = (_os.environ.get("WHAXON_AI_PHASE_GATING", "false")
                    .strip().lower() in ("1", "true", "yes"))

    def _session_check(session_id: str) -> bool:
        try:
            from .msf import MSFClient
            c = MSFClient()
            if not c.is_up():
                return False
            return str(session_id) in c.sessions()
        except Exception:
            return False

    async def _run_in_session(tool_id: str, session_id: str, job_id: str) -> str:
        return await core.runner.run_in_session(
            tool_id=tool_id, session_id=session_id, job_id=job_id,
        )

    def _prior_runs_get(goal: str) -> dict:
        try:
            from whaxon.core.targets import extract_target
            target = extract_target(goal) or ""
            if not target:
                return {}
            from whaxon.ai.prior_runs import summarize
            return summarize(core.store, target)
        except Exception:
            return {}

    return Executor(
        agent=agent,
        catalog_lookup=lambda tid: _catalog_lookup(core, tid),
        scope_check=lambda t: _scope_check(core, t),
        run_tool=lambda tid, tgt, ea, jid, phase="": _run_tool(core, tid, tgt, ea, jid, phase),  # type: ignore[misc]
        get_findings=lambda jid: core.store.get_findings(jid) or [],
        get_job=lambda jid: core.store.get(jid),
        catalog_all=lambda: _catalog_all(core, phase_get=_phase_get, gating=phase_gating),
        scope_summary=lambda: _scope_summary(core),
        limits=limits,
        on_action=on_action,
        on_result=on_result,
        target_lock=target_lock,
        ask_human=ask_human,
        ask_human_source=ask_human_source,
        phase_get=_phase_get,
        phase_set=_phase_set,
        scope_policy=scope_policy,
        session_check=_session_check,
        run_in_session=_run_in_session,
        prior_runs_get=_prior_runs_get,
    )


def _load_provider_from_env() -> Provider:
    """Load a provider based on environment configuration.

    WHAXON_AI_PROVIDER:
        null       (default) NullProvider, plans nothing
        rules                RulesProvider, deterministic ladder
        ollama               LLMProvider + OllamaBackend
        openai               LLMProvider + OpenAIBackend
        anthropic            LLMProvider + AnthropicBackend
        google               LLMProvider + GoogleBackend

    WHAXON_AI_MODEL:
        model name for the selected backend. A sensible default per
        backend is used if unset.

    Unknown providers fall back to NullProvider with a warning.
    """
    import os
    import sys
    name = (os.environ.get("WHAXON_AI_PROVIDER") or "null").strip().lower()
    if name in ("", "null"):
        return NullProvider()
    if name == "rules":
        from whaxon.ai.providers.rules import RulesProvider
        return RulesProvider()
    if name in ("ollama", "openai", "anthropic", "google"):
        from whaxon.ai.providers.backends import BACKENDS
        from whaxon.ai.providers.llm import LLMProvider
        model = os.environ.get("WHAXON_AI_MODEL") or _default_model_for(name)
        backend_cls = BACKENDS[name]
        backend = backend_cls(model=model)
        ok, reason = backend.available()
        if not ok:
            print(f"[ai] backend {name!r} unavailable: {reason}; "
                  "falling back to NullProvider.", file=sys.stderr)
            return NullProvider()
        return LLMProvider(backend=backend)
    print(f"[ai] unknown WHAXON_AI_PROVIDER={name!r}; "
          "falling back to NullProvider.", file=sys.stderr)
    return NullProvider()


def _default_model_for(name: str) -> str:
    return {
        "ollama": "qwen2.5:1.5b",
        "openai": "gpt-4o-mini",
        "anthropic": "claude-3-5-sonnet-20241022",
        "google": "gemini-1.5-flash",
    }.get(name, "")
