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
from whaxon.ai.actions import Action, ActionResult
from whaxon.ai.provider import NullProvider
from whaxon.ai.scope_policy import read_policy as read_scope_policy
from whaxon.ai.phases import filter_catalog as _filter_catalog_by_phase

from . import Core


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
                    extra_args: str, job_id: str) -> str:
    return await core.runner.run_tool(
        tool_id=tool_id,
        target=target,
        job_id=job_id,
        extra_args=extra_args,
        allow_out_of_scope=False,
    )


def build_executor(
    core: Core,
    provider: Provider | None = None,
    limits: ExecutorLimits | None = None,
    on_action=None,
    on_result=None,
    target_lock: str | None = None,
    ask_human=None,
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
        run_tool=lambda tid, tgt, ea, jid: _run_tool(core, tid, tgt, ea, jid),
        get_findings=lambda jid: core.store.get_findings(jid) or [],
        catalog_all=lambda: _catalog_all(core, phase_get=_phase_get, gating=phase_gating),
        scope_summary=lambda: _scope_summary(core),
        limits=limits,
        on_action=on_action,
        on_result=on_result,
        target_lock=target_lock,
        ask_human=ask_human,
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
    import os, sys
    name = (os.environ.get("WHAXON_AI_PROVIDER") or "null").strip().lower()
    if name in ("", "null"):
        return NullProvider()
    if name == "rules":
        from whaxon.ai.providers.rules import RulesProvider
        return RulesProvider()
    if name in ("ollama", "openai", "anthropic", "google"):
        from whaxon.ai.providers.llm import LLMProvider
        from whaxon.ai.providers.backends import BACKENDS
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
    if name == "rules":
        from whaxon.ai.providers.rules import RulesProvider
        return RulesProvider()
    print(f"[ai] unknown WHAXON_AI_PROVIDER={name!r}; "
          "falling back to NullProvider.", file=sys.stderr)
    return NullProvider()