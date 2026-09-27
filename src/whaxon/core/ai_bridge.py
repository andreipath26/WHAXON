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

from . import Core


def _catalog_all(core: Core) -> list[dict[str, Any]]:
    return [asdict(t) for t in core.catalog.list()]


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
    return Executor(
        agent=agent,
        catalog_lookup=lambda tid: _catalog_lookup(core, tid),
        scope_check=lambda t: _scope_check(core, t),
        run_tool=lambda tid, tgt, ea, jid: _run_tool(core, tid, tgt, ea, jid),
        get_findings=lambda jid: core.store.get_findings(jid) or [],
        catalog_all=lambda: _catalog_all(core),
        scope_summary=lambda: _scope_summary(core),
        limits=limits,
        on_action=on_action,
        on_result=on_result,
    )


def _load_provider_from_env() -> Provider:
    """Load a provider based on WHAXON_AI_PROVIDER.

    Recognised values:
        null   (default)  NullProvider, plans nothing
        rules             RulesProvider, deterministic ladder

    Unknown values fall back to NullProvider with a warning.
    """
    import os, sys
    name = (os.environ.get("WHAXON_AI_PROVIDER") or "null").strip().lower()
    if name in ("", "null"):
        return NullProvider()
    if name == "rules":
        from whaxon.ai.providers.rules import RulesProvider
        return RulesProvider()
    print(f"[ai] unknown WHAXON_AI_PROVIDER={name!r}; "
          "falling back to NullProvider.", file=sys.stderr)
    return NullProvider()