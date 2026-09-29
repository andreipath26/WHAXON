"""Integration tests for the core<->ai bridge."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from whaxon.core import Core
from whaxon.core.ai_bridge import build_executor
from whaxon.ai import NullProvider, ExecutorLimits
from whaxon.ai.actions import Action
from whaxon.ai.provider import Provider


@pytest.fixture
def core(tmp_path: Path) -> Core:
    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text(
        "{\"tools\":[{\"id\":\"echo\",\"name\":\"Echo\","
        "\"category\":\"test\",\"binary\":\"/bin/echo\","
        "\"args\":\"{target}\"}]}"
    )
    return Core(data_dir=data)


def test_bridge_runs_null_provider_end_to_end(core: Core) -> None:
    ex = build_executor(core, provider=NullProvider())
    history = asyncio.run(ex.run("anything", job_id_prefix="aitest"))
    assert len(history) == 1
    assert history[0].action.kind == "stop"
    assert history[0].ok is True


def test_bridge_rejects_out_of_scope_before_runner(core: Core) -> None:
    calls: list[tuple] = []

    async def spy(*a, **kw):
        calls.append((a, kw))
        return "never"

    core.runner.run_tool = spy  # type: ignore[assignment]

    class OneShot(Provider):
        name = "one-shot"
        def plan_step(self, goal, history, catalog, scope_summary, step, max_steps, phase="recon", prior_runs=None):
            if step == 1:
                return Action.run_tool("echo", "8.8.8.8", rationale="t",
                                       confidence=0.9, ai_source="one-shot")
            return Action.stop("done", ai_source="one-shot")

    ex = build_executor(core, provider=OneShot(),
                        limits=ExecutorLimits(max_steps=3))
    history = asyncio.run(ex.run("scan something"))
    assert history[0].ok is False
    assert "out of scope" in history[0].error
    assert calls == []


def test_bridge_rejects_unknown_tool_before_runner(core: Core) -> None:
    calls: list[tuple] = []

    async def spy(*a, **kw):
        calls.append((a, kw))
        return "never"

    core.runner.run_tool = spy  # type: ignore[assignment]

    class OneShot(Provider):
        name = "one-shot"
        def plan_step(self, goal, history, catalog, scope_summary, step, max_steps, phase="recon", prior_runs=None):
            if step == 1:
                return Action.run_tool("ghost", "127.0.0.1", rationale="t",
                                       confidence=0.9, ai_source="one-shot")
            return Action.stop("done", ai_source="one-shot")

    ex = build_executor(core, provider=OneShot(),
                        limits=ExecutorLimits(max_steps=3))
    history = asyncio.run(ex.run("scan something"))
    assert history[0].ok is False
    assert "not in catalog" in history[0].error
    assert calls == []

def test_bridge_honours_rules_env(monkeypatch) -> None:
    from whaxon.core.ai_bridge import build_executor
    from whaxon.ai.providers.rules import RulesProvider
    monkeypatch.setenv("WHAXON_AI_ENABLED", "true")
    monkeypatch.setenv("WHAXON_AI_PROVIDER", "rules")
    import tempfile
    from pathlib import Path as _P
    with tempfile.TemporaryDirectory() as td:
        d = _P(td) / "data"
        d.mkdir()
        (d / "tools.json").write_text("{\"tools\":[]}")
        core = Core(data_dir=d)
        ex = build_executor(core)
        assert isinstance(ex.agent.provider, RulesProvider)
        assert ex.agent.provider.name == "rules"


def test_bridge_unknown_provider_falls_back(monkeypatch) -> None:
    from whaxon.core.ai_bridge import build_executor
    from whaxon.ai.provider import NullProvider
    monkeypatch.setenv("WHAXON_AI_ENABLED", "true")
    monkeypatch.setenv("WHAXON_AI_PROVIDER", "gpt-9000")
    import tempfile
    from pathlib import Path as _P
    with tempfile.TemporaryDirectory() as td:
        d = _P(td) / "data"
        d.mkdir()
        (d / "tools.json").write_text("{\"tools\":[]}")
        core = Core(data_dir=d)
        ex = build_executor(core)
        assert isinstance(ex.agent.provider, NullProvider)
