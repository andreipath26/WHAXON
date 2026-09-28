"""Boundary tests: the AI layer must not leak into deterministic code.

Rule: whaxon.core and whaxon.adapters MUST NOT import whaxon.ai.
The reverse is fine — whaxon.ai may import core (it does not yet).

These tests fail the moment anyone adds an import of whaxon.ai to
core or adapters. They are also enforced in CI by a grep step;
the tests here are the belt-and-braces version that runs locally.
"""
from __future__ import annotations

import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "whaxon"
FORBIDDEN_ROOTS = [SRC / "core", SRC / "adapters"]
AI_IMPORT = re.compile(r"^\s*(from\s+whaxon\.ai|import\s+whaxon\.ai)\b")


def _py_files(root: Path):
    if not root.is_dir():
        return
    for p in root.rglob("*.py"):
        yield p


ALLOWED = {SRC / "core" / "ai_bridge.py"}


def test_core_and_adapters_do_not_import_ai():
    offenders: list[str] = []
    for root in FORBIDDEN_ROOTS:
        for path in _py_files(root):
            if path.resolve() in {p.resolve() for p in ALLOWED}:
                continue
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                if AI_IMPORT.match(line):
                    offenders.append(f"{path}:{lineno}: {line.strip()}")
    assert not offenders, (
        "whaxon.ai must not be imported from core or adapters. "
        "Offending lines:\n" + "\n".join(offenders)
    )


def test_ai_package_imports_cleanly():
    import whaxon.ai as ai
    assert hasattr(ai, "Action")
    assert hasattr(ai, "Provider")
    assert hasattr(ai, "NullProvider")
    assert hasattr(ai, "Agent")
    assert hasattr(ai, "Executor")


def test_null_provider_stops_immediately():
    from whaxon.ai import Agent, NullProvider, Action
    a = Agent(provider=NullProvider())
    action = a.next_action(
        goal="scan 10.0.0.1",
        history=[],
        catalog=[{"id": "nmap"}],
        scope_summary={"enabled": True},
        step=1,
    )
    assert isinstance(action, Action)
    assert action.kind == "stop"
    assert action.ai_source == "null"


def test_agent_audit_defaults_to_feasible():
    from whaxon.ai import Agent, NullProvider
    a = Agent(provider=NullProvider())
    audit = a.audit("anything")
    assert audit["feasible"] is True


def test_executor_rejects_out_of_scope():
    from whaxon.ai import Action, Agent, Executor, ExecutorLimits, NullProvider

    class ScriptedProvider(NullProvider):
        name = "scripted"
        def plan_step(self, goal, history, catalog, scope_summary, step, max_steps, phase="recon"):
            if step == 1:
                return Action.run_tool("nmap", "10.0.0.5",
                                       rationale="test", confidence=0.9,
                                       ai_source="scripted")
            return Action.stop("done", ai_source="scripted")

    agent = Agent(provider=ScriptedProvider(), max_steps=2)
    ran: list[tuple] = []
    async def fake_run(tool_id, target, extra_args, job_id):
        ran.append((tool_id, target, extra_args, job_id))
        return "real-job-1"

    ex = Executor(
        agent=agent,
        catalog_lookup=lambda tid: {"id": tid} if tid == "nmap" else None,
        scope_check=lambda t: (False, "not in scope"),
        run_tool=fake_run,
        get_findings=lambda jid: [],
        catalog_all=lambda: [{"id": "nmap"}],
        scope_summary=lambda: {"enabled": True},
        limits=ExecutorLimits(max_steps=2),
    )
    import asyncio
    history = asyncio.run(ex.run("scan something"))
    assert history[0].ok is False
    assert "out of scope" in history[0].error
    assert ran == [], "executor must not call run_tool for out-of-scope targets"


def test_executor_rejects_unknown_tool():
    from whaxon.ai import Action, Agent, Executor, ExecutorLimits, NullProvider

    class ScriptedProvider(NullProvider):
        name = "scripted"
        def plan_step(self, goal, history, catalog, scope_summary, step, max_steps, phase="recon"):
            if step == 1:
                return Action.run_tool("ghost-tool", "10.0.0.5",
                                       rationale="test", confidence=0.9,
                                       ai_source="scripted")
            return Action.stop("done", ai_source="scripted")

    agent = Agent(provider=ScriptedProvider(), max_steps=2)
    ran: list[tuple] = []
    async def fake_run(tool_id, target, extra_args, job_id):
        ran.append((tool_id, target, extra_args, job_id))
        return "real-job-1"

    ex = Executor(
        agent=agent,
        catalog_lookup=lambda tid: None,
        scope_check=lambda t: (True, ""),
        run_tool=fake_run,
        get_findings=lambda jid: [],
        catalog_all=lambda: [],
        scope_summary=lambda: {"enabled": True},
        limits=ExecutorLimits(max_steps=2),
    )
    import asyncio
    history = asyncio.run(ex.run("scan something"))
    assert history[0].ok is False
    assert "not in catalog" in history[0].error
    assert ran == []