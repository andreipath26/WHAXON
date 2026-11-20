"""Target lock: the model cannot override the operator named target."""
from __future__ import annotations

import asyncio

from whaxon.ai import Action, Agent, Executor, ExecutorLimits
from whaxon.ai.provider import Provider
from whaxon.core.targets import extract_target


def _ctx_provider(action_per_step):
    class P(Provider):
        name = "scripted"
        def plan_step(self, goal, history, catalog, scope_summary, step, max_steps, phase="recon", prior_runs=None):
            idx = min(step - 1, len(action_per_step) - 1)
            return action_per_step[idx]
    return P()


def _run(actions, target_lock):
    p = _ctx_provider(actions)
    a = Agent(provider=p, max_steps=len(actions))
    calls = []
    async def fake_run(tool_id, target, extra, jid, **kwargs):
        calls.append((tool_id, target))
        return "job-" + tool_id
    ex = Executor(
        agent=a,
        catalog_lookup=lambda tid: {"id": tid},
        scope_check=lambda t: (True, ""),
        run_tool=fake_run,
        get_findings=lambda jid: [],
        catalog_all=lambda: [{"id": "nmap"}],
        scope_summary=lambda: {"enabled": True},
        limits=ExecutorLimits(max_steps=len(actions)),
        target_lock=target_lock,
    )
    history = asyncio.run(ex.run("goal"))
    return history, calls


def test_lock_rejects_mismatched_target():
    actions = [Action.run_tool("nmap", "10.0.0.5", confidence=0.9, ai_source="s"),
               Action.stop("done", ai_source="s")]
    hist, calls = _run(actions, "127.0.0.1")
    assert hist[0].ok is False
    assert "target mismatch" in hist[0].error
    assert calls == []


def test_lock_allows_matching_target():
    actions = [Action.run_tool("nmap", "127.0.0.1", confidence=0.9, ai_source="s"),
               Action.stop("done", ai_source="s")]
    hist, calls = _run(actions, "127.0.0.1")
    assert hist[0].ok is True
    assert calls == [("nmap", "127.0.0.1")]


def test_no_lock_allows_any_target():
    actions = [Action.run_tool("nmap", "10.0.0.5", confidence=0.9, ai_source="s"),
               Action.stop("done", ai_source="s")]
    hist, calls = _run(actions, None)
    assert hist[0].ok is True
    assert calls == [("nmap", "10.0.0.5")]


def test_extract_ipv4():
    assert extract_target("assess 10.0.0.5") == "10.0.0.5"


def test_extract_hostname():
    assert extract_target("scan example.com") == "example.com"


def test_extract_none():
    assert extract_target("please assess") is None



def test_lock_accepts_host_port_when_locked_to_host():
    """Dogfooding bug: goal locked 127.0.0.1, action proposed 127.0.0.1:8888."""
    actions = [Action.run_tool("nmap", "127.0.0.1:8888", confidence=0.9, ai_source="s"),
               Action.stop("done", ai_source="s")]
    hist, calls = _run(actions, "127.0.0.1")
    assert hist[0].ok is True, f"expected ok, got {hist[0].error!r}"
    assert calls == [("nmap", "127.0.0.1:8888")]


def test_lock_accepts_host_when_locked_to_host_port():
    """Reverse direction: lock has a port, action has bare host."""
    actions = [Action.run_tool("nmap", "127.0.0.1", confidence=0.9, ai_source="s"),
               Action.stop("done", ai_source="s")]
    hist, _calls = _run(actions, "127.0.0.1:8888")
    assert hist[0].ok is True, f"expected ok, got {hist[0].error!r}"


def test_failed_action_is_not_retried():
    """Dogfooding bug: gobuster failed, chain retried it at step 4."""
    actions = [
        Action.run_tool("gobuster", "127.0.0.1", confidence=0.9, ai_source="s"),
        Action.run_tool("gobuster", "127.0.0.1", confidence=0.9, ai_source="s"),
        Action.stop("done", ai_source="s"),
    ]
    p = _ctx_provider(actions)
    a = Agent(provider=p, max_steps=len(actions))
    calls = []
    async def fake_run(tool_id, target, extra, jid, **kwargs):
        calls.append((tool_id, target))
        raise RuntimeError("simulated failure")
    ex = Executor(
        agent=a,
        catalog_lookup=lambda tid: {"id": tid},
        scope_check=lambda t: (True, ""),
        run_tool=fake_run,
        get_findings=lambda jid: [],
        catalog_all=lambda: [{"id": "gobuster"}],
        scope_summary=lambda: {"enabled": True},
        limits=ExecutorLimits(max_steps=len(actions)),
        target_lock=None,
    )
    hist = asyncio.run(ex.run("goal"))
    # Only one real invocation; the second is blocked as "already run".
    assert len(calls) == 1, f"expected 1 call, got {len(calls)}"
    assert "already run" in (hist[1].error or "")

def test_ai_rejects_free_form_extra_args_before_runner_call():
    action = Action.run_tool(
        "nmap", "127.0.0.1", extra_args="8.8.8.8",
        confidence=0.9, ai_source="scripted",
    )
    hist, calls = _run([action, Action.stop("done", ai_source="scripted")], "127.0.0.1")
    assert hist[0].ok is False
    assert "extra_args are disabled" in hist[0].error
    assert calls == []
