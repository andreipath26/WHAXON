"""LLMProvider tests: parsing, retry, validation. Backend mocked."""
from __future__ import annotations

from whaxon.ai.providers.backends.base import BackendError, LLMBackend
from whaxon.ai.providers.llm import LLMProvider


class ScriptedBackend(LLMBackend):
    name = "scripted"

    def __init__(self, replies):
        super().__init__(model="test")
        self.replies = list(replies)
        self.calls = 0

    def chat(self, messages, timeout=60.0):
        self.calls += 1
        if not self.replies:
            raise BackendError("no more replies")
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    def available(self):
        return True, ""


def _ctx(**over):
    d = dict(goal="scan 10.0.0.5", history=[], catalog=[{"id": "nmap"}],
             scope_summary={"enabled": True}, step=1, max_steps=5)
    d.update(over)
    return d


def test_parses_plain_json_run_tool():
    b = ScriptedBackend([
        '{"kind": "run_tool", "tool_id": "nmap", "target": "10.0.0.5",'
        ' "rationale": "d", "confidence": 0.9}'
    ])
    a = LLMProvider(backend=b).plan_step(**_ctx())
    assert a.kind == "run_tool"
    assert a.tool_id == "nmap"
    assert a.target == "10.0.0.5"
    assert a.ai_source == "scripted"
    assert a.confidence == 0.9


def test_parses_json_in_code_fence():
    b = ScriptedBackend([
        'Here you go:\n```json\n{"kind": "stop", "rationale": "done"}\n```'
    ])
    a = LLMProvider(backend=b).plan_step(**_ctx())
    assert a.kind == "stop"


def test_retries_on_invalid_json_then_succeeds():
    b = ScriptedBackend([
        "this is not json",
        '{"kind": "stop", "rationale": "ok"}',
    ])
    a = LLMProvider(backend=b, max_retries=2).plan_step(**_ctx())
    assert a.kind == "stop"
    assert b.calls == 2


def test_gives_up_after_max_retries():
    b = ScriptedBackend(["nope", "nope", "nope"])
    a = LLMProvider(backend=b, max_retries=2).plan_step(**_ctx())
    assert a.kind == "ask_human"
    assert "invalid" in a.rationale or "could not obtain" in a.rationale
    assert b.calls == 3


def test_run_tool_without_tool_id_becomes_ask_human():
    b = ScriptedBackend(['{"kind": "run_tool", "target": "10.0.0.5"}'])
    a = LLMProvider(backend=b).plan_step(**_ctx())
    assert a.kind == "ask_human"


def test_run_tool_without_target_becomes_ask_human():
    b = ScriptedBackend(['{"kind": "run_tool", "tool_id": "nmap"}'])
    a = LLMProvider(backend=b).plan_step(**_ctx())
    assert a.kind == "ask_human"


def test_unknown_kind_becomes_ask_human():
    b = ScriptedBackend(['{"kind": "launch_missiles", "rationale": "oops"}'])
    a = LLMProvider(backend=b).plan_step(**_ctx())
    assert a.kind == "ask_human"


def test_backend_error_becomes_ask_human():
    b = ScriptedBackend([BackendError("network down")])
    a = LLMProvider(backend=b).plan_step(**_ctx())
    assert a.kind == "ask_human"
    assert "backend error" in a.rationale


def test_confidence_clamped():
    b = ScriptedBackend([
        '{"kind": "stop", "rationale": "x", "confidence": 99.0}'
    ])
    a = LLMProvider(backend=b).plan_step(**_ctx())
    assert a.confidence == 1.0


def test_audit_unavailable_backend():
    class UnavailBackend(ScriptedBackend):
        def available(self):
            return False, "no key"

    b = UnavailBackend(["anything"])
    p = LLMProvider(backend=b)
    result = p.audit_prompt("scan 10.0.0.5")
    assert result["feasible"] is False
    assert "no key" in result["reason"]


def test_audit_empty_goal():
    b = ScriptedBackend(["anything"])
    result = LLMProvider(backend=b).audit_prompt("   ")
    assert result["feasible"] is False
