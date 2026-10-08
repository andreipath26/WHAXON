"""Cost estimation and usage tracking — v2 of docs/agent-architecture.md §14."""
from __future__ import annotations

from pathlib import Path

from whaxon.ai.costs import estimate_cost, estimate_tokens


def test_estimate_tokens_empty() -> None:
    assert estimate_tokens("") == 0
    assert estimate_tokens(None) == 0


def test_estimate_tokens_chars_div_4() -> None:
    assert estimate_tokens("a" * 400) == 100
    assert estimate_tokens("abc") == 1  # floor at 1


def test_estimate_cost_known_model() -> None:
    # gpt-4o-mini: $0.15/1M input, $0.60/1M output
    cost = estimate_cost("gpt-4o-mini", 1_000_000, 1_000_000)
    assert cost is not None
    assert abs(cost - (0.15 + 0.60)) < 1e-9


def test_estimate_cost_local_is_free() -> None:
    assert estimate_cost("qwen2.5:1.5b", 1_000_000, 1_000_000) == 0.0


def test_estimate_cost_unknown_returns_none() -> None:
    assert estimate_cost("some-model-nobody-has-heard-of", 100, 100) is None


def test_store_usage_roundtrip(tmp_path: Path) -> None:
    from whaxon.core.store import JobStore
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-u", "goal")
    s.set_ai_run_usage("ai-u", 1500, 300, 0.0003)
    r = s.get_ai_run("ai-u")
    assert r["tokens_in"] == 1500
    assert r["tokens_out"] == 300
    assert abs(r["cost_usd"] - 0.0003) < 1e-9


def test_llm_provider_tracks_tokens() -> None:
    from whaxon.ai.providers.backends.base import LLMBackend
    from whaxon.ai.providers.llm import LLMProvider

    class FakeBackend(LLMBackend):
        name = "fake"
        def __init__(self):
            super().__init__("fake-model")
        def available(self):
            return True, ""
        def chat(self, messages, timeout=60.0):
            return '{"kind": "stop", "rationale": "done"}'

    p = LLMProvider(FakeBackend())
    assert p.usage == {"tokens_in": 0, "tokens_out": 0}
    p.plan_step("goal", [], [], {}, 1, 3)
    u = p.usage
    assert u["tokens_in"] > 0
    assert u["tokens_out"] > 0


def test_record_usage_writes_to_store(tmp_path: Path) -> None:
    from whaxon.core import Core
    from whaxon.interfaces.cli.ai_cmd import _record_usage

    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text('{"tools":[]}')
    core = Core(data_dir=data)
    core.store.create_ai_run("ai-r", "goal")

    class _Provider:
        def __init__(self):
            self.usage = {"tokens_in": 100, "tokens_out": 50}
        model_name = "gpt-4o-mini"

    class _Agent:
        provider = _Provider()

    class _Executor:
        agent = _Agent()

    _record_usage(core, "ai-r", _Executor())
    r = core.store.get_ai_run("ai-r")
    assert r["tokens_in"] == 100
    assert r["tokens_out"] == 50
    # gpt-4o-mini: (100*0.15 + 50*0.60)/1M = 4.5e-5
    assert r["cost_usd"] is not None
    assert abs(r["cost_usd"] - (100 * 0.15 + 50 * 0.60) / 1_000_000) < 1e-12


def test_record_usage_noop_when_no_usage_attr(tmp_path: Path) -> None:
    from whaxon.core import Core
    from whaxon.interfaces.cli.ai_cmd import _record_usage

    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text('{"tools":[]}')
    core = Core(data_dir=data)
    core.store.create_ai_run("ai-n", "goal")

    class _Provider:
        pass

    class _Agent:
        provider = _Provider()

    class _Executor:
        agent = _Agent()

    _record_usage(core, "ai-n", _Executor())
    r = core.store.get_ai_run("ai-n")
    # Columns defaulted to 0, no exception
    assert r["tokens_in"] == 0
    assert r["tokens_out"] == 0


def test_record_usage_noop_when_executor_none(tmp_path: Path) -> None:
    from whaxon.core import Core
    from whaxon.interfaces.cli.ai_cmd import _record_usage

    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text('{"tools":[]}')
    core = Core(data_dir=data)
    core.store.create_ai_run("ai-x", "goal")
    _record_usage(core, "ai-x", None)  # should not raise
    