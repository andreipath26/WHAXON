"""Scope-expansion policy env var (step 6)."""
from __future__ import annotations

import logging

from whaxon.ai.scope_policy import (
    DEFAULT_POLICY,
    POLICIES,
    is_valid,
    read_policy,
)


def test_policies_tuple_matches_design() -> None:
    assert POLICIES == ("strict", "inherited", "recommended")
    assert DEFAULT_POLICY == "strict"


def test_is_valid() -> None:
    assert is_valid("strict")
    assert is_valid("inherited")
    assert is_valid("recommended")
    assert not is_valid("")
    assert not is_valid("STRICT")
    assert not is_valid("bogus")


def test_read_policy_defaults_to_strict_when_unset() -> None:
    assert read_policy({}) == "strict"


def test_read_policy_accepts_strict() -> None:
    assert read_policy({"WHAXON_AI_SCOPE_EXPANSION": "strict"}) == "strict"
    assert read_policy({"WHAXON_AI_SCOPE_EXPANSION": "  STRICT  "}) == "strict"


def test_read_policy_falls_back_on_unknown(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        assert read_policy({"WHAXON_AI_SCOPE_EXPANSION": "bogus"}) == "strict"
    assert any("not a known policy" in r.message for r in caplog.records)


def test_read_policy_falls_back_on_not_implemented(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        assert read_policy({"WHAXON_AI_SCOPE_EXPANSION": "inherited"}) == "strict"
    assert any("not implemented in v1" in r.message for r in caplog.records)


def test_bridge_sets_scope_policy_on_executor(tmp_path, monkeypatch) -> None:
    """End-to-end: env var reaches the Executor as scope_policy."""
    from whaxon.core import Core
    from whaxon.core.ai_bridge import build_executor

    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text('{"tools":[]}')
    core = Core(data_dir=data)

    monkeypatch.setenv("WHAXON_AI_SCOPE_EXPANSION", "inherited")
    ex = build_executor(core)
    assert ex.scope_policy == "strict"  # v1 fallback

    monkeypatch.setenv("WHAXON_AI_SCOPE_EXPANSION", "strict")
    ex = build_executor(core)
    assert ex.scope_policy == "strict"


def test_executor_default_scope_policy_is_strict() -> None:
    """A bare Executor without a bridge keeps the strict default."""
    from whaxon.ai import Agent, Executor, ExecutorLimits

    ex = Executor(
        agent=Agent(),
        catalog_lookup=lambda _: None,
        scope_check=lambda _: (True, ""),
        run_tool=None,  # type: ignore[arg-type]
        get_findings=lambda _: [],
        catalog_all=list,
        scope_summary=dict,
        limits=ExecutorLimits(max_steps=1),
    )
    assert ex.scope_policy == "strict"