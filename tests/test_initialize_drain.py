"""initialize(drain=): legacy queue work requires explicit compatibility opt-in.

A job queued by a previous process (the durable auto-chain) is pending.
A long-lived host leaves it pending by default. A one-shot `whaxon run` must not
silently drain it; doing so could execute work the operator did not ask for
and make coverage disclosure report untested endpoints as tested.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from whaxon.core import Core


def _core(tmp_path: Path) -> Core:
    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text(
        '{"tools":[{"id":"echo","name":"Echo","category":"test",'
        '"binary":"/bin/echo","args":"{target}"}]}'
    )
    return Core(data_dir=data)


def test_initialize_drain_false_leaves_job_pending(tmp_path: Path) -> None:
    core = _core(tmp_path)
    core.store.create_pending("j1", "echo", "127.0.0.1")
    asyncio.run(core.initialize(drain=False))
    assert core.store.list_pending() == [
        {"id": "j1", "tool": "echo", "target": "127.0.0.1"}
    ]


def test_one_shot_initialize_never_drains_even_with_legacy_opt_in(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("WHAXON_LEGACY_QUEUE_DRAIN_ENABLED", "true")
    core = _core(tmp_path)
    core.store.create_pending("j1", "echo", "127.0.0.1")
    asyncio.run(core.initialize(drain=False))
    assert core.store.list_pending() == [
        {"id": "j1", "tool": "echo", "target": "127.0.0.1"}
    ]


def test_initialize_drain_true_leaves_legacy_job_pending_by_default(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.delenv("WHAXON_LEGACY_QUEUE_DRAIN_ENABLED", raising=False)
    core = _core(tmp_path)
    core.store.create_pending("j1", "echo", "127.0.0.1")
    asyncio.run(core.initialize(drain=True))
    assert core.store.list_pending() == [
        {"id": "j1", "tool": "echo", "target": "127.0.0.1"}
    ]


def test_initialize_drain_true_runs_legacy_job_only_with_explicit_opt_in(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("WHAXON_LEGACY_QUEUE_DRAIN_ENABLED", "true")
    core = _core(tmp_path)
    core.store.create_pending("j1", "echo", "127.0.0.1")
    asyncio.run(core.initialize(drain=True))
    assert core.store.list_pending() == []


def test_initialize_fails_closed_when_v2_recovery_fails(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("WHAXON_LEGACY_QUEUE_DRAIN_ENABLED", raising=False)
    core = _core(tmp_path)

    def fail_recovery(*args, **kwargs):
        raise OSError("private recovery details")

    monkeypatch.setattr(core.store, "reconcile_workflow_attempts", fail_recovery)
    try:
        asyncio.run(core.initialize(drain=False))
    except RuntimeError as exc:
        assert str(exc) == "workflow recovery failed; execution is not ready"
        assert isinstance(exc.__cause__, OSError)
    else:
        raise AssertionError("initialize must fail closed when workflow recovery fails")
