"""initialize(drain=): one-shot CLI must not execute queued jobs.

A job queued by a previous process (the durable auto-chain) is pending.
A long-lived host drains it at startup. A one-shot `whaxon run` must not
— it would execute work the operator did not ask for, and coverage
disclosure would report untested endpoints as tested.
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


def test_initialize_drain_true_runs_job(tmp_path: Path) -> None:
    core = _core(tmp_path)
    core.store.create_pending("j1", "echo", "127.0.0.1")
    asyncio.run(core.initialize(drain=True))
    assert core.store.list_pending() == []
