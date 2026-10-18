"""Durable job queue: pending rows survive process exit, worker drains them.

The bug this fixes: the auto-chain spawned a daemon thread that died with
the CLI process, leaving the job stuck at 'running' forever. Now a chained
job is a pending row; a worker claims and runs it; reconcile_stale corrects
any row left running by a dead process.
"""
from __future__ import annotations

from pathlib import Path

from whaxon.core.store import JobStore


def _store(tmp_path: Path) -> JobStore:
    return JobStore(tmp_path / "db.sqlite")


def test_create_pending_writes_pending_row(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.create_pending("j1", "nikto", "host:80")
    rows = s.list_pending()
    assert rows == [{"id": "j1", "tool": "nikto", "target": "host:80"}]


def test_claim_pending_moves_to_running(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.create_pending("j1", "nikto", "host:80")
    row = s.claim_pending()
    assert row == {"id": "j1", "tool": "nikto", "target": "host:80"}
    assert s.list_pending() == []


def test_claim_pending_is_atomic_single_claim(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.create_pending("j1", "nikto", "host:80")
    assert s.claim_pending() is not None
    assert s.claim_pending() is None


def test_reconcile_stale_marks_running_failed(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.create_pending("j1", "nikto", "host:80")
    s.claim_pending()  # now running, started_at set to now
    # Backdate started_at so it counts as stale
    import sqlite3
    import time
    c = sqlite3.connect(s.path)
    c.execute("UPDATE jobs SET started_at=? WHERE id='j1'", (time.time() - 3600,))
    c.commit(); c.close()
    n = s.reconcile_stale(older_than_s=60)
    assert n == 1
    job = s.get("j1")
    assert job["status"] == "failed"
    assert "process exited" in job["error"]


def test_reconcile_leaves_fresh_running_alone(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.create_pending("j1", "nikto", "host:80")
    s.claim_pending()  # just started, not stale
    assert s.reconcile_stale(older_than_s=60) == 0
    assert s.get("j1")["status"] == "running"
