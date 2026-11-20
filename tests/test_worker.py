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
    assert row["id"] == "j1"
    assert row["tool"] == "nikto"
    assert row["target"] == "host:80"
    assert row["lease_token"]
    assert row["lease_owner"] == "worker"
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
    c.execute("UPDATE jobs SET started_at=?, heartbeat_at=NULL WHERE id='j1'", (time.time() - 3600,))
    c.commit(); c.close()
    n = s.reconcile_stale(older_than_s=60)
    assert n == 1
    job = s.get("j1")
    assert job["status"] == "failed"
    assert "lease expired" in job["error"]


def test_reconcile_leaves_fresh_running_alone(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.create_pending("j1", "nikto", "host:80")
    s.claim_pending()  # just started, not stale
    assert s.reconcile_stale(older_than_s=60) == 0
    assert s.get("j1")["status"] == "running"


def test_reconcile_stale_uses_recent_heartbeat_not_old_start_time(tmp_path: Path) -> None:
    import sqlite3
    import time

    s = _store(tmp_path)
    s.create_pending("j1", "nikto", "host:80")
    s.claim_pending(worker_id="worker-a")
    c = sqlite3.connect(s.path)
    c.execute(
        "UPDATE jobs SET started_at=? WHERE id='j1'",
        (time.time() - 3600,),
    )
    c.commit()
    c.close()

    assert s.reconcile_stale(older_than_s=60) == 0
    assert s.get("j1")["status"] == "running"


def test_stale_reconciliation_fences_old_worker_token(tmp_path: Path) -> None:
    import sqlite3
    import time

    s = _store(tmp_path)
    s.create_pending("j1", "nikto", "host:80")
    row = s.claim_pending(worker_id="worker-a")
    token = row["lease_token"]
    c = sqlite3.connect(s.path)
    c.execute(
        "UPDATE jobs SET heartbeat_at=? WHERE id='j1'",
        (time.time() - 3600,),
    )
    c.commit()
    c.close()

    assert s.reconcile_stale(older_than_s=60) == 1
    assert s.heartbeat_job("j1", token) is False
    assert s.set_finished("j1", 0, 1.0, lease_token=token) is False
    assert s.get("j1")["status"] == "failed"


def test_claim_pending_is_single_owner_across_store_instances(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "shared.sqlite"
    first = JobStore(path)
    second = JobStore(path)
    first.create_pending("j1", "nikto", "host:80")

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(first.claim_pending, worker_id="worker-a"),
            pool.submit(second.claim_pending, worker_id="worker-b"),
        ]
        claimed = [future.result() for future in futures]

    winners = [row for row in claimed if row is not None]
    assert len(winners) == 1
    assert winners[0]["id"] == "j1"
    assert winners[0]["lease_owner"] in {"worker-a", "worker-b"}
    assert first.get("j1")["status"] == "running"
