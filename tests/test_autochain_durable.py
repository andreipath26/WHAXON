"""The auto-chain survives process exit (regression for the stuck job).

Old bug: nmap's chain spawned a daemon-thread nikto job; the CLI exited;
the thread died; the job row stayed 'running' forever. Now the chain
writes a pending row, and `whaxon jobs drain` runs it from a new process.
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _whaxon(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "whaxon.cli", *args],
        cwd=str(REPO), capture_output=True, text=True, timeout=60,
    )


def _db(tmp: Path) -> Path:
    return tmp / "whaxon.db"


def test_queue_then_drain_in_separate_process(tmp_path: Path) -> None:
    from whaxon.core.store import JobStore
    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text((REPO / "data" / "tools.json").read_text())
    (data / "scope.json").write_text(json.dumps({
        "engagement": "test", "enabled": True,
        "in_scope": ["127.0.0.1"], "out_of_scope": [],
    }))

    # Process 1: queue a pending echo job, then exit.
    store = JobStore(_db(data))
    store.create_pending("chainjob", "echo", "127.0.0.1")
    assert store.list_pending() == [{"id": "chainjob", "tool": "echo", "target": "127.0.0.1"}]
    del store  # close; process would exit here

    # Process 2 (subprocess): drain picks it up.
    r = _whaxon("jobs", "drain", "--data", str(data))
    assert r.returncode == 0, r.stderr
    assert "drained 1 job" in r.stdout

    # The row is no longer pending, and has a terminal status.
    c = sqlite3.connect(_db(data))
    status = c.execute("SELECT status FROM jobs WHERE id='chainjob'").fetchone()[0]
    c.close()
    assert status in ("finished", "failed"), status


def test_reconcile_on_init_marks_old_running_failed(tmp_path: Path) -> None:
    from whaxon.core.store import JobStore
    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text((REPO / "data" / "tools.json").read_text())
    (data / "scope.json").write_text(json.dumps({
        "engagement": "test", "enabled": True,
        "in_scope": ["127.0.0.1"], "out_of_scope": [],
    }))
    store = JobStore(_db(data))
    store.create_pending("zombie", "nikto", "127.0.0.1:80")
    store.claim_pending()  # now running
    import time
    c = sqlite3.connect(_db(data))
    c.execute("UPDATE jobs SET started_at=? WHERE id='zombie'", (time.time() - 3600,))
    c.commit(); c.close()
    del store

    # Any interface that calls initialize reconciles. Use jobs drain,
    # which builds a Core and drains — but reconcile happens in initialize,
    # which jobs drain does not call. So test the store method directly here.
    s2 = JobStore(_db(data))
    assert s2.reconcile_stale(older_than_s=60) == 1
    assert s2.get("zombie")["status"] == "failed"
