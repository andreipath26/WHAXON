"""Durable Engine V2 run-intent queue shared by API and headless workers.

A queued request survives client/server exit. Running requests are never
replayed automatically after lease loss: the outcome of the external effect
must be reconciled first. Task-level leases and authorization remain owned by
the existing workflow scheduler.
"""
from __future__ import annotations

import json
import math
import time
import uuid


class WorkflowRunQueue:
    def __init__(self, store):
        self.store = store
        with store._lock:
            conn = store._conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS workflow_run_requests (
                        id TEXT PRIMARY KEY,
                        plan_id TEXT NOT NULL,
                        plan_digest TEXT NOT NULL,
                        limits_json TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'queued',
                        owner TEXT,
                        lease_token TEXT,
                        submitted_at REAL NOT NULL,
                        started_at REAL,
                        heartbeat_at REAL,
                        completed_at REAL,
                        error TEXT
                    );
                    CREATE UNIQUE INDEX IF NOT EXISTS
                      idx_workflow_run_open_plan
                      ON workflow_run_requests(plan_id)
                      WHERE status IN ('queued','running','uncertain');
                    CREATE INDEX IF NOT EXISTS idx_workflow_run_queue
                      ON workflow_run_requests(status,submitted_at);
                    CREATE TABLE IF NOT EXISTS workflow_worker_liveness (
                        id INTEGER PRIMARY KEY CHECK (id=1),
                        status TEXT NOT NULL,
                        heartbeat_at REAL NOT NULL
                    );
                    INSERT OR IGNORE INTO workflow_worker_liveness
                      (id,status,heartbeat_at) VALUES (1,'stopped',0);
                    CREATE TABLE IF NOT EXISTS workflow_worker_instances (
                        worker_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        heartbeat_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_workflow_worker_ready
                      ON workflow_worker_instances(status,heartbeat_at);
                """)
            finally:
                conn.close()

    def set_worker_status(self, status: str, *, worker_id: str = "legacy-singleton") -> None:
        if status not in {"starting", "ready", "stopped"}:
            raise ValueError("invalid workflow worker status")
        if not isinstance(worker_id, str) or not worker_id.strip() or len(worker_id) > 200:
            raise ValueError("valid workflow worker identity required")
        now = time.time()
        with self.store._lock:
            conn = self.store._conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO workflow_worker_instances(worker_id,status,heartbeat_at) "
                    "VALUES (?,?,?) ON CONFLICT(worker_id) DO UPDATE SET "
                    "status=excluded.status,heartbeat_at=excluded.heartbeat_at",
                    (worker_id, status, now),
                )
                # Keep the original singleton row current for older WHAXON
                # versions that still read it during a rolling upgrade.
                if worker_id == "legacy-singleton":
                    conn.execute(
                        "UPDATE workflow_worker_liveness SET status=?,heartbeat_at=? "
                        "WHERE id=1",
                        (status, now),
                    )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def worker_is_ready(self, *, max_age_s: float = 10.0) -> bool:
        if (
            isinstance(max_age_s, bool)
            or not isinstance(max_age_s, (int, float))
            or max_age_s <= 0
        ):
            raise ValueError("worker heartbeat age must be positive")
        with self.store._lock:
            conn = self.store._conn()
            try:
                row = conn.execute(
                    "SELECT 1 FROM workflow_worker_instances WHERE status='ready' "
                    "AND heartbeat_at>=? LIMIT 1",
                    (time.time() - max_age_s,),
                ).fetchone()
                legacy = conn.execute(
                    "SELECT status,heartbeat_at FROM workflow_worker_liveness WHERE id=1",
                ).fetchone()
            finally:
                conn.close()
        return bool(row is not None or (
            legacy is not None and legacy["status"] == "ready"
            and time.time() - float(legacy["heartbeat_at"]) <= max_age_s
        ))

    @staticmethod
    def _check_limits(limits):
        expected = {"max_tasks", "max_attempts", "max_concurrency"}
        if not isinstance(limits, dict) or set(limits) != expected:
            raise ValueError("exact workflow execution limits are required")
        if any(type(limits[key]) is not int or not 1 <= limits[key] <= 1000
               for key in expected):
            raise ValueError("workflow execution limits must be positive and bounded")

    @classmethod
    def _format(cls, row):
        data = dict(row)
        raw = data.pop("limits_json")
        try:
            limits = json.loads(raw)
            cls._check_limits(limits)
        except (TypeError, ValueError):
            data["limits"] = None
            data["limits_integrity"] = "invalid"
        else:
            data["limits"] = limits
            data["limits_integrity"] = "valid"
        return data

    @classmethod
    def _public_record(cls, row) -> dict:
        """Client-facing queue records never expose worker lease credentials."""
        value = cls._format(row)
        value.pop("lease_token", None)
        return value

    def enqueue(self, plan_id: str, *, limits: dict) -> dict:
        self._check_limits(limits)
        now = time.time()
        request_id = uuid.uuid4().hex
        with self.store._lock:
            conn = self.store._conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                plan = conn.execute(
                    "SELECT digest, status FROM workflow_plans WHERE id=?",
                    (plan_id,),
                ).fetchone()
                if plan is None:
                    raise ValueError("unknown workflow plan")
                if plan["status"] == "cancel_requested":
                    raise ValueError("cannot enqueue cancelled workflow")
                existing = conn.execute(
                    "SELECT * FROM workflow_run_requests WHERE plan_id=? "
                    "AND status IN ('queued','running','uncertain')",
                    (plan_id,),
                ).fetchone()
                if existing is not None:
                    # A duplicate submission must not adopt an old intent
                    # after the source plan's persisted identity has drifted.
                    # Keep the original queue row for reconciliation; never
                    # silently rebind it to the new digest.
                    if existing["plan_digest"] != plan["digest"]:
                        raise ValueError(
                            "active workflow request has a different plan digest"
                        )
                    try:
                        persisted_limits = json.loads(existing["limits_json"])
                        self._check_limits(persisted_limits)
                    except (TypeError, ValueError) as exc:
                        raise ValueError(
                            "active workflow request has invalid persisted limits"
                        ) from exc
                    if persisted_limits != limits:
                        raise ValueError("active workflow request has different limits")
                    conn.execute("COMMIT")
                    return self._public_record(existing)
                conn.execute(
                    "INSERT INTO workflow_run_requests "
                    "(id,plan_id,plan_digest,limits_json,submitted_at) "
                    "VALUES (?,?,?,?,?)",
                    (request_id, plan_id, plan["digest"],
                     json.dumps(limits, sort_keys=True), now),
                )
                row = conn.execute(
                    "SELECT * FROM workflow_run_requests WHERE id=?",
                    (request_id,),
                ).fetchone()
                conn.execute("COMMIT")
                return self._public_record(row)
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def get(self, request_id: str) -> dict | None:
        """Public inspection excludes the private worker fencing credential."""
        conn = self.store._conn()
        try:
            row = conn.execute(
                "SELECT * FROM workflow_run_requests WHERE id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                return None
            return self._public_record(row)
        finally:
            conn.close()

    def queued_count(self) -> int:
        """Count remaining queued intents without claiming or executing them."""
        conn = self.store._conn()
        try:
            return int(conn.execute(
                "SELECT COUNT(*) FROM workflow_run_requests WHERE status='queued'",
            ).fetchone()[0])
        finally:
            conn.close()

    def claim(self, owner: str) -> dict | None:
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError("worker owner required")
        with self.store._lock:
            conn = self.store._conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                # Quarantine bounded malformed/obsolete queue heads instead of
                # starving valid requests behind them. All decisions and the
                # eventual claim share this one SQLite write transaction.
                for _ in range(64):
                    row = conn.execute(
                        "SELECT * FROM workflow_run_requests "
                        "WHERE status='queued' "
                        "ORDER BY submitted_at,id LIMIT 1",
                    ).fetchone()
                    if row is None:
                        conn.execute("COMMIT")
                        return None
                    plan = conn.execute(
                        "SELECT digest,status FROM workflow_plans WHERE id=?",
                        (row["plan_id"],),
                    ).fetchone()
                    if plan is None or plan["digest"] != row["plan_digest"]:
                        reason = (
                            "source plan missing before dispatch"
                            if plan is None else "plan digest changed before dispatch"
                        )
                        now = time.time()
                        conn.execute(
                            "UPDATE workflow_run_requests SET status='uncertain', "
                            "completed_at=?,error=? WHERE id=? AND status='queued'",
                            (now, reason, row["id"]),
                        )
                        if plan is not None:
                            conn.execute(
                                "INSERT INTO workflow_events "
                                "(plan_id,event_type,detail_json,at) VALUES (?,?,?,?)",
                                (row["plan_id"], "workflow_run_uncertain",
                                 json.dumps({"request_id": row["id"],
                                             "reason": "plan_digest_changed"},
                                            sort_keys=True), now),
                            )
                        continue
                    if plan["status"] == "cancel_requested":
                        conn.execute(
                            "UPDATE workflow_run_requests SET status='cancelled', "
                            "completed_at=?,error='plan cancelled before run claim' "
                            "WHERE id=? AND status='queued'",
                            (time.time(), row["id"]),
                        )
                        continue
                    try:
                        persisted_limits = json.loads(row["limits_json"])
                        self._check_limits(persisted_limits)
                    except (TypeError, ValueError):
                        now = time.time()
                        conn.execute(
                            "UPDATE workflow_run_requests SET status='uncertain', "
                            "completed_at=?,error='invalid persisted execution limits' "
                            "WHERE id=? AND status='queued'",
                            (now, row["id"]),
                        )
                        conn.execute(
                            "INSERT INTO workflow_events "
                            "(plan_id,event_type,detail_json,at) VALUES (?,?,?,?)",
                            (row["plan_id"], "workflow_run_uncertain",
                             json.dumps({"request_id": row["id"],
                                         "reason": "invalid_execution_limits"},
                                        sort_keys=True), now),
                        )
                        continue
                    token = uuid.uuid4().hex
                    now = time.time()
                    conn.execute(
                        "UPDATE workflow_run_requests SET status='running', "
                        "owner=?,lease_token=?,started_at=?,heartbeat_at=? "
                        "WHERE id=? AND status='queued'",
                        (owner, token, now, now, row["id"]),
                    )
                    claimed = conn.execute(
                        "SELECT * FROM workflow_run_requests WHERE id=?",
                        (row["id"],),
                    ).fetchone()
                    conn.execute("COMMIT")
                    return self._format(claimed)
                # A poisoned backlog larger than one bounded pass is
                # reconciled by subsequent polls; no unbounded lock hold.
                conn.execute("COMMIT")
                return None
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def cancel_queued(self, plan_id: str) -> int:
        """Close only unclaimed requests; a running effect is not stopped."""
        with self.store._lock:
            conn = self.store._conn()
            try:
                cursor = conn.execute(
                    "UPDATE workflow_run_requests SET status='cancelled',"
                    "completed_at=?,error='plan cancelled before run claim' "
                    "WHERE plan_id=? AND status='queued'",
                    (time.time(), plan_id),
                )
                return cursor.rowcount
            finally:
                conn.close()

    def heartbeat(self, request_id: str, token: str) -> bool:
        with self.store._lock:
            conn = self.store._conn()
            try:
                cursor = conn.execute(
                    "UPDATE workflow_run_requests SET heartbeat_at=? "
                    "WHERE id=? AND status='running' AND lease_token=?",
                    (time.time(), request_id, token),
                )
                return cursor.rowcount == 1
            finally:
                conn.close()

    def finish(self, request_id: str, token: str, *, status: str,
               error: str = "") -> bool:
        """Fence the terminal result against cancellation in one transaction."""
        if status not in {"completed", "incomplete", "failed", "uncertain"}:
            raise ValueError("invalid run request outcome")
        with self.store._lock:
            conn = self.store._conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT r.plan_id, r.plan_digest, p.digest AS current_digest, "
                    "p.status AS plan_status "
                    "FROM workflow_run_requests r "
                    "LEFT JOIN workflow_plans p ON p.id=r.plan_id "
                    "WHERE r.id=? AND r.status='running' AND r.lease_token=?",
                    (request_id, token),
                ).fetchone()
                if row is None:
                    conn.execute("COMMIT")
                    return False
                reason = None
                if row["plan_status"] is None:
                    status, error = "uncertain", "source plan missing at completion"
                elif row["current_digest"] != row["plan_digest"]:
                    status = "uncertain"
                    error = "source plan digest changed during execution; reconcile effects"
                    reason = "plan_digest_changed_during_run"
                elif row["plan_status"] == "cancel_requested":
                    status = "uncertain"
                    error = "workflow cancelled during execution; reconcile external effects"
                    reason = "plan_cancelled_during_run"
                elif status == "uncertain":
                    reason = "worker_reported_uncertain"
                now = time.time()
                cursor = conn.execute(
                    "UPDATE workflow_run_requests SET status=?,error=?,"
                    "completed_at=?,owner=NULL,lease_token=NULL "
                    "WHERE id=? AND status='running' AND lease_token=?",
                    (status, error, now, request_id, token),
                )
                if cursor.rowcount == 1 and reason is not None:
                    conn.execute(
                        "INSERT INTO workflow_events "
                        "(plan_id,event_type,detail_json,at) VALUES (?,?,?,?)",
                        (row["plan_id"], "workflow_run_uncertain",
                         json.dumps({"request_id": request_id, "reason": reason},
                                    sort_keys=True), now),
                    )
                conn.execute("COMMIT")
                return cursor.rowcount == 1
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def close_reconciled(self, plan_id: str) -> int:
        """Close uncertain run intents only after every active effect is resolved.

        This releases duplicate-submission fencing for an operator to submit
        a new bounded request. It never executes or replays a task.
        """
        with self.store._lock:
            conn = self.store._conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                closed = self.store._close_reconciled_workflow_requests_tx(
                    conn, plan_id,
                )
                conn.execute("COMMIT")
                return closed
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def summary(self, *, stale_after_s: float = 120.0) -> dict:
        """Read-only queue health and safe active identities, not liveness proof.

        A recent heartbeat is evidence of a timestamp, not proof of a live
        worker or authorized external effect. No lease token is disclosed.
        """
        if (isinstance(stale_after_s, bool)
                or not isinstance(stale_after_s, (int, float))
                or not math.isfinite(stale_after_s) or stale_after_s <= 0):
            raise ValueError("stale_after_s must be finite and positive")
        now = time.time()
        conn = self.store._conn()
        try:
            # Pin all queue counters to one SQLite read snapshot so clients
            # cannot observe mutually inconsistent counts during a claim.
            conn.execute("BEGIN")
            rows = conn.execute(
                "SELECT status, COUNT(*) AS count "
                "FROM workflow_run_requests GROUP BY status",
            ).fetchall()
            counts = {
                status: 0 for status in (
                    "queued", "running", "uncertain", "completed",
                    "incomplete", "failed", "cancelled",
                )
            }
            counts.update({row["status"]: int(row["count"]) for row in rows})
            queued = conn.execute(
                "SELECT MIN(submitted_at) AS oldest "
                "FROM workflow_run_requests WHERE status='queued'",
            ).fetchone()["oldest"]
            stale = conn.execute(
                "SELECT COUNT(*) AS total FROM workflow_run_requests "
                "WHERE status='running' AND "
                "(heartbeat_at IS NULL OR heartbeat_at<?)",
                (now - stale_after_s,),
            ).fetchone()["total"]
            active_requests = conn.execute(
                "SELECT id,plan_id,status,submitted_at FROM workflow_run_requests "
                "WHERE status IN ('queued','running','uncertain') "
                "ORDER BY submitted_at,id",
            ).fetchall()
            result = {
                "schema_version": "whaxon.workflow-run-queue-summary.v1",
                "snapshot_at": now,
                "counts": counts,
                "active_requests": [dict(row) for row in active_requests],
                "total": sum(counts.values()),
                "oldest_queued_age_s": (
                    max(0.0, now - queued) if queued is not None else None
                ),
                "stale_running_count": int(stale),
                "uncertain_count": counts["uncertain"],
                "requires_reconciliation_count": counts["uncertain"] + int(stale),
                "stale_after_s": float(stale_after_s),
                "worker_liveness_verified": False,
                "automatic_uncertain_replay": False,
            }
            conn.execute("COMMIT")
            return result
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def reconcile_stale(self, *, older_than_s: float = 120) -> int:
        if (isinstance(older_than_s, bool)
                or not isinstance(older_than_s, (int, float))
                or not math.isfinite(older_than_s) or older_than_s <= 0):
            raise ValueError("stale timeout must be finite and positive")
        with self.store._lock:
            conn = self.store._conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                now = time.time()
                stale = conn.execute(
                    "SELECT id,plan_id FROM workflow_run_requests "
                    "WHERE status='running' AND "
                    "(heartbeat_at IS NULL OR heartbeat_at<?) "
                    "ORDER BY COALESCE(heartbeat_at, started_at, submitted_at), id "
                    "LIMIT 128",
                    (now - older_than_s,),
                ).fetchall()
                for row in stale:
                    conn.execute(
                        "UPDATE workflow_run_requests SET status='uncertain',"
                        "error='run worker lost; reconcile task attempts before any retry',"
                        "completed_at=?,owner=NULL,lease_token=NULL "
                        "WHERE id=? AND status='running'",
                        (now, row["id"]),
                    )
                    if conn.execute(
                        "SELECT 1 FROM workflow_plans WHERE id=?",
                        (row["plan_id"],),
                    ).fetchone() is not None:
                        conn.execute(
                            "INSERT INTO workflow_events "
                            "(plan_id,event_type,detail_json,at) VALUES (?,?,?,?)",
                            (row["plan_id"], "workflow_run_uncertain",
                             json.dumps({"request_id": row["id"],
                                         "reason": "worker_lease_lost"},
                                        sort_keys=True), now),
                        )
                conn.execute("COMMIT")
                return len(stale)
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()
