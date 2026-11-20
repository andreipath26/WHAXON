import hashlib
import hmac
import json
import math
import sqlite3
import threading
import time
from pathlib import Path

_APPROVAL_CANDIDATE_PAGE_SIZE = 256
_APPROVAL_CANDIDATE_SCAN_BUDGET = 10_000

SCHEMA = """
-- The engine that owns a job is durable, not a process-local event hint.
-- Registered V2 jobs must never be dispatched by legacy follow-up rules.
CREATE TABLE IF NOT EXISTS engine_v2_execution_jobs (
    job_id TEXT PRIMARY KEY,
    marked_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, tool TEXT DEFAULT '', target TEXT DEFAULT '', status TEXT DEFAULT 'starting', exit_code INTEGER, error TEXT, started_at REAL, finished_at REAL, duration_s REAL, lease_owner TEXT, lease_token TEXT, heartbeat_at REAL);
CREATE TABLE IF NOT EXISTS lines (job_id TEXT, seq INTEGER, stream TEXT, text TEXT, PRIMARY KEY (job_id, seq));
CREATE TABLE IF NOT EXISTS findings (job_id TEXT, seq INTEGER, kind TEXT, severity TEXT, source TEXT, data_json TEXT, raw_line TEXT, enrichment_json TEXT DEFAULT '{}', verification_status TEXT DEFAULT 'candidate', verified_by TEXT DEFAULT 'engine', verification_reason TEXT DEFAULT '', PRIMARY KEY (job_id, seq));
CREATE TABLE IF NOT EXISTS coverage (job_id TEXT, seq INTEGER, tool_id TEXT, target TEXT, kind TEXT, detail TEXT, phase TEXT DEFAULT '', at REAL, PRIMARY KEY (job_id, seq));
CREATE INDEX IF NOT EXISTS idx_jobs_started ON jobs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_lines_job ON lines(job_id, seq);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    host TEXT,
    type TEXT,
    info_json TEXT,
    opened_at REAL,
    last_seen REAL,
    status TEXT DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS evidence (
    job_id TEXT, seq INTEGER, kind TEXT, name TEXT, path TEXT, note TEXT, added_at REAL,
    PRIMARY KEY (job_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_evidence_job ON evidence(job_id, seq);
CREATE TABLE IF NOT EXISTS ai_runs (id TEXT PRIMARY KEY, goal TEXT NOT NULL, provider TEXT DEFAULT 'null', status TEXT DEFAULT 'running', started_at REAL, finished_at REAL, error TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS ai_run_steps (run_id TEXT, seq INTEGER, action_json TEXT, result_json TEXT, created_at REAL, PRIMARY KEY (run_id, seq));
CREATE INDEX IF NOT EXISTS idx_ai_runs_started ON ai_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_run_steps_run ON ai_run_steps(run_id, seq);
CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY, objective TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft',
    metadata_json TEXT NOT NULL DEFAULT '{}', created_at REAL NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_plans (
    id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, schema_version TEXT NOT NULL,
    digest TEXT NOT NULL, plan_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'proposed',
    created_at REAL NOT NULL, UNIQUE(mission_id, digest)
);
CREATE INDEX IF NOT EXISTS idx_workflow_plans_mission ON workflow_plans(mission_id, created_at);
CREATE TABLE IF NOT EXISTS workflow_tasks (
    id TEXT PRIMARY KEY, task_key TEXT NOT NULL, plan_id TEXT NOT NULL, capability_id TEXT NOT NULL,
    target TEXT NOT NULL, inputs_json TEXT NOT NULL, depends_on_json TEXT NOT NULL,
    permissions_json TEXT NOT NULL, impact TEXT NOT NULL, timeout_s REAL NOT NULL,
    idempotency_key TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending',
    result_json TEXT, error TEXT, active_attempt_id TEXT,
    created_at REAL NOT NULL, updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_workflow_tasks_plan ON workflow_tasks(plan_id);
CREATE TABLE IF NOT EXISTS capability_manifests (capability_id TEXT NOT NULL, provider_id TEXT NOT NULL, provider_version TEXT NOT NULL, fingerprint TEXT NOT NULL, manifest_json TEXT NOT NULL, registered_at REAL NOT NULL, PRIMARY KEY (capability_id, provider_id, provider_version));
CREATE TABLE IF NOT EXISTS workflow_approvals (
    approval_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    task_key TEXT NOT NULL,
    actor TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    revoked_at REAL
);
CREATE INDEX IF NOT EXISTS idx_workflow_approvals_plan ON workflow_approvals(plan_id, task_key);
CREATE TABLE IF NOT EXISTS workflow_rate_limits (
    plan_id TEXT PRIMARY KEY,
    min_spacing_s REAL NOT NULL,
    last_claimed_at REAL
);
CREATE TABLE IF NOT EXISTS workflow_deadlines (
    plan_id TEXT PRIMARY KEY, deadline_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS mission_rate_limits (
    mission_id TEXT PRIMARY KEY,
    min_spacing_s REAL NOT NULL,
    last_claimed_at REAL
);
CREATE TABLE IF NOT EXISTS mission_cost_limits (
    mission_id TEXT PRIMARY KEY, max_cost_microusd INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_attempt_costs (
    attempt_id TEXT PRIMARY KEY, cost_microusd INTEGER NOT NULL,
    source TEXT NOT NULL, recorded_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_workflow_attempt_costs_attempt ON workflow_attempt_costs(attempt_id);
CREATE TABLE IF NOT EXISTS mission_deadlines (
    mission_id TEXT PRIMARY KEY,
    deadline_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS mission_execution_limits (
    mission_id TEXT PRIMARY KEY,
    max_total_attempts INTEGER NOT NULL,
    max_concurrency INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_limits (
    plan_id TEXT PRIMARY KEY,
    max_total_attempts INTEGER NOT NULL,
    max_concurrency INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_event_cursors (
    plan_id TEXT NOT NULL,
    consumer_id TEXT NOT NULL,
    last_event_id INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL,
    PRIMARY KEY (plan_id, consumer_id)
);
CREATE TABLE IF NOT EXISTS workflow_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL, task_ref TEXT, attempt_id TEXT,
    event_type TEXT NOT NULL, detail_json TEXT NOT NULL DEFAULT '{}',
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_workflow_events_plan ON workflow_events(plan_id, id);
CREATE TABLE IF NOT EXISTS task_attempts (
    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, attempt_no INTEGER NOT NULL,
    status TEXT NOT NULL, worker_id TEXT NOT NULL DEFAULT '', idempotency_key TEXT NOT NULL DEFAULT '',
    started_at REAL NOT NULL, heartbeat_at REAL, finished_at REAL, result_json TEXT, error TEXT,
    UNIQUE(task_id, attempt_no)
);
CREATE TABLE IF NOT EXISTS workflow_attempt_reconciliations (
    attempt_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN
      ('no_effect_verified','effect_observed','unresolved')),
    actor TEXT NOT NULL, evidence_ref TEXT NOT NULL, note TEXT NOT NULL,
    recorded_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempt_reconciliations_plan
    ON workflow_attempt_reconciliations(plan_id, recorded_at);
CREATE INDEX IF NOT EXISTS idx_task_attempts_task ON task_attempts(task_id, attempt_no);
CREATE TABLE IF NOT EXISTS workflow_evidence_seals (
    attempt_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, digest TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1, sealed_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_workflow_evidence_seals_job ON workflow_evidence_seals(job_id);
"""




def _workflow_evidence_digest(conn, *, attempt_id, job_id, target, capability_id, plan_digest):
    """Hash a canonical persisted database snapshot for drift detection.

    A local SHA-256 baseline is not a tamper-proof external audit signature.
    Evidence file paths are covered as metadata, not file contents.
    """
    job = conn.execute(
        "SELECT id, tool, target, status, exit_code, error, started_at, finished_at, "
        "duration_s FROM jobs WHERE id=?", (job_id,),
    ).fetchone()
    if not isinstance(capability_id, str) or not capability_id:
        return None
    expected_tool = (
        capability_id.removeprefix("tool.")
        if capability_id.startswith("tool.") else capability_id
    )
    if (
        job is None or job["tool"] != expected_tool
        or job["target"] != target or job["status"] != "finished"
        or job["exit_code"] != 0
    ):
        return None
    snapshot = {
        "version": 1, "attempt_id": attempt_id, "plan_digest": plan_digest,
        "capability_id": capability_id, "target": target, "job": dict(job),
    }
    for table, columns in (
        ("lines", "seq, stream, text"),
        ("findings", "seq, kind, severity, source, data_json, raw_line, "
                     "enrichment_json, verification_status, verified_by, verification_reason"),
        ("coverage", "seq, tool_id, target, kind, detail, phase, at"),
        ("evidence", "seq, kind, name, path, note, added_at"),
    ):
        snapshot[table] = [
            dict(row) for row in conn.execute(
                f"SELECT {columns} FROM {table} WHERE job_id=? ORDER BY seq",
                (job_id,),
            )
        ]
    encoded = json.dumps(snapshot, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _signature_for(kind: str, data: dict) -> str:
    """Build a stable per-finding signature for dedup."""
    if kind == "open_port":
        return f"port:{data.get('port')}/{data.get('protocol', 'tcp')}"
    if kind == "web_issue":
        # A single URL/path can host multiple independent issues (for example,
        # distinct Nikto plugin IDs). Preserve their identities while still
        # aggregating repeat observations of the same issue across jobs.
        path = data.get("path") or data.get("location") or ""
        issue_id = (
            data.get("nikto_id") or data.get("plugin_id")
            or data.get("issue_id") or ""
        )
        message = " ".join(
            str(data.get("message") or data.get("issue") or data.get("title") or "")
            .lower().split()
        )
        return f"path:{path}|issue:{issue_id}|message:{message}"
    if kind == "found_path":
        # A path is not a single fact: different tools or runs can observe
        # different status codes and response sizes for the same URL. Include
        # the observed response attributes so target-level aggregation never
        # silently discards contradictory scanner evidence.
        return "path:%s|status:%s|size:%s" % (
            data.get("path") or "",
            data.get("status") if data.get("status") is not None else "unknown",
            data.get("size") if data.get("size") is not None else "unknown",
        )
    if kind == "sqli":
        return f"param:{data.get('parameter') or ''}"
    if kind == "sqli_database":
        return f"db:{data.get('name') or ''}"
    if kind == "sqli_table":
        return f"table:{data.get('database') or ''}.{data.get('table') or ''}"
    if kind.startswith("sqli_"):
        return f"key:{data.get('key') or ''}"
    if kind == "domain_expiry":
        return "domain_expiry"
    if kind == "registrar":
        return f"registrar:{data.get('registrar') or ''}"
    if kind == "nameserver":
        return f"ns:{data.get('ns') or ''}"
    if kind == "vulnerability":
        return f"template:{data.get('template') or ''}"
    if kind == "correlated":
        # Correlator findings carry pattern + service + version + cve.
        # Distinct service/version combos must not collapse.
        return "pattern:%s|%s|%s|%s" % (
            data.get("pattern") or "",
            data.get("service") or "",
            data.get("version") or "",
            data.get("cve") or "",
        )
    if kind == "msf_session":
        return "msf:%s" % (data.get("session_id") or data.get("sid") or "")
    if kind == "ntlm_hash":
        return "ntlm:%s" % (data.get("user") or data.get("username") or "")
    if kind == "hashcat_crack":
        return "hashcat:%s" % (data.get("hash") or "")[:32]
    # Fallback: a stable hash of the whole data dict, never just the
    # first value. Two distinct findings with different data must never
    # produce the same signature.
    import hashlib as _hashlib
    import json as _json
    blob = _json.dumps(data or {}, sort_keys=True, default=str)
    return "data:" + _hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

class JobStore:
    def __init__(self, db_path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        c = self._conn()
        try:
            c.executescript(SCHEMA)
            # Durable worker leases. Existing databases are upgraded in place.
            try:
                c.execute("ALTER TABLE task_attempts ADD COLUMN heartbeat_at REAL")
            except sqlite3.OperationalError:
                pass
            for column, definition in (
                ("lease_owner", "TEXT"),
                ("lease_token", "TEXT"),
                ("heartbeat_at", "REAL"),
            ):
                try:
                    c.execute(f"ALTER TABLE jobs ADD COLUMN {column} {definition}")
                except sqlite3.OperationalError:
                    pass
            # Migration: add phase column to ai_runs if absent (step 2 of the
            # agent-architecture migration plan). Idempotent: SQLite raises
            # if the column exists, which we swallow.
            try:
                c.execute("ALTER TABLE ai_runs ADD COLUMN phase TEXT DEFAULT 'recon'")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE ai_runs ADD COLUMN phase_history TEXT DEFAULT '[]'")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE ai_runs ADD COLUMN pending_question TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE ai_runs ADD COLUMN tokens_in INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE ai_runs ADD COLUMN tokens_out INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE ai_runs ADD COLUMN cost_usd REAL")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE ai_runs ADD COLUMN owner TEXT DEFAULT 'local'")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE ai_runs ADD COLUMN consecutive_failures INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE ai_runs ADD COLUMN auto INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE findings ADD COLUMN verification_status TEXT DEFAULT 'candidate'")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE findings ADD COLUMN verified_by TEXT DEFAULT 'engine'")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE findings ADD COLUMN verification_reason TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE coverage ADD COLUMN phase TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE workflow_tasks ADD COLUMN active_attempt_id TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                c.execute("ALTER TABLE workflow_tasks ADD COLUMN task_key TEXT")
            except sqlite3.OperationalError:
                pass
            c.execute("UPDATE workflow_tasks SET task_key=id WHERE task_key IS NULL")
            c.execute("CREATE TABLE IF NOT EXISTS approvals (run_id TEXT, seq INTEGER, user TEXT, answer TEXT, note TEXT, at REAL, PRIMARY KEY (run_id, seq))")
        finally: c.close()
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.row_factory = sqlite3.Row
        return c
    def mark_engine_v2_execution_job(self, job_id: str) -> None:
        """Persist V2 job ownership before any external process starts."""
        if not isinstance(job_id, str) or not job_id:
            raise ValueError("valid V2 job identity required")
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO engine_v2_execution_jobs "
                    "(job_id, marked_at) VALUES (?, ?)",
                    (job_id, time.time()),
                )
            finally:
                conn.close()

    def is_engine_v2_execution_job(self, job_id: str) -> bool:
        """Read durable origin even across multiple findings and restarts."""
        if not isinstance(job_id, str) or not job_id:
            return False
        conn = self._conn()
        try:
            return conn.execute(
                "SELECT 1 FROM engine_v2_execution_jobs WHERE job_id=?",
                (job_id,),
            ).fetchone() is not None
        finally:
            conn.close()

    def create(self, job_id):
        with self._lock:
            c = self._conn()
            try: c.execute("INSERT OR IGNORE INTO jobs (id, started_at) VALUES (?, ?)", (job_id, time.time()))
            finally: c.close()
    def set_started(self, job_id, tool, target, lease_token=None):
        with self._lock:
            c = self._conn()
            try:
                now = time.time()
                if lease_token:
                    cur = c.execute(
                        "UPDATE jobs SET status='running', tool=?, target=?, started_at=?, heartbeat_at=? "
                        "WHERE id=? AND status='running' AND lease_token=?",
                        (tool, target, now, now, job_id, lease_token),
                    )
                else:
                    cur = c.execute(
                        "UPDATE jobs SET status='running', tool=?, target=?, started_at=? WHERE id=?",
                        (tool, target, now, job_id),
                    )
                return cur.rowcount == 1
            finally:
                c.close()

    def create_pending(self, job_id, tool, target):
        """Queue a job durably; it remains pending until atomically leased."""
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "INSERT OR IGNORE INTO jobs (id, tool, target, status) VALUES (?, ?, ?, 'pending')",
                    (job_id, tool, target),
                )
            finally:
                c.close()

    def list_pending(self):
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT id, tool, target FROM jobs WHERE status='pending' ORDER BY started_at"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()

    def claim_pending(self, *, exclude_ids=None, include_ids=None, worker_id=None):
        """Atomically lease one pending job and return its fencing token."""
        import secrets

        excluded = tuple(exclude_ids or ())
        included = None if include_ids is None else tuple(dict.fromkeys(include_ids))
        owner = str(worker_id or "worker")
        token = secrets.token_urlsafe(32)
        now = time.time()
        if included == ():
            return None
        with self._lock:
            c = self._conn()
            try:
                where = "status='pending'"
                params = []
                if included is not None:
                    placeholders = ",".join("?" for _ in included)
                    where += f" AND id IN ({placeholders})"
                    params.extend(included)
                if excluded:
                    placeholders = ",".join("?" for _ in excluded)
                    where += f" AND id NOT IN ({placeholders})"
                    params.extend(excluded)
                row = c.execute(
                    "UPDATE jobs SET status='running', started_at=?, lease_owner=?, "
                    "lease_token=?, heartbeat_at=? WHERE id=(SELECT id FROM jobs WHERE "
                    + where + " ORDER BY started_at, id LIMIT 1) "
                    "RETURNING id, tool, target, lease_owner, lease_token, heartbeat_at",
                    (now, owner, token, now, *params),
                ).fetchone()
                return dict(row) if row else None
            finally:
                c.close()

    def heartbeat_job(self, job_id, lease_token):
        """Renew a worker lease; false means ownership has been lost."""
        with self._lock:
            c = self._conn()
            try:
                cur = c.execute(
                    "UPDATE jobs SET heartbeat_at=? WHERE id=? AND status='running' AND lease_token=?",
                    (time.time(), job_id, lease_token),
                )
                return cur.rowcount == 1
            finally:
                c.close()

    def owns_lease(self, job_id, lease_token):
        if not lease_token:
            return True
        c = self._conn()
        try:
            return c.execute(
                "SELECT 1 FROM jobs WHERE id=? AND status IN ('running', 'finished') AND lease_token=?",
                (job_id, lease_token),
            ).fetchone() is not None
        finally:
            c.close()

    def release_lease(self, job_id, lease_token):
        """Release a terminal job lease after its event callbacks have persisted."""
        if not lease_token:
            return False
        with self._lock:
            c = self._conn()
            try:
                cur = c.execute(
                    "UPDATE jobs SET lease_owner=NULL, lease_token=NULL, heartbeat_at=NULL "
                    "WHERE id=? AND status IN ('finished', 'failed') AND lease_token=?",
                    (job_id, lease_token),
                )
                return cur.rowcount == 1
            finally:
                c.close()

    def reconcile_stale(self, older_than_s=120.0):
        """Fail expired running jobs without replaying uncertain side effects."""
        cutoff = time.time() - older_than_s
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                cur = c.execute(
                    "UPDATE jobs SET status='failed', "
                    "error='worker lease expired; execution outcome requires reconciliation', "
                    "finished_at=?, lease_owner=NULL, lease_token=NULL, heartbeat_at=NULL "
                    "WHERE status='running' AND COALESCE(heartbeat_at, started_at) < ?",
                    (now, cutoff),
                )
                return cur.rowcount
            finally:
                c.close()

    def append_line(self, job_id, stream, text):
        with self._lock:
            c = self._conn()
            try:
                row = c.execute("SELECT COALESCE(MAX(seq), -1) + 1 AS n FROM lines WHERE job_id=?", (job_id,)).fetchone()
                c.execute("INSERT INTO lines VALUES (?, ?, ?, ?)", (job_id, row["n"], stream, text))
            finally: c.close()
    def append_finding(self, job_id, f, seq):
        if hasattr(f, "to_dict"):
            f = f.to_dict()
        enrichment = {
            "remediation": f.get("remediation", ""),
            "impact": f.get("impact", ""),
            "cvss": f.get("cvss"),
            "cwe": f.get("cwe", ""),
            "references": f.get("references", []),
            "lookup_hint": f.get("lookup_hint", ""),
            # Keep the canonical request context alongside enrichment so it
            # survives the SQLite round trip without a destructive schema migration.
            "request_context": f.get("request_context") or {},
        }
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "INSERT INTO findings (job_id, seq, kind, severity, source, data_json, raw_line, enrichment_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (job_id, seq, f.get("kind",""), f.get("severity","info"), f.get("source",""), json.dumps(f.get("data",{})), f.get("raw_line",""), json.dumps(enrichment))
                )
            finally: c.close()

    def update_verification(self, job_id, seq, status, by="engine", reason=""):
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "UPDATE findings SET verification_status=?, verified_by=?, verification_reason=? WHERE job_id=? AND seq=?",
                    (status, by, reason, job_id, seq),
                )
            finally: c.close()

    def set_proof(self, job_id, seq, proof):
        """Save a reproducible proof (e.g., curl command) into the finding's enrichment."""
        with self._lock:
            c = self._conn()
            try:
                row = c.execute(
                    "SELECT enrichment_json FROM findings WHERE job_id=? AND seq=?",
                    (job_id, seq)
                ).fetchone()
                if not row:
                    return
                enrichment = json.loads(row["enrichment_json"] or "{}")
                enrichment["proof"] = proof
                c.execute(
                    "UPDATE findings SET enrichment_json=? WHERE job_id=? AND seq=?",
                    (json.dumps(enrichment), job_id, seq)
                )
            finally:
                c.close()

    def record_coverage(self, job_id, tool_id, target, kind, detail, phase=""):
        with self._lock:
            c = self._conn()
            try:
                n = c.execute("SELECT COUNT(*) FROM coverage WHERE job_id=?", (job_id,)).fetchone()[0]
                c.execute(
                    "INSERT INTO coverage (job_id, seq, tool_id, target, kind, detail, phase, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (job_id, n, tool_id, target, kind, detail, phase, time.time()),
                )
            finally: c.close()

    def list_coverage(self, job_id):
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT seq, tool_id, target, kind, detail, phase FROM coverage WHERE job_id=? ORDER BY seq",
                (job_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally: c.close()

    def set_finished(self, job_id, exit_code, duration_s, lease_token=None):
        with self._lock:
            c = self._conn()
            try:
                if lease_token:
                    cur = c.execute(
                        "UPDATE jobs SET status='finished', exit_code=?, duration_s=?, finished_at=? "
                        "WHERE id=? AND status='running' AND lease_token=?",
                        (exit_code, duration_s, time.time(), job_id, lease_token),
                    )
                else:
                    cur = c.execute(
                        "UPDATE jobs SET status='finished', exit_code=?, duration_s=?, finished_at=? WHERE id=?",
                        (exit_code, duration_s, time.time(), job_id),
                    )
                return cur.rowcount == 1
            finally:
                c.close()

    def set_failed(self, job_id, error, lease_token=None):
        with self._lock:
            c = self._conn()
            try:
                if lease_token:
                    cur = c.execute(
                        "UPDATE jobs SET status='failed', error=?, finished_at=?, "
                        "lease_owner=NULL, lease_token=NULL, heartbeat_at=NULL "
                        "WHERE id=? AND status='running' AND lease_token=?",
                        (error, time.time(), job_id, lease_token),
                    )
                else:
                    cur = c.execute(
                        "UPDATE jobs SET status='failed', error=?, finished_at=? WHERE id=?",
                        (error, time.time(), job_id),
                    )
                return cur.rowcount == 1
            finally:
                c.close()
    def add_evidence(self, job_id, kind, name, path=None, note=None):
        with self._lock:
            c = self._conn()
            try:
                row = c.execute(
                    "SELECT COALESCE(MAX(seq), -1) + 1 AS n FROM evidence WHERE job_id=?",
                    (job_id,)
                ).fetchone()
                seq = row["n"]
                c.execute(
                    "INSERT INTO evidence (job_id, seq, kind, name, path, note, added_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (job_id, seq, kind, name, path, note, time.time()),
                )
                return seq
            finally:
                c.close()

    def list_evidence(self, job_id):
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT seq, kind, name, path, note, added_at FROM evidence "
                "WHERE job_id=? ORDER BY seq", (job_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()

    def remove_evidence(self, job_id, seq):
        with self._lock:
            c = self._conn()
            try:
                cur = c.execute("DELETE FROM evidence WHERE job_id=? AND seq=?", (job_id, seq))
                return cur.rowcount > 0
            finally:
                c.close()

    # ---- msf sessions ----

    def upsert_session(self, session_id, host, session_type, info=None):
        import json as _json
        with self._lock:
            c = self._conn()
            try:
                now = time.time()
                existing = c.execute(
                    "SELECT id FROM sessions WHERE id=?", (session_id,)
                ).fetchone()
                if existing:
                    c.execute(
                        "UPDATE sessions SET host=?, type=?, info_json=?, last_seen=?, status='open' WHERE id=?",
                        (host, session_type, _json.dumps(info or {}), now, session_id),
                    )
                else:
                    c.execute(
                        "INSERT INTO sessions (id, host, type, info_json, opened_at, last_seen, status) "
                        "VALUES (?, ?, ?, ?, ?, ?, 'open')",
                        (session_id, host, session_type, _json.dumps(info or {}), now, now),
                    )
            finally:
                c.close()

    def touch_session(self, session_id, info=None):
        """Refresh session telemetry without changing its original identity."""
        with self._lock:
            c = self._conn()
            try:
                cur = c.execute(
                    "UPDATE sessions SET info_json=?, last_seen=? "
                    "WHERE id=? AND status='open'",
                    (json.dumps(info or {}), time.time(), str(session_id)),
                )
                return cur.rowcount == 1
            finally:
                c.close()

    def close_session(self, session_id):
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "UPDATE sessions SET status='closed', last_seen=? WHERE id=?",
                    (time.time(), session_id),
                )
            finally:
                c.close()

    def get_session(self, session_id):
        """Return one persisted session, including its authorization context."""
        import json as _json
        c = self._conn()
        try:
            row = c.execute(
                "SELECT id, host, type, info_json, opened_at, last_seen, status "
                "FROM sessions WHERE id=?",
                (str(session_id),),
            ).fetchone()
            if row is None:
                return None
            try:
                info = _json.loads(row["info_json"] or "{}")
            except (TypeError, ValueError):
                info = {}
            return {
                "id": row["id"], "host": row["host"], "type": row["type"],
                "info": info, "opened_at": row["opened_at"],
                "last_seen": row["last_seen"], "status": row["status"],
            }
        finally:
            c.close()

    def list_sessions(self, include_closed=False):
        import json as _json
        c = self._conn()
        try:
            if include_closed:
                rows = c.execute(
                    "SELECT id, host, type, info_json, opened_at, last_seen, status "
                    "FROM sessions ORDER BY opened_at DESC"
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT id, host, type, info_json, opened_at, last_seen, status "
                    "FROM sessions WHERE status='open' ORDER BY opened_at DESC"
                ).fetchall()
            out = []
            for r in rows:
                try:
                    info = _json.loads(r["info_json"] or "{}")
                except Exception:
                    info = {}
                out.append({
                    "id": r["id"], "host": r["host"], "type": r["type"],
                    "info": info, "opened_at": r["opened_at"],
                    "last_seen": r["last_seen"], "status": r["status"],
                })
            return out
        finally:
            c.close()

    def get(self, job_id):
        c = self._conn()
        try:
            j = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not j: return None
            lines = c.execute("SELECT stream, text FROM lines WHERE job_id=? ORDER BY seq", (job_id,)).fetchall()
            return {"id": j["id"], "tool": j["tool"], "target": j["target"], "status": j["status"], "exit_code": j["exit_code"], "error": j["error"], "duration_s": j["duration_s"], "lines": [{"stream": ln["stream"], "text": ln["text"]} for ln in lines]}
        finally: c.close()
    def get_findings(self, job_id):
        c = self._conn()
        try:
            if not c.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone(): return None
            rows = c.execute(
                "SELECT seq, kind, severity, source, data_json, raw_line, enrichment_json, verification_status, verified_by, verification_reason "
                "FROM findings WHERE job_id=? ORDER BY seq", (job_id,)
            ).fetchall()
            out = []
            for r in rows:
                enrichment = {}
                try:
                    enrichment = json.loads(r["enrichment_json"] or "{}")
                except (json.JSONDecodeError, TypeError):
                    pass
                out.append({
                    "seq": r["seq"],
                    "verification_status": r["verification_status"],
                    "verified_by": r["verified_by"],
                    "verification_reason": r["verification_reason"],
                    "kind": r["kind"],
                    "severity": r["severity"],
                    "source": r["source"],
                    "data": json.loads(r["data_json"]),
                    "raw_line": r["raw_line"],
                    "remediation": enrichment.get("remediation", ""),
                    "impact": enrichment.get("impact", ""),
                    "cvss": enrichment.get("cvss"),
                    "cwe": enrichment.get("cwe", ""),
                    "references": enrichment.get("references", []),
                    "lookup_hint": enrichment.get("lookup_hint", ""),
                    "proof": enrichment.get("proof", ""),
                    "request_context": enrichment.get("request_context") or {},
                })
            return out
        finally: c.close()
    def active_jobs(self):
        """Return currently running jobs for live operational controls."""
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT id, tool, target, status, started_at, "
                "EXISTS(SELECT 1 FROM engine_v2_execution_jobs v2 "
                "WHERE v2.job_id=jobs.id) AS engine_v2_owned FROM jobs "
                "WHERE status='running' ORDER BY started_at DESC"
            ).fetchall()
            return [
                {**dict(row), "engine_v2_owned": bool(row["engine_v2_owned"])}
                for row in rows
            ]
        finally:
            c.close()

    def history(self, limit=50):
        c = self._conn()
        try:
            rows = c.execute("SELECT id, tool, target, status, exit_code, duration_s, started_at FROM jobs WHERE status IN ('finished','failed') ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
            out = []
            for r in rows:
                line_count = c.execute(
                    "SELECT COUNT(*) AS n FROM lines WHERE job_id=?", (r["id"],)
                ).fetchone()["n"]
                findings_count = c.execute(
                    "SELECT COUNT(*) AS n FROM findings WHERE job_id=?", (r["id"],)
                ).fetchone()["n"]
                out.append({
                    "id": r["id"],
                    "tool": r["tool"],
                    "target": r["target"],
                    "status": r["status"],
                    "exit_code": r["exit_code"],
                    "duration_s": r["duration_s"],
                    "started_at": r["started_at"],
                    "line_count": line_count,
                    "findings_count": findings_count,
                })
            return out
        finally: c.close()

    def findings_by_target(self, limit: int = 50) -> list[dict]:
        """Group findings by target, deduped by (kind, signature)."""
        with self._lock:
            c = self._conn()
            try:
                # Get all jobs with their targets
                job_rows = c.execute(
                    "SELECT id, tool, target, status, exit_code, started_at "
                    "FROM jobs WHERE target != '' "
                    "ORDER BY started_at DESC LIMIT ?",
                    (limit * 5,),
                ).fetchall()

                targets: dict = {}
                seen: dict = {}  # (target, kind, sig) -> index in targets[target]["findings"]

                from .scope import _normalize_target
                for j in job_rows:
                    # Group by host, not raw target: 172.17.0.3 and
                    # 172.17.0.3:80 are the same target to a pentester.
                    target = _normalize_target(j["target"])[0] or j["target"]
                    if target not in targets:
                        targets[target] = {
                            "target": target,
                            "job_count": 0,
                            "finding_count": 0,
                            "findings": [],
                            "jobs": [],
                        }
                    t = targets[target]
                    t["jobs"].append({
                        "id": j["id"],
                        "tool": j["tool"],
                        "status": j["status"],
                        "exit_code": j["exit_code"],
                        "started_at": j["started_at"],
                    })
                    t["job_count"] += 1

                    # Pull findings for this job
                    f_rows = c.execute(
                        "SELECT kind, severity, source, data_json, raw_line, enrichment_json "
                        "FROM findings WHERE job_id=? ORDER BY seq",
                        (j["id"],),
                    ).fetchall()
                    for f in f_rows:
                        import json as _json
                        try:
                            data = _json.loads(f["data_json"] or "{}")
                        except Exception:
                            data = {}
                        try:
                            enrich = _json.loads(f["enrichment_json"] or "{}")
                        except Exception:
                            enrich = {}

                        sig = _signature_for(f["kind"], data)
                        # Preserve source provenance for path discoveries:
                        # two tools may report the same path with conflicting
                        # status/size values. _signature_for includes the observed
                        # status and size, while source prevents same-shaped but
                        # independently produced observations from collapsing.
                        key = (
                            target, f["kind"], sig,
                            f["source"] if f["kind"] == "found_path" else "",
                        )
                        if key in seen:
                            idx = seen[key]
                            t["findings"][idx]["count"] += 1
                            t["finding_count"] += 1
                            continue

                        t["findings"].append({
                            "kind": f["kind"],
                            "severity": f["severity"],
                            "source": f["source"],
                            "signature": sig,
                            "count": 1,
                            "data": data,
                            "raw_line": f["raw_line"],
                            "remediation": enrich.get("remediation", ""),
                            "impact": enrich.get("impact", ""),
                            "cvss": enrich.get("cvss"),
                            "cwe": enrich.get("cwe", ""),
                        })
                        seen[key] = len(t["findings"]) - 1
                        t["finding_count"] += 1

                # Sort by most recent job
                result = sorted(
                    [t for t in targets.values() if t["finding_count"] > 0],
                    key=lambda x: x["jobs"][0]["started_at"] if x["jobs"] else 0,
                    reverse=True,
                )
                return result[:limit]
            finally:
                c.close()

    def save_capability_manifest(self, manifest):
        import hashlib
        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        key = (manifest["capability_id"], manifest["provider_id"], manifest["provider_version"])
        fingerprint = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        with self._lock:
            c = self._conn()
            try:
                row = c.execute(
                    "SELECT fingerprint FROM capability_manifests WHERE capability_id=? AND provider_id=? AND provider_version=?",
                    key,
                ).fetchone()
                if row is not None:
                    if row["fingerprint"] != fingerprint:
                        raise ValueError("provider manifest version is immutable")
                    return False
                c.execute(
                    "INSERT INTO capability_manifests (capability_id, provider_id, provider_version, fingerprint, manifest_json, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (*key, fingerprint, encoded, time.time()),
                )
                return True
            finally:
                c.close()

    def list_capability_manifests(self, capability_id=None):
        c = self._conn()
        try:
            if capability_id is None:
                rows = c.execute(
                    "SELECT manifest_json FROM capability_manifests ORDER BY capability_id, provider_id, provider_version"
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT manifest_json FROM capability_manifests WHERE capability_id=? ORDER BY provider_id, provider_version",
                    (capability_id,),
                ).fetchall()
            return [json.loads(row["manifest_json"]) for row in rows]
        finally:
            c.close()

    # --- Engine v2 mission and workflow persistence ----------------------

    def create_mission(self, mission_id, objective, metadata=None):
        """Persist a mission objective; repeated identical creation is idempotent."""
        if not mission_id or not str(mission_id).strip() or not objective or not str(objective).strip():
            raise ValueError("mission id and objective are required")
        now = time.time()
        encoded = json.dumps(metadata or {}, sort_keys=True)
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "INSERT OR IGNORE INTO missions "
                    "(id, objective, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (mission_id, objective, encoded, now, now),
                )
                row = c.execute("SELECT objective, metadata_json FROM missions WHERE id=?", (mission_id,)).fetchone()
                if row["objective"] != objective or row["metadata_json"] != encoded:
                    raise ValueError("mission id already exists with different content")
                return self.get_mission(mission_id)
            finally:
                c.close()

    def get_mission(self, mission_id):
        c = self._conn()
        try:
            row = c.execute("SELECT * FROM missions WHERE id=?", (mission_id,)).fetchone()
            if row is None:
                return None
            value = dict(row)
            value["metadata"] = json.loads(value.pop("metadata_json") or "{}")
            return value
        finally:
            c.close()

    def save_workflow_plan(self, plan_id, plan):
        """Persist an immutable validated plan with plan-local task identifiers."""
        import uuid

        from .workflow import WorkflowPlan
        if isinstance(plan, dict):
            plan = WorkflowPlan.from_dict(plan)
        if not isinstance(plan, WorkflowPlan):
            raise TypeError("plan must be a WorkflowPlan or its dictionary representation")
        if not plan_id or not str(plan_id).strip():
            raise ValueError("plan_id is required")
        encoded = json.dumps(plan.to_dict(), sort_keys=True, separators=(",", ":"))
        task_refs = {
            task.id: uuid.uuid5(uuid.NAMESPACE_URL, f"whaxon:{plan_id}:{task.id}").hex
            for task in plan.tasks
        }
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if c.execute("SELECT 1 FROM missions WHERE id=?", (plan.mission_id,)).fetchone() is None:
                    raise ValueError(f"unknown mission: {plan.mission_id}")
                existing = c.execute(
                    "SELECT digest FROM workflow_plans WHERE id=?", (plan_id,)
                ).fetchone()
                if existing:
                    if existing["digest"] != plan.digest:
                        raise ValueError("workflow plan ids are immutable; create a new plan id")
                    c.execute("COMMIT")
                    return False
                c.execute(
                    "INSERT INTO workflow_plans "
                    "(id, mission_id, schema_version, digest, plan_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (plan_id, plan.mission_id, plan.schema_version, plan.digest, encoded, now),
                )
                for task in plan.tasks:
                    c.execute(
                        "INSERT INTO workflow_tasks "
                        "(id, task_key, plan_id, capability_id, target, inputs_json, depends_on_json, "
                        "permissions_json, impact, timeout_s, idempotency_key, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            task_refs[task.id], task.id, plan_id, task.capability_id, task.target,
                            json.dumps(task.inputs, sort_keys=True),
                            json.dumps([task_refs[dep] for dep in task.depends_on]),
                            json.dumps(task.permissions), task.impact, task.timeout_s,
                            task.idempotency_key, now, now,
                        ),
                    )
                c.execute("COMMIT")
                return True
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def grant_workflow_approval(
        self, plan_id, task_key, approval_id, actor, *, expires_at,
        policy_version="policy.v1",
    ):
        """Persist attributable consent bound to the immutable task and plan.

        Recording consent does not grant execution permission. Scope and provider
        policy are independently checked at each dispatch boundary.
        """
        import math
        from dataclasses import asdict

        from .workflow import ApprovalBinding, WorkflowPlan

        for name, item in (
            ("approval_id", approval_id), ("actor", actor),
            ("policy_version", policy_version), ("task_key", task_key),
        ):
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"{name} must be a nonempty string")
        if (
            isinstance(expires_at, bool) or not isinstance(expires_at, (int, float))
            or not math.isfinite(expires_at) or expires_at <= time.time()
        ):
            raise ValueError("approval expiry must be finite and in the future")
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT p.plan_json, p.digest, p.status FROM workflow_plans p "
                    "WHERE p.id=?", (plan_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"unknown workflow plan: {plan_id}")
                if row["status"] == "cancel_requested":
                    raise ValueError("workflow cancellation requested")
                plan = WorkflowPlan.from_dict(json.loads(row["plan_json"]))
                matching = [task for task in plan.tasks if task.id == task_key]
                if not matching:
                    raise ValueError(f"unknown workflow task: {task_key}")
                task = matching[0]
                binding = ApprovalBinding(
                    plan_digest=row["digest"], task_id=task_key,
                    target=task.target, input_digest=ApprovalBinding.digest_inputs(task.inputs),
                    policy_version=policy_version, expires_at=float(expires_at),
                    permissions=task.permissions, impact=task.impact,
                )
                encoded = json.dumps(asdict(binding), sort_keys=True)
                existing = c.execute(
                    "SELECT plan_id, task_key, actor, policy_version, binding_json, revoked_at "
                    "FROM workflow_approvals WHERE approval_id=?", (approval_id,),
                ).fetchone()
                if existing:
                    if (
                        existing["plan_id"] != plan_id
                        or existing["task_key"] != task_key
                        or existing["actor"] != actor
                        or existing["policy_version"] != policy_version
                        or existing["binding_json"] != encoded
                        or existing["revoked_at"] is not None
                    ):
                        raise ValueError("approval id is immutable or has been revoked")
                    c.execute("COMMIT")
                    return False
                c.execute(
                    "INSERT INTO workflow_approvals "
                    "(approval_id, plan_id, task_key, actor, policy_version, binding_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (approval_id, plan_id, task_key, actor, policy_version, encoded, now),
                )
                c.execute(
                    "INSERT INTO workflow_events "
                    "(plan_id, task_ref, event_type, detail_json, at) "
                    "VALUES (?, (SELECT id FROM workflow_tasks WHERE plan_id=? AND task_key=?), "
                    "'approval_granted', ?, ?)",
                    (plan_id, plan_id, task_key,
                     json.dumps({"approval_id": approval_id, "actor": actor}), now),
                )
                c.execute("COMMIT")
                return True
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def revoke_workflow_approval(self, plan_id, approval_id, *, actor):
        """Durably revoke a consent record; revocation is non-reversible."""
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("revoking actor is required")
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                approval = c.execute(
                    "SELECT task_key FROM workflow_approvals WHERE plan_id=? AND approval_id=?",
                    (plan_id, approval_id),
                ).fetchone()
                if approval is None:
                    raise ValueError(f"unknown workflow approval: {approval_id}")
                now = time.time()
                changed = c.execute(
                    "UPDATE workflow_approvals SET revoked_at=? "
                    "WHERE plan_id=? AND approval_id=? AND revoked_at IS NULL",
                    (now, plan_id, approval_id),
                )
                if changed.rowcount:
                    c.execute(
                        "INSERT INTO workflow_events "
                        "(plan_id, task_ref, event_type, detail_json, at) "
                        "VALUES (?, (SELECT id FROM workflow_tasks "
                        "WHERE plan_id=? AND task_key=?), 'approval_revoked', ?, ?)",
                        (plan_id, plan_id, approval["task_key"],
                         json.dumps({"approval_id": approval_id, "actor": actor}), now),
                    )
                c.execute("COMMIT")
                return changed.rowcount > 0
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def list_workflow_approvals(self, plan_id):
        """List consent metadata without exposing bound task inputs."""
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            rows = c.execute(
                "SELECT approval_id, task_key, actor, policy_version, "
                "created_at, revoked_at, binding_json FROM workflow_approvals "
                "WHERE plan_id=? ORDER BY created_at, approval_id", (plan_id,),
            ).fetchall()
            return [{
                "approval_id": row["approval_id"], "task_key": row["task_key"],
                "actor": row["actor"], "policy_version": row["policy_version"],
                "created_at": row["created_at"], "revoked_at": row["revoked_at"],
                "expires_at": json.loads(row["binding_json"])["expires_at"],
            } for row in rows]
        finally:
            c.close()

    def list_workflow_approval_candidates(self, *, limit=100):
        """Return bounded pending tasks requiring operator consent.

        Candidates include moderate+ impact tasks and lower-impact tasks whose
        permission or exactly bound provider manifest declares a network effect.
        Pending tasks are scanned in stable keyset batches up to a fixed budget.
        Older candidates beyond that budget may wait until earlier rows change.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("approval queue limit must be between 1 and 1000")
        from .capabilities import requires_network_approval

        page_size = _APPROVAL_CANDIDATE_PAGE_SIZE
        scan_budget = _APPROVAL_CANDIDATE_SCAN_BUDGET
        c = self._conn()

        def manifest_has_network_effect(manifest_row) -> bool:
            if manifest_row is None:
                return True
            try:
                manifest = json.loads(manifest_row["manifest_json"])
            except (TypeError, ValueError):
                return True
            if not isinstance(manifest, dict):
                return True
            side_effects = manifest.get("side_effects")
            if not isinstance(side_effects, list):
                return True
            return requires_network_approval((), side_effects)

        def has_network_effect(row) -> bool:
            if row["impact"] in ("moderate", "high", "critical"):
                return True
            try:
                permissions = json.loads(row["permissions_json"])
            except (TypeError, ValueError):
                return True
            if not isinstance(permissions, list) or any(
                not isinstance(item, str) for item in permissions
            ):
                return True
            if requires_network_approval(permissions, ()):
                return True

            try:
                plan = json.loads(row["plan_json"])
            except (TypeError, ValueError):
                return True
            if not isinstance(plan, dict):
                return True
            metadata = plan.get("metadata")
            if not isinstance(metadata, dict):
                return True

            if "provider_bindings" not in metadata:
                bindings = None
            else:
                bindings = metadata["provider_bindings"]
                if not isinstance(bindings, dict):
                    return True

            if bindings is None or row["task_key"] not in bindings:
                # A historical/unpinned task may still run through the one
                # trusted provider. Inspect every persisted provider manifest
                # for this capability rather than silently treating it as local.
                manifest_rows = c.execute(
                    "SELECT manifest_json FROM capability_manifests "
                    "WHERE capability_id=?",
                    (row["capability_id"],),
                ).fetchall()
                if not manifest_rows:
                    return True
                return any(manifest_has_network_effect(item) for item in manifest_rows)

            binding = bindings[row["task_key"]]
            if not isinstance(binding, dict):
                return True
            provider_id = binding.get("provider_id")
            fingerprint = binding.get("manifest_fingerprint")
            if (
                not isinstance(provider_id, str) or not provider_id
                or not isinstance(fingerprint, str) or not fingerprint
            ):
                return True
            manifest_row = c.execute(
                "SELECT manifest_json FROM capability_manifests "
                "WHERE capability_id=? AND provider_id=? AND fingerprint=?",
                (row["capability_id"], provider_id, fingerprint),
            ).fetchone()
            return manifest_has_network_effect(manifest_row)

        try:
            candidates = []
            cursor = None
            scanned = 0
            while len(candidates) < limit and scanned < scan_budget:
                cursor_clause = ""
                parameters = []
                if cursor is not None:
                    created_at, plan_id, task_key = cursor
                    cursor_clause = (
                        "AND (t.created_at < ? OR "
                        "(t.created_at = ? AND (t.plan_id > ? OR "
                        "(t.plan_id = ? AND t.task_key > ?)))) "
                    )
                    parameters.extend((
                        created_at, created_at, plan_id, plan_id, task_key,
                    ))
                page_limit = min(page_size, scan_budget - scanned)
                parameters.append(page_limit)
                rows = c.execute(
                    "SELECT t.plan_id, t.task_key, t.capability_id, t.target, t.impact, "
                    "t.permissions_json, t.status AS task_status, p.status AS plan_status, "
                    "p.digest, p.plan_json, m.id AS mission_id, m.objective, t.created_at "
                    "FROM workflow_tasks t "
                    "JOIN workflow_plans p ON p.id=t.plan_id "
                    "JOIN missions m ON m.id=p.mission_id "
                    "WHERE t.status IN ('pending','blocked') "
                    "AND p.status!='cancel_requested' "
                    f"{cursor_clause}"
                    "ORDER BY t.created_at DESC, t.plan_id, t.task_key LIMIT ?",
                    tuple(parameters),
                ).fetchall()
                if not rows:
                    break
                scanned += len(rows)
                for row in rows:
                    cursor = (row["created_at"], row["plan_id"], row["task_key"])
                    if not has_network_effect(row):
                        continue
                    candidate = dict(row)
                    candidate.pop("permissions_json", None)
                    candidate.pop("plan_json", None)
                    candidate.pop("created_at", None)
                    candidates.append(candidate)
                    if len(candidates) >= limit:
                        break
                if len(rows) < page_limit:
                    break
            return candidates
        finally:
            c.close()

    def has_valid_workflow_approval(self, plan_id, task_key, *, policy_version="policy.v1"):
        """Validate unrevoked, unexpired consent against current canonical plan."""
        from .workflow import ApprovalBinding, WorkflowPlan

        c = self._conn()
        try:
            row = c.execute(
                "SELECT digest, plan_json, status FROM workflow_plans WHERE id=?", (plan_id,),
            ).fetchone()
            if row is None or row["status"] == "cancel_requested":
                return False
            plan = WorkflowPlan.from_dict(json.loads(row["plan_json"]))
            task = next((task for task in plan.tasks if task.id == task_key), None)
            if task is None:
                return False
            approvals = c.execute(
                "SELECT binding_json FROM workflow_approvals "
                "WHERE plan_id=? AND task_key=? AND policy_version=? AND revoked_at IS NULL",
                (plan_id, task_key, policy_version),
            ).fetchall()
            for approval in approvals:
                value = json.loads(approval["binding_json"])
                value["permissions"] = tuple(value.get("permissions") or ())
                binding = ApprovalBinding(**value)
                if binding.is_valid(
                    plan_digest=row["digest"], task=task,
                    policy_version=policy_version, now=time.time(),
                ):
                    return True
            return False
        finally:
            c.close()

    def set_mission_rate_limit(self, mission_id, *, min_spacing_s):
        """Enforce durable spacing across every plan sharing a mission."""
        import math

        if (
            isinstance(min_spacing_s, bool)
            or not isinstance(min_spacing_s, (int, float))
            or not math.isfinite(min_spacing_s)
            or min_spacing_s <= 0
        ):
            raise ValueError("mission min_spacing_s must be finite and positive")
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if c.execute("SELECT 1 FROM missions WHERE id=?", (mission_id,)).fetchone() is None:
                    raise ValueError(f"unknown mission: {mission_id}")
                old = c.execute(
                    "SELECT min_spacing_s FROM mission_rate_limits WHERE mission_id=?",
                    (mission_id,),
                ).fetchone()
                if old is not None and min_spacing_s < old["min_spacing_s"]:
                    raise ValueError("mission rate limit cannot be relaxed")
                if old is None or min_spacing_s != old["min_spacing_s"]:
                    c.execute(
                        "INSERT INTO mission_rate_limits (mission_id, min_spacing_s) "
                        "VALUES (?, ?) ON CONFLICT(mission_id) DO UPDATE SET "
                        "min_spacing_s=excluded.min_spacing_s",
                        (mission_id, min_spacing_s),
                    )
                    self._audit_mission_execution_change(
                        c, mission_id, "mission_rate_limit_set",
                        {"min_spacing_s": min_spacing_s},
                    )
                c.execute("COMMIT")
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def get_mission_rate_limit(self, mission_id):
        """Expose the effective durable mission rate policy to all interfaces."""
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM missions WHERE id=?", (mission_id,)).fetchone() is None:
                raise ValueError(f"unknown mission: {mission_id}")
            row = c.execute(
                "SELECT min_spacing_s, last_claimed_at FROM mission_rate_limits "
                "WHERE mission_id=?", (mission_id,),
            ).fetchone()
            return {
                "mission_id": mission_id,
                "min_spacing_s": row["min_spacing_s"] if row else None,
                "last_claimed_at": row["last_claimed_at"] if row else None,
                "enforced": row is not None,
            }
        finally:
            c.close()

    def set_workflow_rate_limit(self, plan_id, *, min_spacing_s):
        """Persist the minimum spacing between claims, without loosening bounds."""
        import math

        if (
            isinstance(min_spacing_s, bool) or not isinstance(min_spacing_s, (int, float))
            or not math.isfinite(min_spacing_s) or min_spacing_s <= 0
        ):
            raise ValueError("min_spacing_s must be finite and positive")
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                    raise ValueError(f"unknown workflow plan: {plan_id}")
                old = c.execute(
                    "SELECT min_spacing_s FROM workflow_rate_limits WHERE plan_id=?", (plan_id,),
                ).fetchone()
                if old is not None and min_spacing_s < old["min_spacing_s"]:
                    raise ValueError("workflow rate limit cannot be relaxed")
                if old is None or old["min_spacing_s"] != min_spacing_s:
                    c.execute(
                        "INSERT INTO workflow_rate_limits (plan_id, min_spacing_s) VALUES (?, ?) "
                        "ON CONFLICT(plan_id) DO UPDATE SET min_spacing_s=excluded.min_spacing_s",
                        (plan_id, min_spacing_s),
                    )
                    c.execute(
                        "INSERT INTO workflow_events "
                        "(plan_id, event_type, detail_json, at) VALUES (?, 'rate_limit_set', ?, ?)",
                        (plan_id, json.dumps({"min_spacing_s": min_spacing_s}), now),
                    )
                c.execute("COMMIT")
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def set_workflow_deadline(self, plan_id, *, deadline_at):
        """Set a persistent absolute cutoff for new dispatch claims; only tighten."""
        import math

        if (
            isinstance(deadline_at, bool)
            or not isinstance(deadline_at, (int, float))
            or not math.isfinite(deadline_at) or deadline_at <= 0
        ):
            raise ValueError("deadline_at must be a finite positive unix timestamp")
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                    raise ValueError(f"unknown workflow plan: {plan_id}")
                old = c.execute(
                    "SELECT deadline_at FROM workflow_deadlines WHERE plan_id=?", (plan_id,),
                ).fetchone()
                if old is not None and deadline_at > old["deadline_at"]:
                    raise ValueError("workflow deadline cannot be extended")
                if old is None or deadline_at != old["deadline_at"]:
                    c.execute(
                        "INSERT INTO workflow_deadlines (plan_id, deadline_at) VALUES (?, ?) "
                        "ON CONFLICT(plan_id) DO UPDATE SET deadline_at=excluded.deadline_at",
                        (plan_id, deadline_at),
                    )
                    c.execute(
                        "INSERT INTO workflow_events "
                        "(plan_id, event_type, detail_json, at) VALUES (?, 'deadline_set', ?, ?)",
                        (plan_id, json.dumps({"deadline_at": deadline_at}), time.time()),
                    )
                c.execute("COMMIT")
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def get_workflow_deadline(self, plan_id):
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            row = c.execute(
                "SELECT deadline_at FROM workflow_deadlines WHERE plan_id=?", (plan_id,),
            ).fetchone()
            return row["deadline_at"] if row else None
        finally:
            c.close()

    def set_workflow_limits(self, plan_id, *, max_total_attempts, max_concurrency):
        """Set conservative backend-enforced limits; never relax active limits."""
        if (
            isinstance(max_total_attempts, bool) or not isinstance(max_total_attempts, int)
            or isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int)
            or max_total_attempts < 1 or max_concurrency < 1
        ):
            raise ValueError("workflow limits must be positive integers")
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                    raise ValueError(f"unknown workflow plan: {plan_id}")
                old = c.execute(
                    "SELECT max_total_attempts, max_concurrency FROM workflow_limits "
                    "WHERE plan_id=?", (plan_id,),
                ).fetchone()
                if old is not None and (
                    max_total_attempts > old["max_total_attempts"]
                    or max_concurrency > old["max_concurrency"]
                ):
                    raise ValueError("workflow limits cannot be relaxed after configuration")
                c.execute(
                    "INSERT INTO workflow_limits "
                    "(plan_id, max_total_attempts, max_concurrency) VALUES (?, ?, ?) "
                    "ON CONFLICT(plan_id) DO UPDATE SET "
                    "max_total_attempts=excluded.max_total_attempts, "
                    "max_concurrency=excluded.max_concurrency",
                    (plan_id, max_total_attempts, max_concurrency),
                )
                if old is None or (
                    max_total_attempts != old["max_total_attempts"]
                    or max_concurrency != old["max_concurrency"]
                ):
                    c.execute(
                        "INSERT INTO workflow_events "
                        "(plan_id, event_type, detail_json, at) "
                        "VALUES (?, 'limits_configured', ?, ?)",
                        (plan_id, json.dumps({
                            "max_total_attempts": max_total_attempts,
                            "max_concurrency": max_concurrency,
                        }), time.time()),
                    )
                c.execute("COMMIT")
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def get_workflow_plan(self, plan_id):
        c = self._conn()
        try:
            row = c.execute("SELECT * FROM workflow_plans WHERE id=?", (plan_id,)).fetchone()
            if row is None:
                return None
            value = dict(row)
            value["plan"] = json.loads(value.pop("plan_json"))
            return value
        finally:
            c.close()

    def verify_workflow_plan_integrity(self, plan_id):
        """Verify the immutable DAG snapshot against persisted executable rows.

        The execution paths use the same check in their write transaction.
        """
        c = self._conn()
        try:
            return self._verify_workflow_plan_integrity_tx(c, plan_id)
        finally:
            c.close()

    def _verify_workflow_plan_integrity_tx(self, c, plan_id):
        import uuid

        from .workflow import WorkflowPlan

        row = c.execute(
            "SELECT mission_id, schema_version, digest, plan_json FROM workflow_plans "
            "WHERE id=?", (plan_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown workflow plan: {plan_id}")
        try:
            plan = WorkflowPlan.from_dict(json.loads(row["plan_json"]))
            if (
                plan.digest != row["digest"]
                or plan.mission_id != row["mission_id"]
                or plan.schema_version != row["schema_version"]
            ):
                raise ValueError("immutable plan header mismatch")
            expected_refs = {
                task.id: uuid.uuid5(uuid.NAMESPACE_URL, f"whaxon:{plan_id}:{task.id}").hex
                for task in plan.tasks
            }
            rows = c.execute(
                "SELECT id, task_key, capability_id, target, inputs_json, depends_on_json, "
                "permissions_json, impact, timeout_s, idempotency_key "
                "FROM workflow_tasks WHERE plan_id=?", (plan_id,),
            ).fetchall()
            if len(rows) != len(plan.tasks):
                raise ValueError("plan task count mismatch")
            actual = {task["task_key"]: task for task in rows}
            if len(actual) != len(rows) or set(actual) != set(expected_refs):
                raise ValueError("plan task references mismatch")
            for task in plan.tasks:
                stored = actual[task.id]
                if (
                    stored["id"] != expected_refs[task.id]
                    or stored["capability_id"] != task.capability_id
                    or stored["target"] != task.target
                    or json.loads(stored["inputs_json"]) != json.loads(
                        json.dumps(task.inputs)
                    )
                    or json.loads(stored["depends_on_json"]) != [
                        expected_refs[dependency] for dependency in task.depends_on
                    ]
                    or json.loads(stored["permissions_json"]) != list(task.permissions)
                    or stored["impact"] != task.impact
                    or stored["timeout_s"] != task.timeout_s
                    or stored["idempotency_key"] != task.idempotency_key
                ):
                    raise ValueError(f"immutable task mismatch: {task.id}")
        except (ValueError, KeyError, TypeError, OverflowError) as exc:
            raise ValueError(f"workflow integrity verification failed: {exc}") from exc
        return {"plan_id": plan_id, "valid": True, "digest": row["digest"],
                "task_count": len(plan.tasks)}

    def list_workflow_tasks(self, plan_id):
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT id AS task_ref, task_key AS id, plan_id, capability_id, target, "
                "inputs_json, depends_on_json, permissions_json, impact, timeout_s, "
                "idempotency_key, status, result_json, error, active_attempt_id, "
                "created_at, updated_at FROM workflow_tasks WHERE plan_id=? ORDER BY rowid",
                (plan_id,),
            ).fetchall()
            task_keys = {
                row["task_ref"]: row["id"] for row in rows
            }
            result = []
            for row in rows:
                value = dict(row)
                for column, key in (
                    ("inputs_json", "inputs"), ("depends_on_json", "depends_on"),
                    ("permissions_json", "permissions"), ("result_json", "result"),
                ):
                    raw = value.pop(column)
                    value[key] = json.loads(raw) if raw else (None if key == "result" else [])
                if key == "result":
                    value["depends_on"] = [
                        task_keys.get(task_ref, task_ref)
                        for task_ref in value["depends_on"]
                    ]
                result.append(value)
            return result
        finally:
            c.close()

    def workflow_attempt_owned(self, attempt_id):
        """Read ownership fencing state before invoking any provider."""
        c = self._conn()
        try:
            row = c.execute(
                "SELECT 1 FROM task_attempts a "
                "JOIN workflow_tasks t ON t.id=a.task_id "
                "WHERE a.id=? AND a.status='running' "
                "AND t.status='running' AND t.active_attempt_id=a.id",
                (attempt_id,),
            ).fetchone()
            return row is not None
        finally:
            c.close()

    def heartbeat_workflow_attempt(self, attempt_id):
        """Renew a running workflow-attempt lease; false means ownership was lost."""
        with self._lock:
            c = self._conn()
            try:
                cur = c.execute(
                    "UPDATE task_attempts SET heartbeat_at=? "
                    "WHERE id=? AND status='running' AND EXISTS ("
                    "SELECT 1 FROM workflow_tasks t WHERE t.id=task_attempts.task_id "
                    "AND t.status='running' AND t.active_attempt_id=task_attempts.id)",
                    (time.time(), attempt_id),
                )
                return cur.rowcount == 1
            finally:
                c.close()

    def reconcile_workflow_attempts(self, stale_after_s=None):
        """Mark orphaned attempts uncertain; optionally preserve fresh worker leases."""
        now = time.time()
        if stale_after_s is not None:
            if isinstance(stale_after_s, bool):
                raise ValueError("stale_after_s must be finite and positive")
            try:
                stale_after_s = float(stale_after_s)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError("stale_after_s must be finite and positive") from exc
            if not math.isfinite(stale_after_s) or stale_after_s <= 0:
                raise ValueError("stale_after_s must be finite and positive")
            stale_before = now - stale_after_s
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if stale_after_s is None:
                    rows = c.execute(
                        "SELECT id, task_id FROM task_attempts "
                        "WHERE status='running' ORDER BY started_at, id"
                    ).fetchall()
                else:
                    rows = c.execute(
                        "SELECT id, task_id FROM task_attempts "
                        "WHERE status='running' "
                        "AND COALESCE(heartbeat_at, started_at) < ? "
                        "ORDER BY started_at, id",
                        (stale_before,),
                    ).fetchall()
                for row in rows:
                    error = "worker stopped before recording an outcome; reconcile before retry"
                    c.execute(
                        "UPDATE task_attempts SET status='uncertain', finished_at=?, error=? "
                        "WHERE id=? AND status='running'",
                        (now, error, row["id"]),
                    )
                    c.execute(
                        "UPDATE workflow_tasks SET status='uncertain', error=?, "
                        "active_attempt_id=NULL, updated_at=? "
                        "WHERE id=? AND status='running' "
                        "AND (active_attempt_id=? OR active_attempt_id IS NULL)",
                        (error, now, row["task_id"], row["id"]),
                    )
                    plan_row = c.execute(
                        "SELECT plan_id FROM workflow_tasks WHERE id=?", (row["task_id"],)
                    ).fetchone()
                    c.execute(
                        "INSERT INTO workflow_events "
                        "(plan_id, task_ref, attempt_id, event_type, detail_json, at) "
                        "VALUES (?, ?, ?, 'task_uncertain', ?, ?)",
                        (plan_row["plan_id"], row["task_id"], row["id"],
                         json.dumps({"reason": "stale_worker_lease"}), now),
                    )
                c.execute("COMMIT")
                return len(rows)
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def get_workflow_event_cursor(self, plan_id, consumer_id):
        """Read a durable consumer checkpoint without consuming any event."""
        if not isinstance(consumer_id, str) or not 1 <= len(consumer_id) <= 128:
            raise ValueError("consumer_id must be a nonempty identifier up to 128 chars")
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            row = c.execute(
                "SELECT last_event_id FROM workflow_event_cursors "
                "WHERE plan_id=? AND consumer_id=?", (plan_id, consumer_id),
            ).fetchone()
            return row["last_event_id"] if row else 0
        finally:
            c.close()

    def acknowledge_workflow_events(self, plan_id, consumer_id, event_id):
        """Monotone, transactionally persisted checkpoint of a real plan event.

        Consumers must process the event first, then explicitly acknowledge.
        This does not guarantee exactly-once external message delivery.
        """
        if not isinstance(consumer_id, str) or not 1 <= len(consumer_id) <= 128:
            raise ValueError("consumer_id must be a nonempty identifier up to 128 chars")
        if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
            raise ValueError("event_id must be a positive integer")
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                    raise ValueError(f"unknown workflow plan: {plan_id}")
                if c.execute(
                    "SELECT 1 FROM workflow_events WHERE plan_id=? AND id=?",
                    (plan_id, event_id),
                ).fetchone() is None:
                    raise ValueError("event does not exist in this workflow")
                old = c.execute(
                    "SELECT last_event_id FROM workflow_event_cursors "
                    "WHERE plan_id=? AND consumer_id=?", (plan_id, consumer_id),
                ).fetchone()
                if old is not None and event_id < old["last_event_id"]:
                    raise ValueError("workflow event cursor cannot move backwards")
                c.execute(
                    "INSERT INTO workflow_event_cursors "
                    "(plan_id, consumer_id, last_event_id, updated_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(plan_id, consumer_id) DO UPDATE SET "
                    "last_event_id=excluded.last_event_id, updated_at=excluded.updated_at",
                    (plan_id, consumer_id, event_id, time.time()),
                )
                c.execute("COMMIT")
                return event_id
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def list_unacknowledged_workflow_events(self, plan_id, consumer_id, limit=100):
        """Deliver durable event pages starting at the consumer's last checkpoint."""
        after_id = self.get_workflow_event_cursor(plan_id, consumer_id)
        return self.list_workflow_events(plan_id, after_id=after_id, limit=limit)

    def list_workflow_events(self, plan_id, after_id=0, limit=100):
        """Bounded, ordered, persisted Engine V2 lifecycle event feed."""
        if isinstance(after_id, bool) or not isinstance(after_id, int) or after_id < 0:
            raise ValueError("after_id must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            rows = c.execute(
                "SELECT * FROM workflow_events WHERE plan_id=? AND id>? ORDER BY id LIMIT ?",
                (plan_id, after_id, limit),
            ).fetchall()
            return [{**dict(row), "detail": json.loads(row["detail_json"])} for row in rows]
        finally:
            c.close()

    def count_workflow_task_attempts(self, plan_id):
        """Unpaginated database aggregation for scheduler correctness."""
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            rows = c.execute(
                "SELECT t.task_key, COUNT(*) AS n "
                "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                "WHERE t.plan_id=? GROUP BY t.task_key",
                (plan_id,),
            ).fetchall()
            return {row["task_key"]: row["n"] for row in rows}
        finally:
            c.close()

    def list_workflow_attempts(self, plan_id, *, after_started=0.0, limit=100):
        """Inspect persisted attempts across restarts without exposing inputs or secrets."""
        import math

        if isinstance(after_started, bool) or not isinstance(after_started, (float, int)):
            raise ValueError("after_started must be a finite nonnegative number")
        if not math.isfinite(after_started) or after_started < 0:
            raise ValueError("after_started must be a finite nonnegative number")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            rows = c.execute(
                "SELECT a.id, t.task_key, a.attempt_no, a.status, a.worker_id, "
                "a.started_at, a.heartbeat_at, a.finished_at, a.error "
                "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                "WHERE t.plan_id=? AND a.started_at>? "
                "ORDER BY a.started_at, a.id LIMIT ?",
                (plan_id, after_started, limit),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            c.close()

    def list_missions(self, *, limit=100, after_created=0.0):
        """Stable bounded mission discovery for headless clients."""
        import math

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        if (
            isinstance(after_created, bool)
            or not isinstance(after_created, (int, float))
            or not math.isfinite(after_created) or after_created < 0
        ):
            raise ValueError("after_created must be finite and nonnegative")
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT id, objective, status, created_at, updated_at "
                "FROM missions WHERE created_at>? ORDER BY created_at, id LIMIT ?",
                (after_created, limit),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            c.close()

    def list_workflow_mission_plans(self, mission_id):
        """List immutable plans and durable status for one existing mission."""
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM missions WHERE id=?", (mission_id,)).fetchone() is None:
                raise ValueError(f"unknown mission: {mission_id}")
            rows = c.execute(
                "SELECT id, digest, schema_version, status, created_at "
                "FROM workflow_plans WHERE mission_id=? ORDER BY created_at, id",
                (mission_id,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            c.close()

    def _close_reconciled_workflow_requests_tx(self, c, plan_id, *, now=None):
        """Close resolved run intents inside the caller's SQLite transaction."""
        at = time.time() if now is None else now
        if c.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='workflow_run_requests'",
        ).fetchone() is None:
            return 0
        plan = c.execute(
            "SELECT digest FROM workflow_plans WHERE id=?", (plan_id,),
        ).fetchone()
        if plan is None:
            raise ValueError(f"unknown workflow plan: {plan_id}")
        unresolved = c.execute(
            "SELECT COUNT(*) FROM task_attempts a "
            "JOIN workflow_tasks t ON t.id=a.task_id "
            "LEFT JOIN workflow_attempt_reconciliations r ON r.attempt_id=a.id "
            "WHERE t.plan_id=? AND (a.status='running' OR "
            "(a.status='uncertain' AND "
            "(r.attempt_id IS NULL OR r.disposition='unresolved')))",
            (plan_id,),
        ).fetchone()[0]
        if unresolved:
            return 0
        pending = c.execute(
            "SELECT id FROM workflow_run_requests "
            "WHERE plan_id=? AND plan_digest=? AND status='uncertain' "
            "ORDER BY submitted_at, id",
            (plan_id, plan["digest"]),
        ).fetchall()
        closed = 0
        for row in pending:
            cursor = c.execute(
                "UPDATE workflow_run_requests SET status='incomplete',"
                "completed_at=?,owner=NULL,lease_token=NULL,"
                "error='operator reconciliation recorded; no automatic replay' "
                "WHERE id=? AND status='uncertain'",
                (at, row["id"]),
            )
            if cursor.rowcount != 1:
                continue
            c.execute(
                "INSERT INTO workflow_events "
                "(plan_id,event_type,detail_json,at) VALUES (?,?,?,?)",
                (plan_id, "workflow_run_reconciled", json.dumps({
                    "request_id": row["id"],
                    "from_status": "uncertain",
                    "to_status": "incomplete",
                    "reason": "provider_effect_reconciled",
                    "automatic_replay": False,
                }, sort_keys=True), at),
            )
            closed += 1
        return closed

    def record_workflow_attempt_reconciliation(
        self, plan_id, attempt_id, *, disposition, actor, evidence_ref, note,
    ):
        """Record an operator-reported outcome and reference; never replay.

        The reference is not independently verified. Actor is a caller-supplied
        label, not an authenticated-principal claim.
        no_effect_verified makes the task retryable only after a separate run
        request; effect_observed blocks it because observation is not a WHAXON
        verification result. unresolved leaves the task uncertain.
        """
        choices = {"no_effect_verified", "effect_observed", "unresolved"}
        if disposition not in choices:
            raise ValueError("unsupported reconciliation disposition")
        values = {"actor": actor, "evidence_ref": evidence_ref, "note": note}
        limits = {"actor": 128, "evidence_ref": 2048, "note": 4000}
        for key, value in values.items():
            if (not isinstance(value, str) or value != value.strip()
                    or not value or len(value) > limits[key]
                    or any(ord(char) < 32 and char not in "\\n\\t" for char in value)):
                raise ValueError(f"{key} must be normalized non-empty text within its limit")
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                self._verify_workflow_plan_integrity_tx(c, plan_id)
                attempt = c.execute(
                    "SELECT a.id, a.status AS attempt_status, t.id AS task_ref, "
                    "t.status AS task_status, t.task_key FROM task_attempts a "
                    "JOIN workflow_tasks t ON t.id=a.task_id "
                    "WHERE t.plan_id=? AND a.id=?",
                    (plan_id, attempt_id),
                ).fetchone()
                if attempt is None:
                    raise ValueError("unknown workflow attempt for this plan")
                existing = c.execute(
                    "SELECT disposition, actor, evidence_ref, note, recorded_at "
                    "FROM workflow_attempt_reconciliations WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["disposition"] == disposition
                        and existing["actor"] == actor
                        and existing["evidence_ref"] == evidence_ref
                        and existing["note"] == note
                    ):
                        run_requests_closed = (
                            self._close_reconciled_workflow_requests_tx(
                                c, plan_id,
                            )
                        )
                        c.execute("COMMIT")
                        return {
                            "plan_id": plan_id, "attempt_id": attempt_id,
                            "disposition": disposition, "actor_claimed": actor,
                            "evidence_ref": evidence_ref, "note": note,
                            "recorded_at": existing["recorded_at"],
                            "task_status": attempt["task_status"],
                            "task_retryable": disposition == "no_effect_verified",
                            "automatic_replay": False, "idempotent": True,
                            "run_requests_closed": run_requests_closed,
                        }
                    raise ValueError("workflow attempt already has a different reconciliation")
                if attempt["attempt_status"] != "uncertain" or attempt["task_status"] != "uncertain":
                    raise ValueError("only uncertain workflow attempts can be reconciled")
                if disposition == "no_effect_verified":
                    task_status = "failed"
                    task_error = (
                        "operator recorded no external effect; retry requires a separate run request"
                    )
                elif disposition == "effect_observed":
                    task_status = "blocked"
                    task_error = (
                        "external effect observed; WHAXON outcome remains unverified"
                    )
                else:
                    task_status = "uncertain"
                    task_error = "external effect remains unresolved"
                c.execute(
                    "INSERT INTO workflow_attempt_reconciliations "
                    "(attempt_id,plan_id,disposition,actor,evidence_ref,note,recorded_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (attempt_id, plan_id, disposition, actor, evidence_ref, note, now),
                )
                if disposition != "unresolved":
                    cursor = c.execute(
                        "UPDATE workflow_tasks SET status=?,error=?,active_attempt_id=NULL,"
                        "updated_at=? WHERE id=? AND status='uncertain'",
                        (task_status, task_error, now, attempt["task_ref"]),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("workflow task changed during reconciliation")
                c.execute(
                    "INSERT INTO workflow_events "
                    "(plan_id,task_ref,attempt_id,event_type,detail_json,at) "
                    "VALUES (?,?,?,'workflow_attempt_reconciled',?,?)",
                    (plan_id, attempt["task_ref"], attempt_id,
                     json.dumps({
                         "disposition": disposition, "actor_claimed": actor,
                         "evidence_ref": evidence_ref, "note": note,
                     }, sort_keys=True), now),
                )
                run_requests_closed = self._close_reconciled_workflow_requests_tx(
                    c, plan_id, now=now,
                )
                c.execute("COMMIT")
                return {
                    "plan_id": plan_id, "attempt_id": attempt_id,
                    "disposition": disposition, "actor_claimed": actor,
                    "evidence_ref": evidence_ref, "note": note,
                    "recorded_at": now, "task_status": task_status,
                    "task_retryable": disposition == "no_effect_verified",
                    "automatic_replay": False, "idempotent": False,
                    "run_requests_closed": run_requests_closed,
                }
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def get_workflow_dispatch_reconciliation(self, plan_id):
        """Separate uncertain attempts and expose any operator resolution record."""
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            rows = c.execute(
                "SELECT a.id AS attempt_id, t.task_key, a.status, "
                "EXISTS(SELECT 1 FROM workflow_events e "
                "WHERE e.plan_id=t.plan_id AND e.attempt_id=a.id "
                "AND e.event_type='dispatch_started') AS dispatch_recorded, "
                "r.disposition, r.actor, r.evidence_ref, r.note, r.recorded_at "
                "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                "LEFT JOIN workflow_attempt_reconciliations r ON r.attempt_id=a.id "
                "WHERE t.plan_id=? AND a.status IN ('running', 'uncertain') "
                "ORDER BY a.started_at, a.id", (plan_id,),
            ).fetchall()
            return [
                {
                    "attempt_id": row["attempt_id"],
                    "task_key": row["task_key"], "status": row["status"],
                    "external_effect_possible": bool(row["dispatch_recorded"]),
                    "operator_resolution": (
                        {
                            "disposition": row["disposition"],
                            "actor_claimed": row["actor"],
                            "evidence_ref": row["evidence_ref"],
                            "note": row["note"],
                            "recorded_at": row["recorded_at"],
                        } if row["disposition"] else None
                    ),
                    "manual_reconciliation_required": (
                        (
                            row["status"] == "running"
                            and bool(row["dispatch_recorded"])
                        )
                        or (
                            row["status"] == "uncertain"
                            and row["disposition"] in (None, "unresolved")
                        )
                    ),
                }
                for row in rows
            ]
        finally:
            c.close()

    def get_workflow_audit_snapshot(self, plan_id):
        """Digest a consistent lifecycle snapshot for *external* anchoring.

        This read-only SHA-256 digest is NOT an immutable audit log or an
        independent trust anchor. An operator must preserve the returned
        digest outside the database and independently verify later snapshots.
        Values and raw event details are hashed, not returned to the caller.
        """
        version = "whaxon.workflow-audit-snapshot.v1"
        digest = hashlib.sha256()
        digest.update((version + "\n").encode("utf-8"))

        def record(kind, values):
            payload = json.dumps(
                [kind, list(values)], sort_keys=True,
                ensure_ascii=True, allow_nan=False, separators=(",", ":"),
            )
            digest.update(payload.encode("utf-8") + b"\n")

        c = self._conn()
        try:
            c.execute("BEGIN")
            plan = c.execute(
                "SELECT id, mission_id, digest, status, schema_version, plan_json "
                "FROM workflow_plans WHERE id=?", (plan_id,),
            ).fetchone()
            if plan is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            record("plan", tuple(plan))
            counts = {}
            streams = (
                ("tasks", "SELECT id, task_key, capability_id, target, "
                 "inputs_json, depends_on_json, permissions_json, impact, "
                 "timeout_s, idempotency_key, status, active_attempt_id, "
                 "error, result_json FROM workflow_tasks "
                 "WHERE plan_id=? ORDER BY id"),
                ("attempts", "SELECT a.id, a.task_id, a.attempt_no, a.status, "
                 "a.worker_id, a.idempotency_key, a.started_at, "
                 "a.heartbeat_at, a.finished_at, a.result_json, a.error "
                 "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                 "WHERE t.plan_id=? ORDER BY a.id"),
                ("events", "SELECT id, task_ref, attempt_id, event_type, "
                 "detail_json, at FROM workflow_events WHERE plan_id=? "
                 "ORDER BY id"),
            )
            for name, query in streams:
                cursor = c.execute(query, (plan_id,))
                count = 0
                for row in cursor:
                    record(name, tuple(row))
                    count += 1
                counts[name] = count
            return {
                "schema_version": version,
                "plan_id": plan_id,
                "plan_digest": plan["digest"],
                "algorithm": "sha256",
                "digest": digest.hexdigest(),
                "event_count": counts["events"],
                "task_count": counts["tasks"],
                "attempt_count": counts["attempts"],
                "independent_anchor_verified": False,
            }
        finally:
            c.close()

    def verify_workflow_audit_snapshot(self, plan_id, expected_digest):
        """Compare lifecycle state with a caller-held external snapshot digest."""
        if (
            not isinstance(expected_digest, str)
            or len(expected_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_digest)
        ):
            raise ValueError("expected_digest must be 64 lowercase hex characters")
        actual = self.get_workflow_audit_snapshot(plan_id)["digest"]
        return hmac.compare_digest(actual, expected_digest)

    def get_workflow_audit_integrity(self, plan_id):
        """Check that every persisted attempt has exactly one claim event.

        This is an internal consistency check, not a cryptographic trust anchor.
        """
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            attempts = c.execute(
                "SELECT a.id, a.status FROM task_attempts a "
                "JOIN workflow_tasks t ON t.id=a.task_id WHERE t.plan_id=?",
                (plan_id,),
            ).fetchall()
            reconciliations = c.execute(
                "SELECT r.attempt_id, r.disposition, r.actor, r.evidence_ref, "
                "r.note, a.task_id FROM workflow_attempt_reconciliations r "
                "JOIN task_attempts a ON a.id=r.attempt_id WHERE r.plan_id=?",
                (plan_id,),
            ).fetchall()
            events = c.execute(
                "SELECT attempt_id, task_ref, event_type, detail_json FROM workflow_events "
                "WHERE plan_id=? AND attempt_id IS NOT NULL", (plan_id,),
            ).fetchall()
            has_run_request_queue = c.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='workflow_run_requests'"
            ).fetchone() is not None
            run_requests = []
            run_request_events = []
            if has_run_request_queue:
                run_requests = c.execute(
                    "SELECT id, status, error FROM workflow_run_requests WHERE plan_id=?",
                    (plan_id,),
                ).fetchall()
                run_request_events = c.execute(
                    "SELECT task_ref, attempt_id, detail_json FROM workflow_events WHERE plan_id=? "
                    "AND event_type='workflow_run_reconciled'",
                    (plan_id,),
                ).fetchall()
            run_request_by_id = {row["id"]: row for row in run_requests}
            reconciled_request_ids = {
                row["id"] for row in run_requests
                if row["status"] == "incomplete"
                and row["error"] == "operator reconciliation recorded; no automatic replay"
            }
            run_reconciliation_event_counts = {}
            mismatched_run_reconciliations = set()
            unknown_run_reconciliations = set()
            for event in run_request_events:
                try:
                    detail = json.loads(event["detail_json"])
                except (TypeError, ValueError):
                    detail = None
                request_id = detail.get("request_id") if isinstance(detail, dict) else None
                if not isinstance(request_id, str) or request_id not in run_request_by_id:
                    unknown_run_reconciliations.add(
                        request_id if isinstance(request_id, str) else "<invalid>"
                    )
                    continue
                run_reconciliation_event_counts[request_id] = (
                    run_reconciliation_event_counts.get(request_id, 0) + 1
                )
                expected_detail = {
                    "request_id": request_id,
                    "from_status": "uncertain",
                    "to_status": "incomplete",
                    "reason": "provider_effect_reconciled",
                    "automatic_replay": False,
                }
                request = run_request_by_id[request_id]
                if (
                    detail != expected_detail
                    or request["status"] != "incomplete"
                    or request["error"] != "operator reconciliation recorded; no automatic replay"
                    or event["task_ref"] is not None
                    or event["attempt_id"] is not None
                ):
                    mismatched_run_reconciliations.add(request_id)
            duplicate_run_reconciliations = sorted(
                request_id for request_id, count in run_reconciliation_event_counts.items()
                if count > 1
            )
            missing_or_duplicate_run_reconciliations = sorted(
                request_id for request_id in reconciled_request_ids
                if run_reconciliation_event_counts.get(request_id, 0) != 1
            )
            attempt_by_id = {row["id"]: row["status"] for row in attempts}
            reconciliation_by_id = {
                row["attempt_id"]: row for row in reconciliations
            }
            claims = {}
            terminal = {}
            dispatch = {}
            reconciliation_events = {}
            mismatched = set()
            mismatched_reconciliations = set()
            unknown = set()
            unknown_reconciliations = set()
            for event in events:
                attempt_id = event["attempt_id"]
                kind = event["event_type"]
                if attempt_id not in attempt_by_id:
                    unknown.add(attempt_id)
                    continue
                if kind == "task_claimed":
                    claims[attempt_id] = claims.get(attempt_id, 0) + 1
                if kind == "dispatch_started":
                    dispatch[attempt_id] = dispatch.get(attempt_id, 0) + 1
                if kind == "workflow_attempt_reconciled":
                    reconciliation_events[attempt_id] = (
                        reconciliation_events.get(attempt_id, 0) + 1
                    )
                    expected = reconciliation_by_id.get(attempt_id)
                    if expected is None:
                        unknown_reconciliations.add(attempt_id)
                    else:
                        try:
                            detail = json.loads(event["detail_json"])
                        except (TypeError, ValueError):
                            detail = None
                        expected_detail = {
                            "disposition": expected["disposition"],
                            "actor_claimed": expected["actor"],
                            "evidence_ref": expected["evidence_ref"],
                            "note": expected["note"],
                        }
                        if (
                            detail != expected_detail
                            or event["task_ref"] != expected["task_id"]
                        ):
                            mismatched_reconciliations.add(attempt_id)
                if kind in (
                    "task_succeeded", "task_failed", "task_cancelled",
                    "task_blocked", "task_uncertain",
                ):
                    terminal[attempt_id] = terminal.get(attempt_id, 0) + 1
                    if kind != "task_" + attempt_by_id[attempt_id]:
                        mismatched.add(attempt_id)
            missing_claims = sorted(
                row["id"] for row in attempts if claims.get(row["id"], 0) != 1
            )
            missing_terminal = sorted(
                row["id"] for row in attempts
                if (terminal.get(row["id"], 0) != 1
                    if row["status"] != "running"
                    else terminal.get(row["id"], 0) != 0)
            )
            duplicate_dispatch = sorted(
                attempt_id for attempt_id, count in dispatch.items() if count > 1
            )
            missing_or_duplicate_reconciliations = sorted(
                attempt_id for attempt_id in reconciliation_by_id
                if reconciliation_events.get(attempt_id, 0) != 1
            )
            return {
                "plan_id": plan_id, "attempts": len(attempts),
                "missing_or_duplicate_claims": missing_claims,
                "missing_or_duplicate_terminal_events": missing_terminal,
                "mismatched_terminal_events": sorted(mismatched),
                "duplicate_dispatch_events": duplicate_dispatch,
                "unknown_attempt_events": sorted(unknown),
                "missing_or_duplicate_reconciliation_events":
                    missing_or_duplicate_reconciliations,
                "mismatched_reconciliation_events":
                    sorted(mismatched_reconciliations),
                "unknown_reconciliation_events":
                    sorted(unknown_reconciliations),
                "duplicate_run_request_reconciliation_events":
                    duplicate_run_reconciliations,
                "missing_or_duplicate_run_request_reconciliation_events":
                    missing_or_duplicate_run_reconciliations,
                "mismatched_run_request_reconciliation_events":
                    sorted(mismatched_run_reconciliations),
                "unknown_run_request_reconciliation_events":
                    sorted(unknown_run_reconciliations),
                "consistent": not (
                    missing_claims or missing_terminal or mismatched
                    or duplicate_dispatch or unknown
                    or missing_or_duplicate_reconciliations
                    or mismatched_reconciliations
                    or unknown_reconciliations
                    or duplicate_run_reconciliations
                    or missing_or_duplicate_run_reconciliations
                    or mismatched_run_reconciliations
                    or unknown_run_reconciliations
                ),
            }
        finally:
            c.close()

    def get_workflow_readiness(self, plan_id):
        """Fail-safe operational summary of outstanding reconciliation and controls."""
        snapshot = self.get_workflow_progress(plan_id)
        reconciliation = self.get_workflow_dispatch_reconciliation(plan_id)
        audit = self.get_workflow_audit_integrity(plan_id)
        deadline = self.get_workflow_deadline(plan_id)
        blockers = []
        if not audit["consistent"]:
            blockers.append("workflow_audit_inconsistent")
        if snapshot["counts"].get("uncertain", 0):
            blockers.append("uncertain_task_outcomes")
        if any(item["manual_reconciliation_required"] for item in reconciliation):
            blockers.append("external_effect_reconciliation_required")
        if snapshot["cancellation_requested"]:
            blockers.append("cancellation_requested")
        if deadline is not None and time.time() >= deadline and not snapshot["complete"]:
            blockers.append("workflow_deadline_exceeded")
        if snapshot["attempt_budget_exhausted"] and not snapshot["complete"]:
            blockers.append("attempt_budget_exhausted")
        return {
            "plan_id": plan_id,
            "complete": snapshot["complete"],
            "all_succeeded": snapshot["complete"] and snapshot["total_tasks"] == (
                snapshot["counts"].get("succeeded", 0)
            ),
            "audit_consistent": audit["consistent"],
            "requires_manual_reconciliation": any(
                item["manual_reconciliation_required"] for item in reconciliation
            ),
            "blockers": sorted(set(blockers)),
            "ready_to_report_success": not blockers and snapshot["complete"]
            and snapshot["total_tasks"] == snapshot["counts"].get("succeeded", 0),
        }

    def get_workflow_evidence(self, plan_id, *, limit=100):
        """Link successful workflow attempts to their real persisted tool evidence.

        This is a read-only reporting boundary. Missing, contradictory or
        unfinished tool evidence is surfaced as incomplete, never synthesized.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        c = self._conn()
        try:
            c.execute("BEGIN")
            plan = c.execute(
                "SELECT mission_id, digest FROM workflow_plans WHERE id=?", (plan_id,),
            ).fetchone()
            if plan is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            rows = c.execute(
                "SELECT t.task_key, t.target, t.capability_id, a.id AS attempt_id, "
                "a.attempt_no, a.status, a.result_json, a.error "
                "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                "WHERE t.plan_id=? ORDER BY a.started_at, a.id LIMIT ?",
                (plan_id, limit),
            ).fetchall()
            evidence = []
            for row in rows:
                entry = {
                    "task_key": row["task_key"], "target": row["target"],
                    "capability_id": row["capability_id"],
                    "attempt_id": row["attempt_id"], "attempt_no": row["attempt_no"],
                    "attempt_status": row["status"], "job_id": None,
                    "evidence_status": "unavailable", "integrity_status": "unsealed",
                    "finding_count": 0, "findings": [],
                }
                if row["status"] != "succeeded":
                    entry["evidence_status"] = "not_successful"
                else:
                    try:
                        result = json.loads(row["result_json"] or "null")
                    except (TypeError, json.JSONDecodeError):
                        result = None
                    job_id = result.get("job_id") if isinstance(result, dict) else None
                    if isinstance(job_id, str) and job_id:
                        job = c.execute(
                            "SELECT id, target, status, exit_code FROM jobs WHERE id=?",
                            (job_id,),
                        ).fetchone()
                        entry["job_id"] = job_id
                        if (
                            job is not None and job["target"] == row["target"]
                            and job["status"] == "finished" and job["exit_code"] == 0
                        ):
                            findings = c.execute(
                                "SELECT seq, kind, severity, source, raw_line, "
                                "verification_status, verification_reason "
                                "FROM findings WHERE job_id=? ORDER BY seq", (job_id,),
                            ).fetchall()
                            entry["findings"] = [dict(finding) for finding in findings]
                            entry["finding_count"] = len(findings)
                            entry["evidence_status"] = "recorded"
                            seal = c.execute(
                                "SELECT job_id, digest FROM workflow_evidence_seals "
                                "WHERE attempt_id=?", (row["attempt_id"],),
                            ).fetchone()
                            if seal is not None:
                                current = _workflow_evidence_digest(
                                    c, attempt_id=row["attempt_id"], job_id=job_id,
                                    target=row["target"], capability_id=row["capability_id"],
                                    plan_digest=plan["digest"],
                                )
                                entry["integrity_status"] = (
                                    "verified" if seal["job_id"] == job_id
                                    and current == seal["digest"] else "changed"
                                )
                                if entry["integrity_status"] == "changed":
                                    entry["evidence_status"] = "integrity_mismatch"
                                    entry["findings"] = []
                                    entry["finding_count"] = 0
                        else:
                            entry["evidence_status"] = "job_not_verified"
                evidence.append(entry)
            return {
                "plan_id": plan_id, "mission_id": plan["mission_id"],
                "plan_digest": plan["digest"],
                "attempts": evidence,
                "all_evidence_recorded": bool(evidence) and all(
                    item["evidence_status"] == "recorded" for item in evidence
                ),
                "all_evidence_integrity_verified": bool(evidence) and all(
                    item["integrity_status"] == "verified" for item in evidence
                ),
            }
        finally:
            c.close()

    def has_valid_workflow_evidence_seal(self, job_id):
        """Require source findings to belong to an intact successful V2 attempt."""
        c = self._conn()
        try:
            c.execute("BEGIN")
            rows = c.execute(
                "SELECT s.attempt_id, s.digest, t.target, t.capability_id, p.digest AS plan_digest "
                "FROM workflow_evidence_seals s "
                "JOIN task_attempts a ON a.id=s.attempt_id "
                "JOIN workflow_tasks t ON t.id=a.task_id "
                "JOIN workflow_plans p ON p.id=t.plan_id "
                "WHERE s.job_id=? AND a.status='succeeded'",
                (job_id,),
            ).fetchall()
            return any(
                _workflow_evidence_digest(
                    c, attempt_id=row["attempt_id"], job_id=job_id,
                    target=row["target"], capability_id=row["capability_id"],
                    plan_digest=row["plan_digest"],
                ) == row["digest"]
                for row in rows
            )
        finally:
            c.close()

    def get_workflow_resource_summary(self, plan_id):
        """Durable, evidence-based utilization; no invented CPU or provider costs."""
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            row = c.execute(
                "SELECT COUNT(*) AS attempts, "
                "COALESCE(SUM(CASE WHEN a.status='running' THEN 1 ELSE 0 END), 0) AS active, "
                "COALESCE(SUM(CASE WHEN a.finished_at IS NOT NULL "
                "THEN MAX(0, a.finished_at-a.started_at) ELSE 0 END), 0) AS elapsed_s "
                "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                "WHERE t.plan_id=?", (plan_id,),
            ).fetchone()
            return {
                "plan_id": plan_id, "attempts": row["attempts"],
                "active_attempts": row["active"],
                "completed_attempt_wall_seconds": row["elapsed_s"],
                "cpu_seconds": None, "memory_peak_bytes": None, "cost_usd": None,
                "cost_accounting_available": False,
            }
        finally:
            c.close()

    def get_workflow_progress(self, plan_id):
        """Return a durable, consistent lifecycle snapshot from SQLite.

        A cancellation request does not imply that already dispatched actions
        have stopped. Those attempts remain visible in running or uncertain.
        """
        c = self._conn()
        try:
            c.execute("BEGIN")
            plan = c.execute(
                "SELECT mission_id, status FROM workflow_plans WHERE id=?", (plan_id,)
            ).fetchone()
            if plan is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            rows = c.execute(
                "SELECT status, COUNT(*) AS n FROM workflow_tasks "
                "WHERE plan_id=? GROUP BY status", (plan_id,),
            ).fetchall()
            attempts = c.execute(
                "SELECT COUNT(*) AS n FROM task_attempts a "
                "JOIN workflow_tasks t ON t.id=a.task_id "
                "WHERE t.plan_id=?", (plan_id,),
            ).fetchone()["n"]
            usage = c.execute(
                "SELECT COUNT(*) AS total, "
                "COALESCE(SUM(CASE WHEN a.status='running' THEN 1 ELSE 0 END), 0) AS active "
                "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                "WHERE t.plan_id=?", (plan_id,),
            ).fetchone()
            limits = c.execute(
                "SELECT max_total_attempts, max_concurrency FROM workflow_limits WHERE plan_id=?",
                (plan_id,),
            ).fetchone()
            budget = limits["max_total_attempts"] if limits else 100
            concurrency = limits["max_concurrency"] if limits else 4
            counts = {row["status"]: row["n"] for row in rows}
            total = sum(counts.values())
            # A failed task may still be retryable; without the caller's retry
            # policy persisted here it must never count as verified complete.
            terminal = sum(counts.get(status, 0) for status in (
                "succeeded", "blocked", "cancelled", "uncertain",
            ))
            return {
                "plan_id": plan_id,
                "mission_id": plan["mission_id"],
                "status": plan["status"],
                "cancellation_requested": plan["status"] == "cancel_requested",
                "total_tasks": total,
                "terminal_tasks": terminal,
                "attempts": attempts,
                "active_attempts": usage["active"],
                "remaining_attempt_budget": max(0, budget - usage["total"]),
                "max_total_attempts": budget,
                "max_concurrency": concurrency,
                "attempt_budget_exhausted": usage["total"] >= budget,
                "counts": counts,
                "complete": terminal == total,
            }
        finally:
            c.close()

    def reconcile_workflow_plan(self, plan_id, *, stale_after_s=60.0):
        """Conservatively reconcile only expired attempts belonging to a plan.

        Active leases are not stolen; uncertain external effects are not replayed.
        """
        if not isinstance(stale_after_s, (int, float)) or not 0 < stale_after_s < float("inf"):
            raise ValueError("stale_after_s must be positive and finite")
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                    raise ValueError(f"unknown workflow plan: {plan_id}")
                rows = c.execute(
                    "SELECT a.id, a.task_id FROM task_attempts a "
                    "JOIN workflow_tasks t ON t.id=a.task_id "
                    "WHERE t.plan_id=? AND a.status='running' "
                    "AND COALESCE(a.heartbeat_at,a.started_at) < ?",
                    (plan_id, now - stale_after_s),
                ).fetchall()
                for row in rows:
                    error = "stale worker lease; external outcome uncertain"
                    c.execute(
                        "UPDATE task_attempts SET status='uncertain', finished_at=?, error=? "
                        "WHERE id=? AND status='running'", (now, error, row["id"]),
                    )
                    c.execute(
                        "UPDATE workflow_tasks SET status='uncertain', error=?, "
                        "active_attempt_id=NULL, updated_at=? "
                        "WHERE id=? AND status='running' AND active_attempt_id=?",
                        (error, now, row["task_id"], row["id"]),
                    )
                    c.execute(
                        "INSERT INTO workflow_events "
                        "(plan_id, task_ref, attempt_id, event_type, detail_json, at) "
                        "VALUES (?, ?, ?, 'task_uncertain', ?, ?)",
                        (plan_id, row["task_id"], row["id"],
                         json.dumps({"reason": "expired_lease"}), now),
                    )
                c.execute("COMMIT")
                return len(rows)
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    @staticmethod
    def _audit_mission_execution_change(c, mission_id, event_type, detail):
        """Record mission-wide policy changes in every affected plan's audit feed."""
        now = time.time()
        plans = c.execute(
            "SELECT id FROM workflow_plans WHERE mission_id=?", (mission_id,),
        ).fetchall()
        for plan in plans:
            c.execute(
                "INSERT INTO workflow_events (plan_id, event_type, detail_json, at) "
                "VALUES (?, ?, ?, ?)",
                (plan["id"], event_type, json.dumps(detail, sort_keys=True), now),
            )

    def set_mission_cost_limit(self, mission_id, *, max_cost_microusd):
        """Set a non-relaxable cap on accounted USD micros for future claims."""
        if (
            isinstance(max_cost_microusd, bool) or not isinstance(max_cost_microusd, int)
            or max_cost_microusd < 0
        ):
            raise ValueError("max_cost_microusd must be a nonnegative integer")
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if c.execute("SELECT 1 FROM missions WHERE id=?", (mission_id,)).fetchone() is None:
                    raise ValueError(f"unknown mission: {mission_id}")
                old = c.execute(
                    "SELECT max_cost_microusd FROM mission_cost_limits WHERE mission_id=?",
                    (mission_id,),
                ).fetchone()
                if old is not None and max_cost_microusd > old["max_cost_microusd"]:
                    raise ValueError("mission cost cap cannot be relaxed")
                c.execute(
                    "INSERT INTO mission_cost_limits (mission_id, max_cost_microusd) VALUES (?, ?) "
                    "ON CONFLICT(mission_id) DO UPDATE SET max_cost_microusd=excluded.max_cost_microusd",
                    (mission_id, max_cost_microusd),
                )
                if old is None or old["max_cost_microusd"] != max_cost_microusd:
                    self._audit_mission_execution_change(
                        c, mission_id, "mission_cost_limit_set",
                        {"max_cost_microusd": max_cost_microusd},
                    )
                c.execute("COMMIT")
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def record_workflow_attempt_cost(self, attempt_id, *, cost_microusd, source):
        """Record provider-reported cost once, without guessing or overwriting it."""
        if (
            isinstance(cost_microusd, bool) or not isinstance(cost_microusd, int)
            or cost_microusd < 0
        ):
            raise ValueError("cost_microusd must be a nonnegative integer")
        if not isinstance(source, str) or not source.strip() or len(source.strip()) > 128:
            raise ValueError("source must identify the provider cost evidence")
        source = source.strip()
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT t.plan_id, a.status FROM task_attempts a "
                    "JOIN workflow_tasks t ON t.id=a.task_id WHERE a.id=?", (attempt_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("unknown workflow attempt")
                if row["status"] == "running":
                    raise ValueError("cannot finalize cost for running attempt")
                prior = c.execute(
                    "SELECT cost_microusd, source FROM workflow_attempt_costs WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()
                if prior is not None:
                    if prior["cost_microusd"] != cost_microusd or prior["source"] != source:
                        raise ValueError("conflicting attempt cost; corrections require audit reconciliation")
                else:
                    c.execute(
                        "INSERT INTO workflow_attempt_costs "
                        "(attempt_id, cost_microusd, source, recorded_at) VALUES (?, ?, ?, ?)",
                        (attempt_id, cost_microusd, source, time.time()),
                    )
                    c.execute(
                        "INSERT INTO workflow_events "
                        "(plan_id, attempt_id, event_type, detail_json, at) "
                        "VALUES (?, ?, 'cost_recorded', ?, ?)",
                        (row["plan_id"], attempt_id, json.dumps({
                            "cost_microusd": cost_microusd, "source": source,
                        }), time.time()),
                    )
                c.execute("COMMIT")
                return cost_microusd
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def get_mission_cost_summary(self, mission_id):
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM missions WHERE id=?", (mission_id,)).fetchone() is None:
                raise ValueError(f"unknown mission: {mission_id}")
            cap = c.execute(
                "SELECT max_cost_microusd FROM mission_cost_limits WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            usage = c.execute(
                "SELECT COALESCE(SUM(cost.cost_microusd), 0) AS spent, COUNT(cost.attempt_id) AS reported "
                "FROM workflow_attempt_costs cost JOIN task_attempts a ON a.id=cost.attempt_id "
                "JOIN workflow_tasks t ON t.id=a.task_id "
                "JOIN workflow_plans p ON p.id=t.plan_id WHERE p.mission_id=?",
                (mission_id,),
            ).fetchone()
            unreported = c.execute(
                "SELECT COUNT(*) AS n FROM task_attempts a "
                "JOIN workflow_tasks t ON t.id=a.task_id "
                "JOIN workflow_plans p ON p.id=t.plan_id "
                "LEFT JOIN workflow_attempt_costs cost ON cost.attempt_id=a.id "
                "WHERE p.mission_id=? AND cost.attempt_id IS NULL", (mission_id,),
            ).fetchone()["n"]
            return {
                "mission_id": mission_id,
                "cap_microusd": cap["max_cost_microusd"] if cap else None,
                "accounted_cost_microusd": usage["spent"],
                "reported_attempts": usage["reported"],
                "unreported_attempts": unreported,
                "exhausted": cap is not None and usage["spent"] >= cap["max_cost_microusd"],
                "pre_dispatch_cost_reservations_available": False,
                "full_cost_coverage": unreported == 0,
            }
        finally:
            c.close()

    def _mission_cost_allows_claim(self, c, plan_id):
        cap = c.execute(
            "SELECT l.max_cost_microusd FROM mission_cost_limits l "
            "JOIN workflow_plans p ON p.mission_id=l.mission_id WHERE p.id=?", (plan_id,),
        ).fetchone()
        if cap is None:
            return True
        spent = c.execute(
            "SELECT COALESCE(SUM(cost.cost_microusd), 0) AS n "
            "FROM workflow_attempt_costs cost JOIN task_attempts a ON a.id=cost.attempt_id "
            "JOIN workflow_tasks t ON t.id=a.task_id "
            "JOIN workflow_plans p ON p.id=t.plan_id "
            "WHERE p.mission_id=(SELECT mission_id FROM workflow_plans WHERE id=?)",
            (plan_id,),
        ).fetchone()["n"]
        # Missing cost evidence means a hard upper bound cannot be guaranteed.
        # Fail closed until every completed attempt has an explicit cost report.
        missing = c.execute(
            "SELECT COUNT(*) AS n FROM task_attempts a "
            "JOIN workflow_tasks t ON t.id=a.task_id "
            "JOIN workflow_plans p ON p.id=t.plan_id "
            "LEFT JOIN workflow_attempt_costs cost ON cost.attempt_id=a.id "
            "WHERE p.mission_id=(SELECT mission_id FROM workflow_plans WHERE id=?) "
            "AND a.status!='running' AND cost.attempt_id IS NULL",
            (plan_id,),
        ).fetchone()["n"]
        return spent < cap["max_cost_microusd"] and missing == 0

    def set_mission_deadline(self, mission_id, *, deadline_at):
        """A durable, mission-scoped cutoff that cannot be extended."""
        import math

        if (
            isinstance(deadline_at, bool)
            or not isinstance(deadline_at, (int, float))
            or not math.isfinite(deadline_at) or deadline_at <= 0
        ):
            raise ValueError("mission deadline_at must be a finite positive unix timestamp")
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if c.execute("SELECT 1 FROM missions WHERE id=?", (mission_id,)).fetchone() is None:
                    raise ValueError(f"unknown mission: {mission_id}")
                old = c.execute(
                    "SELECT deadline_at FROM mission_deadlines WHERE mission_id=?", (mission_id,),
                ).fetchone()
                if old is not None and deadline_at > old["deadline_at"]:
                    raise ValueError("mission deadline cannot be extended")
                c.execute(
                    "INSERT INTO mission_deadlines (mission_id, deadline_at) VALUES (?, ?) "
                    "ON CONFLICT(mission_id) DO UPDATE SET deadline_at=excluded.deadline_at",
                    (mission_id, deadline_at),
                )
                if old is None or old["deadline_at"] != deadline_at:
                    self._audit_mission_execution_change(
                        c, mission_id, "mission_deadline_set",
                        {"deadline_at": deadline_at},
                    )
                c.execute("COMMIT")
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def get_mission_deadline(self, mission_id):
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM missions WHERE id=?", (mission_id,)).fetchone() is None:
                raise ValueError(f"unknown mission: {mission_id}")
            row = c.execute(
                "SELECT deadline_at FROM mission_deadlines WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            return row["deadline_at"] if row else None
        finally:
            c.close()

    def _mission_deadline_allows_dispatch(self, c, plan_id, now):
        row = c.execute(
            "SELECT d.deadline_at FROM mission_deadlines d "
            "JOIN workflow_plans p ON p.mission_id=d.mission_id WHERE p.id=?",
            (plan_id,),
        ).fetchone()
        return row is None or now < row["deadline_at"]

    def set_mission_execution_limits(self, mission_id, *, max_total_attempts, max_concurrency):
        """Tighten cumulative and concurrent budgets across every plan of a mission."""
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in (max_total_attempts, max_concurrency)
        ):
            raise ValueError("mission limits must be positive integers")
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if c.execute("SELECT 1 FROM missions WHERE id=?", (mission_id,)).fetchone() is None:
                    raise ValueError(f"unknown mission: {mission_id}")
                old = c.execute(
                    "SELECT max_total_attempts, max_concurrency FROM mission_execution_limits "
                    "WHERE mission_id=?", (mission_id,),
                ).fetchone()
                if old is not None and (
                    max_total_attempts > old["max_total_attempts"]
                    or max_concurrency > old["max_concurrency"]
                ):
                    raise ValueError("mission limits cannot be relaxed")
                c.execute(
                    "INSERT INTO mission_execution_limits "
                    "(mission_id, max_total_attempts, max_concurrency) VALUES (?, ?, ?) "
                    "ON CONFLICT(mission_id) DO UPDATE SET "
                    "max_total_attempts=excluded.max_total_attempts, "
                    "max_concurrency=excluded.max_concurrency",
                    (mission_id, max_total_attempts, max_concurrency),
                )
                if old is None or (
                    old["max_total_attempts"] != max_total_attempts
                    or old["max_concurrency"] != max_concurrency
                ):
                    self._audit_mission_execution_change(
                        c, mission_id, "mission_execution_limits_set",
                        {"max_total_attempts": max_total_attempts,
                         "max_concurrency": max_concurrency},
                    )
                c.execute("COMMIT")
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def get_mission_execution_limits(self, mission_id):
        """Return configured mission caps and measured across-plan usage."""
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM missions WHERE id=?", (mission_id,)).fetchone() is None:
                raise ValueError(f"unknown mission: {mission_id}")
            limits = c.execute(
                "SELECT max_total_attempts, max_concurrency FROM mission_execution_limits "
                "WHERE mission_id=?", (mission_id,),
            ).fetchone()
            usage = c.execute(
                "SELECT COUNT(*) AS attempts, "
                "COALESCE(SUM(CASE WHEN a.status='running' THEN 1 ELSE 0 END), 0) AS active "
                "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                "JOIN workflow_plans p ON p.id=t.plan_id WHERE p.mission_id=?",
                (mission_id,),
            ).fetchone()
            deadline = c.execute(
                "SELECT deadline_at FROM mission_deadlines WHERE mission_id=?", (mission_id,),
            ).fetchone()
            return {
                "mission_id": mission_id,
                "deadline_at": deadline["deadline_at"] if deadline else None,
                "deadline_exceeded": bool(deadline and time.time() >= deadline["deadline_at"]),
                "max_total_attempts": limits["max_total_attempts"] if limits else None,
                "max_concurrency": limits["max_concurrency"] if limits else None,
                "attempts": usage["attempts"], "active_attempts": usage["active"],
                "enforced": limits is not None,
            }
        finally:
            c.close()

    def _mission_budget_available(self, c, plan_id):
        """Call inside BEGIN IMMEDIATE; serializes claims from different workers."""
        limits = c.execute(
            "SELECT l.max_total_attempts, l.max_concurrency FROM mission_execution_limits l "
            "JOIN workflow_plans p ON p.mission_id=l.mission_id WHERE p.id=?",
            (plan_id,),
        ).fetchone()
        if limits is None:
            return True
        usage = c.execute(
            "SELECT COUNT(*) AS attempts, "
            "COALESCE(SUM(CASE WHEN a.status='running' THEN 1 ELSE 0 END), 0) AS active "
            "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
            "JOIN workflow_plans p ON p.id=t.plan_id "
            "WHERE p.mission_id=(SELECT mission_id FROM workflow_plans WHERE id=?)",
            (plan_id,),
        ).fetchone()
        return (
            usage["attempts"] < limits["max_total_attempts"]
            and usage["active"] < limits["max_concurrency"]
        )

    def _execution_limits_allow_dispatch(self, c, plan_id):
        """Recheck tightened plan and mission caps after claim, before effects.

        The current running attempt is already counted, so equality is allowed.
        New claims use strict less-than comparisons instead.
        """
        limits = c.execute(
            "SELECT max_total_attempts, max_concurrency FROM workflow_limits "
            "WHERE plan_id=?", (plan_id,),
        ).fetchone()
        usage = c.execute(
            "SELECT COUNT(*) AS attempts, "
            "COALESCE(SUM(CASE WHEN a.status='running' THEN 1 ELSE 0 END), 0) AS active "
            "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
            "WHERE t.plan_id=?", (plan_id,),
        ).fetchone()
        if usage["attempts"] > (limits["max_total_attempts"] if limits else 100):
            return False
        if usage["active"] > (limits["max_concurrency"] if limits else 4):
            return False
        mission_limits = c.execute(
            "SELECT l.max_total_attempts, l.max_concurrency "
            "FROM mission_execution_limits l JOIN workflow_plans p "
            "ON p.mission_id=l.mission_id WHERE p.id=?", (plan_id,),
        ).fetchone()
        if mission_limits is not None:
            mission_usage = c.execute(
                "SELECT COUNT(*) AS attempts, "
                "COALESCE(SUM(CASE WHEN a.status='running' THEN 1 ELSE 0 END), 0) AS active "
                "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                "JOIN workflow_plans p ON p.id=t.plan_id "
                "WHERE p.mission_id=(SELECT mission_id FROM workflow_plans WHERE id=?)",
                (plan_id,),
            ).fetchone()
            if (
                mission_usage["attempts"] > mission_limits["max_total_attempts"]
                or mission_usage["active"] > mission_limits["max_concurrency"]
            ):
                return False
        return self._mission_cost_allows_claim(c, plan_id)

    def get_workflow_limits(self, plan_id):
        """Return effective backend limits, including defaults for old plans."""
        c = self._conn()
        try:
            if c.execute("SELECT 1 FROM workflow_plans WHERE id=?", (plan_id,)).fetchone() is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            row = c.execute(
                "SELECT max_total_attempts, max_concurrency FROM workflow_limits "
                "WHERE plan_id=?", (plan_id,),
            ).fetchone()
            return {
                "max_total_attempts": row["max_total_attempts"] if row else 100,
                "max_concurrency": row["max_concurrency"] if row else 4,
            }
        finally:
            c.close()

    def mark_workflow_dispatch_started(self, plan_id, attempt_id):
        """Atomically record dispatch intent or reject a cancelled/stale attempt.

        The recorded event makes crash recovery distinguish pre-dispatch claims
        from attempts that may have produced external side effects.
        """
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT a.task_id, a.status AS attempt_status, "
                    "t.status AS task_status, t.active_attempt_id, p.status AS plan_status "
                    "FROM task_attempts a "
                    "JOIN workflow_tasks t ON t.id=a.task_id "
                    "JOIN workflow_plans p ON p.id=t.plan_id "
                    "WHERE a.id=? AND t.plan_id=?", (attempt_id, plan_id),
                ).fetchone()
                self._verify_workflow_plan_integrity_tx(c, plan_id)
                if row is None or row["attempt_status"] != "running" or (
                    row["task_status"] != "running" or row["active_attempt_id"] != attempt_id
                ):
                    raise ValueError("stale workflow dispatch attempt")
                if row["plan_status"] == "cancel_requested":
                    c.execute("COMMIT")
                    return False
                deadline = c.execute(
                    "SELECT deadline_at FROM workflow_deadlines WHERE plan_id=?", (plan_id,),
                ).fetchone()
                if (
                    (deadline is not None and now >= deadline["deadline_at"])
                    or not self._mission_deadline_allows_dispatch(c, plan_id, now)
                    or not self._execution_limits_allow_dispatch(c, plan_id)
                ):
                    c.execute("COMMIT")
                    return False
                previous = c.execute(
                    "SELECT 1 FROM workflow_events "
                    "WHERE plan_id=? AND attempt_id=? AND event_type='dispatch_started'",
                    (plan_id, attempt_id),
                ).fetchone()
                if previous is not None:
                    raise ValueError("workflow dispatch already recorded")
                c.execute(
                    "INSERT INTO workflow_events "
                    "(plan_id, task_ref, attempt_id, event_type, at) "
                    "VALUES (?, ?, ?, 'dispatch_started', ?)",
                    (plan_id, row["task_id"], attempt_id, now),
                )
                c.execute("COMMIT")
                return True
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def workflow_cancellation_requested(self, plan_id):
        """Read the durable stop-intent barrier for an execution boundary."""
        c = self._conn()
        try:
            row = c.execute(
                "SELECT status FROM workflow_plans WHERE id=?", (plan_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"unknown workflow plan: {plan_id}")
            return row["status"] == "cancel_requested"
        finally:
            c.close()

    def request_workflow_cancellation(self, plan_id):
        """Persist stop intent and cancel unclaimed work atomically.

        Running attempts retain their leases and must be reconciled independently:
        a cancellation request does not prove an external provider has stopped.
        """
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                plan = c.execute(
                    "SELECT status FROM workflow_plans WHERE id=?", (plan_id,)
                ).fetchone()
                if plan is None:
                    raise ValueError(f"unknown workflow plan: {plan_id}")
                if plan["status"] != "cancel_requested":
                    c.execute(
                        "UPDATE workflow_plans SET status='cancel_requested' WHERE id=?",
                        (plan_id,),
                    )
                if plan["status"] != "cancel_requested":
                    c.execute(
                        "INSERT INTO workflow_events (plan_id, event_type, at) "
                        "VALUES (?, 'cancellation_requested', ?)",
                        (plan_id, now),
                    )
                cancelled = c.execute(
                    "SELECT id FROM workflow_tasks "
                    "WHERE plan_id=? AND status IN ('pending', 'failed')",
                    (plan_id,),
                ).fetchall()
                cur = c.execute(
                    "UPDATE workflow_tasks SET status='cancelled', "
                    "error='workflow cancellation requested before dispatch', updated_at=? "
                    "WHERE plan_id=? AND status IN ('pending', 'failed')",
                    (now, plan_id),
                )
                for task in cancelled:
                    c.execute(
                        "INSERT INTO workflow_events "
                        "(plan_id, task_ref, event_type, at) "
                        "VALUES (?, ?, 'task_cancelled', ?)",
                        (plan_id, task["id"], now),
                    )
                c.execute("COMMIT")
                return cur.rowcount
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def claim_ready_workflow_task(self, plan_id, worker_id, max_attempts=3):
        """Atomically claim a DAG node using plan-scoped task references."""
        import uuid
        if (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or max_attempts < 1
        ):
            raise ValueError("max_attempts must be a positive integer")
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                plan = c.execute(
                    "SELECT status FROM workflow_plans WHERE id=?", (plan_id,)
                ).fetchone()
                if plan is None or plan["status"] == "cancel_requested":
                    c.execute("COMMIT")
                    return None
                self._verify_workflow_plan_integrity_tx(c, plan_id)
                deadline = c.execute(
                    "SELECT deadline_at FROM workflow_deadlines WHERE plan_id=?", (plan_id,),
                ).fetchone()
                if (
                    (deadline is not None and time.time() >= deadline["deadline_at"])
                    or not self._mission_deadline_allows_dispatch(c, plan_id, time.time())
                ):
                    c.execute("COMMIT")
                    return None
                limit_row = c.execute(
                    "SELECT max_total_attempts, max_concurrency FROM workflow_limits "
                    "WHERE plan_id=?", (plan_id,),
                ).fetchone()
                max_total = limit_row["max_total_attempts"] if limit_row else 100
                max_parallel = limit_row["max_concurrency"] if limit_row else 4
                usage = c.execute(
                    "SELECT COUNT(*) AS attempts, "
                    "COALESCE(SUM(CASE WHEN a.status='running' THEN 1 ELSE 0 END), 0) AS active "
                    "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                    "WHERE t.plan_id=?", (plan_id,),
                ).fetchone()
                if (
                    usage["attempts"] >= max_total
                    or usage["active"] >= max_parallel
                    or not self._mission_budget_available(c, plan_id)
                    or not self._mission_cost_allows_claim(c, plan_id)
                ):
                    c.execute("COMMIT")
                    return None
                mission_rate = c.execute(
                    "SELECT r.min_spacing_s, r.last_claimed_at "
                    "FROM mission_rate_limits r JOIN workflow_plans p "
                    "ON p.mission_id=r.mission_id WHERE p.id=?", (plan_id,),
                ).fetchone()
                if mission_rate is not None and mission_rate["last_claimed_at"] is not None and (
                    time.time() < mission_rate["last_claimed_at"] + mission_rate["min_spacing_s"]
                ):
                    c.execute("COMMIT")
                    return None
                rate = c.execute(
                    "SELECT min_spacing_s, last_claimed_at FROM workflow_rate_limits "
                    "WHERE plan_id=?", (plan_id,),
                ).fetchone()
                if rate is not None and rate["last_claimed_at"] is not None and (
                    time.time() < rate["last_claimed_at"] + rate["min_spacing_s"]
                ):
                    c.execute("COMMIT")
                    return None
                candidates = c.execute(
                    "SELECT * FROM workflow_tasks WHERE plan_id=? AND status IN ('pending','failed') "
                    "ORDER BY created_at, task_key", (plan_id,),
                ).fetchall()
                for row in candidates:
                    count = c.execute(
                        "SELECT COUNT(*) AS n FROM task_attempts WHERE task_id=?", (row["id"],)
                    ).fetchone()["n"]
                    if count >= max_attempts:
                        continue
                    dependency_refs = json.loads(row["depends_on_json"] or "[]")
                    dependencies = []
                    if dependency_refs:
                        marks = ",".join("?" for _ in dependency_refs)
                        states = c.execute(
                            f"SELECT id, task_key, status FROM workflow_tasks WHERE id IN ({marks})",
                            tuple(dependency_refs),
                        ).fetchall()
                        if len(states) != len(dependency_refs):
                            continue
                        state_by_ref = {item["id"]: item for item in states}
                        failed_terminal = False
                        for dependency_ref in dependency_refs:
                            dependency = state_by_ref[dependency_ref]
                            if dependency["status"] in ("blocked", "cancelled", "uncertain"):
                                failed_terminal = True
                                break
                            if dependency["status"] == "failed":
                                dep_attempts = c.execute(
                                    "SELECT COUNT(*) AS n FROM task_attempts WHERE task_id=?",
                                    (dependency_ref,),
                                ).fetchone()["n"]
                                if dep_attempts >= max_attempts:
                                    failed_terminal = True
                                    break
                        if failed_terminal:
                            now = time.time()
                            c.execute(
                                "UPDATE workflow_tasks SET status='blocked', "
                                "error='dependency did not complete successfully', updated_at=? WHERE id=?",
                                (now, row["id"]),
                            )
                            c.execute(
                                "INSERT INTO workflow_events "
                                "(plan_id, task_ref, event_type, detail_json, at) "
                                "VALUES (?, ?, 'task_blocked', ?, ?)",
                                (plan_id, row["id"],
                                 json.dumps({"reason": "dependency_not_successful"}), now),
                            )
                            continue
                        if any(state_by_ref[ref]["status"] != "succeeded" for ref in dependency_refs):
                            continue
                        dependencies = [state_by_ref[ref]["task_key"] for ref in dependency_refs]
                    attempt_no = count + 1
                    attempt_id = uuid.uuid4().hex
                    now = time.time()
                    cur = c.execute(
                        "UPDATE workflow_tasks SET status='running', active_attempt_id=?, "
                        "error=NULL, updated_at=? WHERE id=? AND status IN ('pending','failed')",
                        (attempt_id, now, row["id"]),
                    )
                    if cur.rowcount != 1:
                        continue
                    c.execute(
                        "INSERT INTO task_attempts "
                        "(id, task_id, attempt_no, status, worker_id, idempotency_key, started_at, heartbeat_at) "
                        "VALUES (?, ?, ?, 'running', ?, ?, ?, ?)",
                        (attempt_id, row["id"], attempt_no, worker_id, row["idempotency_key"], now, now),
                    )
                    c.execute(
                        "UPDATE workflow_rate_limits SET last_claimed_at=? WHERE plan_id=?",
                        (now, plan_id),
                    )
                    c.execute(
                        "UPDATE mission_rate_limits SET last_claimed_at=? WHERE mission_id="
                        "(SELECT mission_id FROM workflow_plans WHERE id=?)",
                        (now, plan_id),
                    )
                    c.execute(
                        "INSERT INTO workflow_events "
                        "(plan_id, task_ref, attempt_id, event_type, detail_json, at) "
                        "VALUES (?, ?, ?, 'task_claimed', ?, ?)",
                        (plan_id, row["id"], attempt_id,
                         json.dumps({"worker_id": worker_id, "attempt_no": attempt_no}), now),
                    )
                    value = dict(row)
                    value.update({
                        "attempt_id": attempt_id, "attempt_no": attempt_no,
                        "worker_id": worker_id, "status": "running",
                        "task_ref": row["id"], "id": row["task_key"],
                        "inputs": json.loads(row["inputs_json"] or "{}"),
                        "depends_on": dependencies,
                        "permissions": json.loads(row["permissions_json"] or "[]"),
                    })
                    c.execute("COMMIT")
                    return value
                c.execute("COMMIT")
                return None
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def start_task_attempt(
        self, attempt_id, task_id, attempt_no, worker_id="", idempotency_key="", plan_id=None,
    ):
        """Create one fenced attempt; task_id may be plan-local when unambiguous."""
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                if plan_id is None:
                    matches = c.execute(
                        "SELECT id FROM workflow_tasks WHERE id=? OR task_key=? LIMIT 2",
                        (task_id, task_id),
                    ).fetchall()
                    if len(matches) > 1:
                        raise ValueError("task id is ambiguous; supply plan_id")
                    task_ref = matches[0]["id"] if matches else None
                else:
                    match = c.execute(
                        "SELECT id FROM workflow_tasks WHERE plan_id=? AND (id=? OR task_key=?)",
                        (plan_id, task_id, task_id),
                    ).fetchone()
                    task_ref = match["id"] if match else None
                if task_ref is None:
                    raise ValueError(f"unknown workflow task: {task_id}")
                plan_row = c.execute(
                    "SELECT t.plan_id, p.status FROM workflow_tasks t "
                    "JOIN workflow_plans p ON p.id=t.plan_id WHERE t.id=?",
                    (task_ref,),
                ).fetchone()
                if plan_row["status"] == "cancel_requested":
                    raise ValueError("workflow cancellation requested")
                deadline = c.execute(
                    "SELECT deadline_at FROM workflow_deadlines WHERE plan_id=?",
                    (plan_row["plan_id"],),
                ).fetchone()
                if deadline is not None and time.time() >= deadline["deadline_at"]:
                    raise ValueError("workflow deadline exceeded")
                if not self._mission_deadline_allows_dispatch(c, plan_row["plan_id"], now):
                    raise ValueError("mission deadline exceeded")
                effective_plan = plan_row["plan_id"]
                self._verify_workflow_plan_integrity_tx(c, effective_plan)
                limits = c.execute(
                    "SELECT max_total_attempts, max_concurrency FROM workflow_limits "
                    "WHERE plan_id=?", (effective_plan,),
                ).fetchone()
                usage = c.execute(
                    "SELECT COUNT(*) AS attempts, "
                    "COALESCE(SUM(CASE WHEN a.status='running' THEN 1 ELSE 0 END), 0) AS active "
                    "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                    "WHERE t.plan_id=?", (effective_plan,),
                ).fetchone()
                if usage["attempts"] >= (limits["max_total_attempts"] if limits else 100):
                    raise ValueError("workflow total attempt budget exhausted")
                if usage["active"] >= (limits["max_concurrency"] if limits else 4):
                    raise ValueError("workflow concurrency budget exhausted")
                if not self._mission_budget_available(c, effective_plan):
                    raise ValueError("mission execution budget exhausted")
                if not self._mission_cost_allows_claim(c, effective_plan):
                    raise ValueError("mission cost budget blocked or reporting incomplete")
                task = c.execute(
                    "SELECT status, idempotency_key FROM workflow_tasks WHERE id=?", (task_ref,)
                ).fetchone()
                if task["status"] in ("succeeded", "cancelled", "blocked", "uncertain"):
                    raise ValueError(f"task is terminal: {task_id}")
                if task["status"] == "running":
                    raise ValueError(f"task already has an active attempt: {task_id}")
                if task["status"] not in ("pending", "failed"):
                    raise ValueError(f"task is not claimable: {task_id}")
                if task["idempotency_key"] and idempotency_key != task["idempotency_key"]:
                    raise ValueError("task attempt idempotency key mismatch")
                dependencies_row = c.execute(
                    "SELECT depends_on_json FROM workflow_tasks WHERE id=?", (task_ref,),
                ).fetchone()
                dependency_refs = json.loads(dependencies_row["depends_on_json"] or "[]")
                if dependency_refs:
                    marks = ",".join("?" for _ in dependency_refs)
                    dep_rows = c.execute(
                        f"SELECT id, status FROM workflow_tasks WHERE id IN ({marks})",
                        tuple(dependency_refs),
                    ).fetchall()
                    if len(dep_rows) != len(dependency_refs) or any(
                        item["status"] != "succeeded" for item in dep_rows
                    ):
                        raise ValueError("workflow dependencies are not succeeded")
                mission_rate = c.execute(
                    "SELECT r.min_spacing_s, r.last_claimed_at "
                    "FROM mission_rate_limits r JOIN workflow_plans p "
                    "ON p.mission_id=r.mission_id WHERE p.id=?", (effective_plan,),
                ).fetchone()
                if mission_rate is not None and mission_rate["last_claimed_at"] is not None and (
                    now < mission_rate["last_claimed_at"] + mission_rate["min_spacing_s"]
                ):
                    raise ValueError("mission rate budget exhausted")
                rate = c.execute(
                    "SELECT min_spacing_s, last_claimed_at FROM workflow_rate_limits "
                    "WHERE plan_id=?", (effective_plan,),
                ).fetchone()
                if rate is not None and rate["last_claimed_at"] is not None and (
                    now < rate["last_claimed_at"] + rate["min_spacing_s"]
                ):
                    raise ValueError("workflow rate budget exhausted")
                previous = c.execute(
                    "SELECT COALESCE(MAX(attempt_no), 0) AS n FROM task_attempts WHERE task_id=?",
                    (task_ref,),
                ).fetchone()["n"]
                if isinstance(attempt_no, bool) or not isinstance(attempt_no, int) or attempt_no != previous + 1:
                    raise ValueError("attempt number must be the next positive sequence")
                c.execute(
                    "INSERT INTO task_attempts "
                    "(id, task_id, attempt_no, status, worker_id, idempotency_key, started_at) "
                    "VALUES (?, ?, ?, 'running', ?, ?, ?)",
                    (attempt_id, task_ref, int(attempt_no), worker_id, idempotency_key, now),
                )
                cur = c.execute(
                    "UPDATE workflow_tasks SET status='running', active_attempt_id=?, "
                    "error=NULL, updated_at=? WHERE id=? AND status IN ('pending','failed')",
                    (attempt_id, now, task_ref),
                )
                if cur.rowcount != 1:
                    raise ValueError(f"task is already claimed: {task_id}")
                c.execute(
                    "UPDATE workflow_rate_limits SET last_claimed_at=? WHERE plan_id=?",
                    (now, effective_plan),
                )
                c.execute(
                    "UPDATE mission_rate_limits SET last_claimed_at=? WHERE mission_id="
                    "(SELECT mission_id FROM workflow_plans WHERE id=?)",
                    (now, effective_plan),
                )
                c.execute(
                    "INSERT INTO workflow_events "
                    "(plan_id, task_ref, attempt_id, event_type, detail_json, at) "
                    "VALUES (?, ?, ?, 'task_claimed', ?, ?)",
                    (effective_plan, task_ref, attempt_id,
                     json.dumps({"worker_id": worker_id, "attempt_no": attempt_no}), now),
                )
                c.execute("COMMIT")
                return True
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def get_workflow_attempt_status(self, attempt_id):
        """Read the committed result, including cancellation-race fencing."""
        c = self._conn()
        try:
            row = c.execute(
                "SELECT status FROM task_attempts WHERE id=?", (attempt_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"unknown task attempt: {attempt_id}")
            return row["status"]
        finally:
            c.close()

    def finish_task_attempt(self, attempt_id, status, result=None, error=""):
        """Record an attempt outcome and update its task in one transaction."""
        if status not in ("succeeded", "failed", "cancelled", "uncertain", "blocked"):
            raise ValueError(f"invalid terminal attempt status: {status}")
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT a.task_id, a.status, p.id AS plan_id, "
                    "p.status AS plan_status "
                    "FROM task_attempts a JOIN workflow_tasks t ON t.id=a.task_id "
                    "JOIN workflow_plans p ON p.id=t.plan_id WHERE a.id=?",
                    (attempt_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"unknown task attempt: {attempt_id}")
                if row["status"] != "running":
                    raise ValueError("task attempt is already terminal")
                # Revalidate the immutable DAG at the terminal commit boundary.
                # A provider may have produced effects while persisted task
                # bindings were changed; such an outcome cannot be certified.
                try:
                    self._verify_workflow_plan_integrity_tx(c, row["plan_id"])
                except ValueError:
                    status = "uncertain"
                    result = None
                    error = (
                        "workflow plan integrity failed during provider execution; "
                        "reconcile external effects"
                    )
                # The plan cancellation barrier and outcome must serialize in
                # one write transaction. An external effect cannot be certified
                # successful after cancellation was durably recorded.
                if row["plan_status"] == "cancel_requested" and status in ("succeeded", "failed"):
                    status = "uncertain"
                    result = None
                    error = "provider outcome after cancellation requires reconciliation"
                encoded = json.dumps(result, sort_keys=True) if result is not None else None
                c.execute(
                    "UPDATE task_attempts SET status=?, finished_at=?, result_json=?, error=? WHERE id=?",
                    (status, now, encoded, error, attempt_id),
                )
                cur = c.execute(
                    "UPDATE workflow_tasks SET status=?, result_json=?, error=?, "
                    "active_attempt_id=NULL, updated_at=? "
                    "WHERE id=? AND status='running' AND active_attempt_id=?",
                    (status, encoded, error, now, row["task_id"], attempt_id),
                )
                if cur.rowcount != 1:
                    raise ValueError("stale task attempt cannot update the workflow task")
                plan_row = c.execute(
                    "SELECT plan_id FROM workflow_tasks WHERE id=?", (row["task_id"],)
                ).fetchone()
                c.execute(
                    "INSERT INTO workflow_events "
                    "(plan_id, task_ref, attempt_id, event_type, detail_json, at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (plan_row["plan_id"], row["task_id"], attempt_id,
                     "task_" + status, json.dumps({"error": error}), now),
                )
                # Seal matching provider evidence inside the terminal-outcome transaction.
                # Missing, in-progress or cross-target jobs remain unsealed.
                if status == "succeeded" and isinstance(result, dict):
                    job_id = result.get("job_id")
                    task = c.execute(
                        "SELECT t.target, t.capability_id, p.digest FROM workflow_tasks t "
                        "JOIN workflow_plans p ON p.id=t.plan_id WHERE t.id=?",
                        (row["task_id"],),
                    ).fetchone()
                    if (
                        isinstance(job_id, str) and bool(job_id)
                        and result.get("target") == task["target"]
                        and result.get("tool_id") == task["capability_id"].removeprefix("tool.")
                    ):
                        digest = _workflow_evidence_digest(
                            c, attempt_id=attempt_id, job_id=job_id,
                            target=task["target"], capability_id=task["capability_id"],
                            plan_digest=task["digest"],
                        )
                        if digest is not None:
                            c.execute(
                                "INSERT INTO workflow_evidence_seals "
                                "(attempt_id, job_id, digest, version, sealed_at) "
                                "VALUES (?, ?, ?, 1, ?)",
                                (attempt_id, job_id, digest, now),
                            )
                c.execute("COMMIT")
                return True
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    # --- AI runs ---------------------------------------------------------

    def create_ai_run(self, run_id, goal, provider="null", phase="recon", owner="local"):
        with self._lock:
            c = self._conn()
            try: c.execute("INSERT OR IGNORE INTO ai_runs (id, goal, provider, status, started_at, phase, owner) VALUES (?, ?, ?, 'running', ?, ?, ?)", (run_id, goal, provider, time.time(), phase, owner))
            finally: c.close()

    def append_ai_run_step(self, run_id, seq, action_json, result_json):
        with self._lock:
            c = self._conn()
            try: c.execute("INSERT OR REPLACE INTO ai_run_steps (run_id, seq, action_json, result_json, created_at) VALUES (?, ?, ?, ?, ?)", (run_id, seq, json.dumps(action_json), json.dumps(result_json), time.time()))
            finally: c.close()

    def set_ai_run_phase(self, run_id, phase, history_entry=None):
        with self._lock:
            c = self._conn()
            try:
                row = c.execute("SELECT phase_history FROM ai_runs WHERE id=?", (run_id,)).fetchone()
                history = json.loads(row["phase_history"]) if row and row["phase_history"] else []
                if history_entry is None:
                    history_entry = {"phase": phase, "at": time.time()}
                history.append(history_entry)
                c.execute("UPDATE ai_runs SET phase=?, phase_history=? WHERE id=?", (phase, json.dumps(history), run_id))
            finally: c.close()

    def set_ai_run_waiting(self, run_id, question_json):
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "UPDATE ai_runs SET status='waiting', pending_question=? WHERE id=?",
                    (question_json, run_id),
                )
            finally: c.close()

    def add_approval(self, run_id, seq, user, answer, note=""):
        """Record an answer and clear the run's waiting state.

        An approval answers the pending question, so the run is no
        longer waiting on it. Resume moves the run forward; if the
        loop pauses again, set_ai_run_waiting re-sets 'waiting'.
        """
        with self._lock:
            c = self._conn()
            try:
                c.execute("INSERT OR REPLACE INTO approvals (run_id, seq, user, answer, note, at) VALUES (?, ?, ?, ?, ?, ?)", (run_id, int(seq), user, answer, note, time.time()))
                c.execute("UPDATE ai_runs SET status='running', pending_question='' WHERE id=? AND status='waiting'", (run_id,))
            finally: c.close()

    def list_approvals(self, run_id):
        c = self._conn()
        try:
            rows = c.execute("SELECT run_id, seq, user, answer, note, at FROM approvals WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
            return [dict(r) for r in rows]
        finally: c.close()

    def last_approval(self, run_id):
        """Return the latest approval row for a run, or None."""
        c = self._conn()
        try:
            row = c.execute(
                "SELECT run_id, seq, user, answer, note, at "
                "FROM approvals WHERE run_id=? ORDER BY seq DESC LIMIT 1",
                (run_id,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            c.close()

    def list_pending_runs(self, owner=None):
        c = self._conn()
        try:
            base = "SELECT id, goal, owner, phase, pending_question, started_at FROM ai_runs WHERE status='waiting'"
            if owner:
                rows = c.execute(base + " AND owner=? ORDER BY started_at DESC", (owner,)).fetchall()
            else:
                rows = c.execute(base + " ORDER BY started_at DESC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                pq = d.get("pending_question")
                if isinstance(pq, str) and pq:
                    try:
                        d["pending_question"] = json.loads(pq)
                    except (ValueError, TypeError):
                        d["pending_question"] = None
                out.append(d)
            return out
        finally: c.close()

    def set_ai_run_usage(self, run_id, tokens_in, tokens_out, cost_usd=None):
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "UPDATE ai_runs SET tokens_in=?, tokens_out=?, cost_usd=? WHERE id=?",
                    (int(tokens_in), int(tokens_out), cost_usd, run_id),
                )
            finally: c.close()

    def set_ai_run_consecutive_failures(self, run_id, count):
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "UPDATE ai_runs SET consecutive_failures=? WHERE id=?",
                    (int(count), run_id),
                )
            finally: c.close()

    def set_ai_run_finished(self, run_id, status="done", error=""):
        with self._lock:
            c = self._conn()
            try: c.execute("UPDATE ai_runs SET status=?, finished_at=?, error=? WHERE id=?", (status, time.time(), error, run_id))
            finally: c.close()

    def get_ai_run(self, run_id):
        c = self._conn()
        try:
            row = c.execute("SELECT * FROM ai_runs WHERE id=?", (run_id,)).fetchone()
            if row is None: return None
            out = dict(row)
            steps = c.execute("SELECT seq, action_json, result_json, created_at FROM ai_run_steps WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
            out["steps"] = [{"seq": r["seq"], "action": json.loads(r["action_json"]), "result": json.loads(r["result_json"]), "created_at": r["created_at"]} for r in steps]
            return out
        finally: c.close()

    def list_ai_runs(self, limit=50):
        c = self._conn()
        try:
            rows = c.execute("SELECT id, goal, provider, status, started_at, finished_at, error, phase FROM ai_runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
        finally: c.close()

    def lines_since(self, job_id, since_seq=0):
        c = self._conn()
        try:
            rows = c.execute("SELECT seq, stream, text FROM lines WHERE job_id=? AND seq>=? ORDER BY seq", (job_id, since_seq)).fetchall()
            return [{"seq": r["seq"], "stream": r["stream"], "text": r["text"]} for r in rows]
        finally: c.close()
