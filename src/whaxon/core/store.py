import json, sqlite3, threading, time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, tool TEXT DEFAULT '', target TEXT DEFAULT '', status TEXT DEFAULT 'starting', exit_code INTEGER, error TEXT, started_at REAL, finished_at REAL, duration_s REAL);
CREATE TABLE IF NOT EXISTS lines (job_id TEXT, seq INTEGER, stream TEXT, text TEXT, PRIMARY KEY (job_id, seq));
CREATE TABLE IF NOT EXISTS findings (job_id TEXT, seq INTEGER, kind TEXT, severity TEXT, source TEXT, data_json TEXT, raw_line TEXT, enrichment_json TEXT DEFAULT '{}', PRIMARY KEY (job_id, seq));
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
"""



def _signature_for(kind: str, data: dict) -> str:
    """Build a stable per-finding signature for dedup."""
    if kind == "open_port":
        return f"port:{data.get('port')}/{data.get('protocol', 'tcp')}"
    if kind == "web_issue":
        return f"path:{data.get('path') or data.get('location') or ''}"
    if kind == "found_path":
        return f"path:{data.get('path') or ''}"
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
    # Fallback: use the first data value
    for v in (data or {}).values():
        return f"val:{v}"
    return "unknown"

class JobStore:
    def __init__(self, db_path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        c = self._conn()
        try:
            c.executescript(SCHEMA)
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
            c.execute("CREATE TABLE IF NOT EXISTS approvals (run_id TEXT, seq INTEGER, user TEXT, answer TEXT, note TEXT, at REAL, PRIMARY KEY (run_id, seq))")
        finally: c.close()
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.row_factory = sqlite3.Row
        return c
    def create(self, job_id):
        with self._lock:
            c = self._conn()
            try: c.execute("INSERT OR IGNORE INTO jobs (id, started_at) VALUES (?, ?)", (job_id, time.time()))
            finally: c.close()
    def set_started(self, job_id, tool, target):
        with self._lock:
            c = self._conn()
            try: c.execute("UPDATE jobs SET status='running', tool=?, target=?, started_at=? WHERE id=?", (tool, target, time.time(), job_id))
            finally: c.close()
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
        }
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "INSERT INTO findings (job_id, seq, kind, severity, source, data_json, raw_line, enrichment_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (job_id, seq, f.get("kind",""), f.get("severity","info"), f.get("source",""), json.dumps(f.get("data",{})), f.get("raw_line",""), json.dumps(enrichment))
                )
            finally: c.close()

    def set_finished(self, job_id, exit_code, duration_s):
        with self._lock:
            c = self._conn()
            try: c.execute("UPDATE jobs SET status='finished', exit_code=?, duration_s=?, finished_at=? WHERE id=?", (exit_code, duration_s, time.time(), job_id))
            finally: c.close()
    def set_failed(self, job_id, error):
        with self._lock:
            c = self._conn()
            try: c.execute("UPDATE jobs SET status='failed', error=?, finished_at=? WHERE id=?", (error, time.time(), job_id))
            finally: c.close()
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
                "SELECT kind, severity, source, data_json, raw_line, enrichment_json "
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
                })
            return out
        finally: c.close()
    def history(self, limit=50):
        c = self._conn()
        try:
            rows = c.execute("SELECT id, tool, target, status, exit_code, duration_s FROM jobs WHERE status IN ('finished','failed') ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
            out = []
            for r in rows:
                n = c.execute("SELECT COUNT(*) AS n FROM lines WHERE job_id=?", (r["id"],)).fetchone()["n"]
                out.append({"id": r["id"], "tool": r["tool"], "target": r["target"], "status": r["status"], "exit_code": r["exit_code"], "duration_s": r["duration_s"], "line_count": n})
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

                for j in job_rows:
                    target = j["target"]
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
                        key = (target, f["kind"], sig)
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
        with self._lock:
            c = self._conn()
            try:
                c.execute("INSERT OR REPLACE INTO approvals (run_id, seq, user, answer, note, at) VALUES (?, ?, ?, ?, ?, ?)", (run_id, int(seq), user, answer, note, time.time()))
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
            return [dict(r) for r in rows]
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