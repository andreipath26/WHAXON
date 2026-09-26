import json, sqlite3, threading, time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, tool TEXT DEFAULT '', target TEXT DEFAULT '', status TEXT DEFAULT 'starting', exit_code INTEGER, error TEXT, started_at REAL, finished_at REAL, duration_s REAL);
CREATE TABLE IF NOT EXISTS lines (job_id TEXT, seq INTEGER, stream TEXT, text TEXT, PRIMARY KEY (job_id, seq));
CREATE TABLE IF NOT EXISTS findings (job_id TEXT, seq INTEGER, kind TEXT, severity TEXT, source TEXT, data_json TEXT, raw_line TEXT, PRIMARY KEY (job_id, seq));
CREATE INDEX IF NOT EXISTS idx_jobs_started ON jobs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_lines_job ON lines(job_id, seq);
CREATE TABLE IF NOT EXISTS evidence (
    job_id TEXT, seq INTEGER, kind TEXT, name TEXT, path TEXT, note TEXT, added_at REAL,
    PRIMARY KEY (job_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_evidence_job ON evidence(job_id, seq);
"""

class JobStore:
    def __init__(self, db_path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        c = self._conn()
        try: c.executescript(SCHEMA)
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
        with self._lock:
            c = self._conn()
            try:
                c.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?)", (job_id, seq, f.get("kind",""), f.get("severity","info"), f.get("source",""), json.dumps(f.get("data",{})), f.get("raw_line","")))
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
            rows = c.execute("SELECT kind, severity, source, data_json, raw_line FROM findings WHERE job_id=? ORDER BY seq", (job_id,)).fetchall()
            return [{"kind": r["kind"], "severity": r["severity"], "source": r["source"], "data": json.loads(r["data_json"]), "raw_line": r["raw_line"]} for r in rows]
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
    def lines_since(self, job_id, since_seq=0):
        c = self._conn()
        try:
            rows = c.execute("SELECT seq, stream, text FROM lines WHERE job_id=? AND seq>=? ORDER BY seq", (job_id, since_seq)).fetchall()
            return [{"seq": r["seq"], "stream": r["stream"], "text": r["text"]} for r in rows]
        finally: c.close()
