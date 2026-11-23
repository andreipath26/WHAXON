"""Durable, transport-neutral Engine V2 AI advisory ledger.

AI advice is untrusted text, never an approval, tool invocation, verified
finding, or workflow execution request. Network ingress and OAuth are separate
trusted adapters; this module does not authenticate external callers.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ALLOWED_DECISIONS = frozenset({"reviewed", "dismissed"})


def _identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _message(name: str, value: str) -> str:
    if (
        not isinstance(value, str) or not value.strip()
        or len(value.encode("utf-8")) > 12000
        or any(ord(c) < 32 and c not in "\r\n\t" for c in value)
    ):
        raise ValueError(f"{name} must be 1–12000 bytes of safe text")
    return value


class AIAdvisoryLedger:
    """Persistence for advisory-only messages from authenticated MCP clients.

    The outer adapter MUST authenticate provider, OAuth client and owner; none
    of these are trusted when supplied by arbitrary HTTP/request bodies.
    """

    def __init__(self, store):
        self.store = store
        with store._lock:
            conn = store._conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS ai_advisory_requests (
                        id TEXT PRIMARY KEY,
                        mission_id TEXT NOT NULL,
                        plan_id TEXT,
                        plan_digest TEXT,
                        provider_id TEXT NOT NULL,
                        client_id TEXT NOT NULL,
                        request_key TEXT NOT NULL,
                        request_digest TEXT NOT NULL,
                        prompt TEXT NOT NULL,
                        response_id TEXT,
                        response_digest TEXT,
                        response_text TEXT,
                        status TEXT NOT NULL DEFAULT 'awaiting_reply',
                        reviewer TEXT,
                        reviewed_at REAL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        replied_at REAL,
                        UNIQUE(provider_id,client_id,request_key)
                    );
                    CREATE INDEX IF NOT EXISTS ai_advisory_mission_idx
                        ON ai_advisory_requests(mission_id,created_at);
                    CREATE TABLE IF NOT EXISTS ai_advisory_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_id TEXT NOT NULL,
                        event TEXT NOT NULL,
                        detail_json TEXT NOT NULL,
                        created_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS ai_advisory_event_idx
                        ON ai_advisory_events(request_id,id);
                """)
            finally:
                conn.close()

    @staticmethod
    def _public(row):
        if row is None:
            return None
        item = dict(row)
        item["transport_authenticated"] = False
        item["model_inference_verified"] = False
        item["execution_authorized"] = False
        return item

    @staticmethod
    def _event(conn, request_id: str, event: str, detail: dict, now: float):
        conn.execute(
            "INSERT INTO ai_advisory_events "
            "(request_id,event,detail_json,created_at) VALUES (?,?,?,?)",
            (request_id, event, json.dumps(detail, sort_keys=True), now),
        )

    def create_request(
        self, *, mission_id: str, provider_id: str, client_id: str,
        request_key: str, prompt: str, plan_id: str | None = None,
        ttl_seconds: int = 86400,
    ) -> dict:
        """Persist an outbound question without contacting any provider."""
        for name, value in (
            ("mission_id", mission_id), ("provider_id", provider_id),
            ("client_id", client_id), ("request_key", request_key),
        ):
            _identifier(name, value)
        _message("prompt", prompt)
        if plan_id is not None:
            _identifier("plan_id", plan_id)
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 86400:
            raise ValueError("ttl_seconds must be between 60 and 86400")
        digest = hashlib.sha256(
            json.dumps([mission_id, plan_id, prompt, ttl_seconds],
                       separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        now = time.time()
        with self.store._lock:
            conn = self.store._conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                mission = conn.execute(
                    "SELECT 1 FROM missions WHERE id=?", (mission_id,),
                ).fetchone()
                if mission is None:
                    raise ValueError("unknown mission")
                plan_digest = None
                if plan_id is not None:
                    plan = conn.execute(
                        "SELECT mission_id,digest FROM workflow_plans WHERE id=?",
                        (plan_id,),
                    ).fetchone()
                    if plan is None or plan["mission_id"] != mission_id:
                        raise ValueError("plan is not bound to this mission")
                    plan_digest = plan["digest"]
                existing = conn.execute(
                    "SELECT * FROM ai_advisory_requests "
                    "WHERE provider_id=? AND client_id=? AND request_key=?",
                    (provider_id, client_id, request_key),
                ).fetchone()
                if existing is not None:
                    if (existing["request_digest"] != digest
                            or existing["plan_digest"] != plan_digest):
                        raise ValueError("conflicting advisory request idempotency key")
                    conn.execute("COMMIT")
                    return self._public(existing)
                request_id = uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO ai_advisory_requests "
                    "(id,mission_id,plan_id,plan_digest,provider_id,client_id,"
                    "request_key,request_digest,prompt,created_at,expires_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (request_id, mission_id, plan_id, plan_digest, provider_id,
                     client_id, request_key, digest, prompt, now, now+ttl_seconds),
                )
                self._event(conn, request_id, "advisory_created",
                            {"provider_id": provider_id, "client_id": client_id}, now)
                row = conn.execute(
                    "SELECT * FROM ai_advisory_requests WHERE id=?", (request_id,),
                ).fetchone()
                conn.execute("COMMIT")
                return self._public(row)
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def record_response(
        self, request_id: str, *, provider_id: str, client_id: str,
        response_id: str, response: str,
    ) -> dict:
        """Accept at most one identity-bound, immutable, untrusted reply."""
        for name, value in (
            ("request_id", request_id), ("provider_id", provider_id),
            ("client_id", client_id), ("response_id", response_id),
        ):
            _identifier(name, value)
        _message("response", response)
        digest = hashlib.sha256(response.encode("utf-8")).hexdigest()
        now = time.time()
        with self.store._lock:
            conn = self.store._conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM ai_advisory_requests WHERE id=? "
                    "AND provider_id=? AND client_id=?",
                    (request_id, provider_id, client_id),
                ).fetchone()
                if row is None:
                    raise ValueError("unknown advisory for this provider/client")
                if row["response_id"] is not None:
                    if row["response_id"] != response_id or row["response_digest"] != digest:
                        raise ValueError("conflicting or replayed advisory response")
                    conn.execute("COMMIT")
                    return self._public(row)
                if row["expires_at"] <= now:
                    raise ValueError("advisory request expired")
                if row["status"] != "awaiting_reply":
                    raise ValueError("advisory request is no longer awaiting reply")
                if row["plan_id"] is not None:
                    plan = conn.execute(
                        "SELECT mission_id,digest FROM workflow_plans WHERE id=?",
                        (row["plan_id"],),
                    ).fetchone()
                    if (plan is None or plan["mission_id"] != row["mission_id"]
                            or plan["digest"] != row["plan_digest"]):
                        raise ValueError("advisory source plan identity changed")
                conn.execute(
                    "UPDATE ai_advisory_requests SET response_id=?,"
                    "response_digest=?,response_text=?,status='pending_review',"
                    "replied_at=? WHERE id=? AND status='awaiting_reply'",
                    (response_id, digest, response, now, request_id),
                )
                self._event(conn, request_id, "advisory_received",
                            {"response_digest": digest}, now)
                result = conn.execute(
                    "SELECT * FROM ai_advisory_requests WHERE id=?", (request_id,),
                ).fetchone()
                conn.execute("COMMIT")
                return self._public(result)
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def decide(self, request_id: str, *, reviewer: str, decision: str) -> dict:
        """Record a human disposition; even 'reviewed' grants ZERO permissions."""
        _identifier("request_id", request_id)
        _identifier("reviewer", reviewer)
        if decision not in _ALLOWED_DECISIONS:
            raise ValueError("decision must be reviewed or dismissed")
        now = time.time()
        with self.store._lock:
            conn = self.store._conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM ai_advisory_requests WHERE id=?", (request_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("unknown advisory")
                if row["status"] == decision and row["reviewer"] == reviewer:
                    conn.execute("COMMIT")
                    return self._public(row)
                if row["status"] != "pending_review":
                    raise ValueError("advisory has no pending review")
                conn.execute(
                    "UPDATE ai_advisory_requests SET status=?,reviewer=?,"
                    "reviewed_at=? WHERE id=? AND status='pending_review'",
                    (decision, reviewer, now, request_id),
                )
                self._event(conn, request_id, "advisory_" + decision,
                            {"reviewer": reviewer}, now)
                result = conn.execute(
                    "SELECT * FROM ai_advisory_requests WHERE id=?", (request_id,),
                ).fetchone()
                conn.execute("COMMIT")
                return self._public(result)
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def get(self, request_id: str, *, provider_id: str | None = None,
            client_id: str | None = None) -> dict | None:
        """Read through an already-authenticated caller's identity context."""
        _identifier("request_id", request_id)
        if (provider_id is None) != (client_id is None):
            raise ValueError("provider and client must be scoped together")
        if provider_id is not None:
            _identifier("provider_id", provider_id)
            _identifier("client_id", client_id)
        conn = self.store._conn()
        try:
            if provider_id is None:
                row = conn.execute(
                    "SELECT * FROM ai_advisory_requests WHERE id=?", (request_id,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM ai_advisory_requests "
                    "WHERE id=? AND provider_id=? AND client_id=?",
                    (request_id, provider_id, client_id),
                ).fetchone()
            return self._public(row)
        finally:
            conn.close()

    def list_mission(self, mission_id: str, *, limit: int = 100) -> list[dict]:
        """Trusted local operator view only; not a remotely exposed endpoint."""
        _identifier("mission_id", mission_id)
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("limit must be in [1,200]")
        conn = self.store._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM ai_advisory_requests WHERE mission_id=? "
                "ORDER BY created_at DESC,id DESC LIMIT ?",
                (mission_id, limit),
            ).fetchall()
            return [self._public(row) for row in rows]
        finally:
            conn.close()

    def events(self, request_id: str) -> list[dict]:
        """Local read-only audit sequence, not an independent trust anchor."""
        _identifier("request_id", request_id)
        conn = self.store._conn()
        try:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM ai_advisory_events WHERE request_id=? ORDER BY id",
                (request_id,),
            ).fetchall()]
        finally:
            conn.close()
