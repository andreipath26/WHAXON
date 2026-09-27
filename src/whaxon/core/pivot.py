"""Pivot graph — track exploit -> session -> forward chains."""
from __future__ import annotations
import time
from typing import Any

KINDS = ("exploit", "session", "forward")
RELATIONS = ("from_exploit", "tunnels_via", "reached_through")


def ensure_table(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS pivot_edges (id INTEGER PRIMARY KEY AUTOINCREMENT, parent_kind TEXT NOT NULL, parent_id TEXT NOT NULL, child_kind TEXT NOT NULL, child_id TEXT NOT NULL, relation TEXT NOT NULL, evidence TEXT, created_at REAL NOT NULL)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pivot_parent ON pivot_edges(parent_kind, parent_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pivot_child ON pivot_edges(child_kind, child_id)")
    conn.commit()


def add_edge(conn, parent_kind, parent_id, child_kind, child_id, relation, evidence=""):
    if parent_kind not in KINDS or child_kind not in KINDS: return
    if relation not in RELATIONS: return
    ensure_table(conn)
    row = conn.execute(
        "SELECT 1 FROM pivot_edges WHERE parent_kind=? AND parent_id=? AND child_kind=? AND child_id=? AND relation=? LIMIT 1",
        (parent_kind, str(parent_id), child_kind, str(child_id), relation)
    ).fetchone()
    if row is not None:
        return
    conn.execute("INSERT INTO pivot_edges (parent_kind, parent_id, child_kind, child_id, relation, evidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (parent_kind, str(parent_id), child_kind, str(child_id), relation, evidence, time.time()))
    conn.commit()


def list_edges(conn):
    ensure_table(conn)
    rows = conn.execute("SELECT parent_kind, parent_id, child_kind, child_id, relation, evidence, created_at FROM pivot_edges ORDER BY created_at ASC").fetchall()
    return [{"parent": {"kind": r[0], "id": r[1]}, "child": {"kind": r[2], "id": r[3]}, "relation": r[4], "evidence": r[5] or "", "created_at": r[6]} for r in rows]


def _adjacency(edges):
    adj = {}
    for e in edges:
        key = (e["parent"]["kind"], e["parent"]["id"])
        adj.setdefault(key, []).append(e)
    return adj


def graph(conn):
    edges = list_edges(conn)
    return {"edges": edges, "count": len(edges)}


def chain_for_session(conn, session_id):
    edges = list_edges(conn)
    adj = _adjacency(edges)
    root_exploits = [e for e in edges if e["child"] == {"kind": "session", "id": str(session_id)} and e["relation"] == "from_exploit"]
    descendants = []
    stack = [("session", str(session_id))]
    seen = set()
    while stack:
        node = stack.pop()
        if node in seen: continue
        seen.add(node)
        for e in adj.get(node, []):
            descendants.append(e)
            stack.append((e["child"]["kind"], e["child"]["id"]))
    return {"session_id": str(session_id), "root_exploits": root_exploits, "descendants": descendants}
