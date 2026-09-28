"""Tests for report.attach_chains — the pivot-chain collector.

Extracted from server.py in this session. Behaviour contract:
  - returns [] on empty store
  - returns [] when there are no from_exploit -> session edges
  - returns one entry per root exploit, each with root + descendants
  - swallows exceptions and returns [] on failure
"""
from __future__ import annotations

from whaxon.core import pivot
from whaxon.core.report import attach_chains
from whaxon.core.store import JobStore


def _store(tmp_path):
    return JobStore(tmp_path / "test.db")


def test_empty_store_returns_empty(tmp_path):
    assert attach_chains(_store(tmp_path)) == []


def test_no_pivot_edges_returns_empty(tmp_path):
    store = _store(tmp_path)
    conn = store._conn()
    try:
        pivot.ensure_table(conn)
    finally:
        conn.close()
    assert attach_chains(store) == []


def test_session_without_from_exploit_is_ignored(tmp_path):
    store = _store(tmp_path)
    conn = store._conn()
    try:
        pivot.add_edge(conn, "session", "1", "forward", "99", "tunnels_via", "10.0.0.5:8080")
    finally:
        conn.close()
    assert attach_chains(store) == []


def test_one_exploit_to_session_produces_one_chain(tmp_path):
    store = _store(tmp_path)
    conn = store._conn()
    try:
        pivot.add_edge(conn, "exploit", "abc", "session", "1", "from_exploit", "smb")
    finally:
        conn.close()
    chains = attach_chains(store)
    assert len(chains) == 1
    c = chains[0]
    assert c["root"] == {"kind": "exploit", "id": "abc"}
    assert isinstance(c["descendants"], list)


def test_chain_root_is_parent_of_session_edge(tmp_path):
    store = _store(tmp_path)
    conn = store._conn()
    try:
        pivot.add_edge(conn, "exploit", "xyz", "session", "5", "from_exploit", "ssh")
        pivot.add_edge(conn, "session", "5", "forward", "6", "tunnels_via", "10.0.0.9:22")
    finally:
        conn.close()
    chains = attach_chains(store)
    assert len(chains) == 1
    assert chains[0]["root"]["id"] == "xyz"
    # descendant list contains the session->forward edge
    children = [d.get("child", {}).get("id") for d in chains[0]["descendants"]]
    assert "6" in children
