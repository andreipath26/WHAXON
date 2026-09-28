"""Tests for the portfwd server endpoints.

The portfwd endpoints (GET/POST/DELETE on /api/msf/sessions/<id>/portfwd)
delegate to whaxon.core.portfwd's free functions. Those functions walk
client.connect().sessions.session(id) to reach a write/read handle — a
deep stack that's tedious to fake correctly.

These tests mock the three free functions instead:

    whaxon.core.portfwd.list_live
    whaxon.core.portfwd.add_forward
    whaxon.core.portfwd.remove_forward

That verifies the HTTP contract (validation, status codes, response shape)
without pulling in the RPC plumbing. The portfwd functions themselves are
not exercised here.
"""
from __future__ import annotations

from whaxon.core import Core
from whaxon.core import portfwd as _pf
from whaxon.interfaces.web.server import (
    AsyncRunner,
    JobRegistry,
    create_app,
)


class _FakeMSF:
    def is_up(self):
        return True

    def sessions(self):
        return {}

    def version(self):
        return "6.5.3"


def _make_app(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    monkeypatch.delenv("WHAXON_AUTH_USER", raising=False)
    monkeypatch.delenv("WHAXON_AUTH_PASS_HASH", raising=False)
    core = Core(data_dir=tmp_path)
    monkeypatch.setattr(core, "msf", _FakeMSF())
    registry = JobRegistry(core)
    runner = AsyncRunner(core)
    app = create_app(core, registry, runner)
    app.config["TESTING"] = True
    return app, core


# ---------------------------------------------------------------- GET list

def test_pf_list_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(_pf, "list_live", lambda client, sid: [])
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().get("/api/msf/sessions/1/portfwd")
    assert r.status_code == 200
    data = r.get_json()
    assert data["session_id"] == "1"
    assert data["live"] == []


def test_pf_list_returns_rows(tmp_path, monkeypatch):
    rows = [{"pid": 4242, "lport": 8080, "rhost": "10.0.0.9", "rport": 80,
             "cmd": "socat TCP-LISTEN:8080,fork TCP:10.0.0.9:80"}]
    monkeypatch.setattr(_pf, "list_live", lambda client, sid: rows)
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().get("/api/msf/sessions/1/portfwd")
    assert r.status_code == 200
    data = r.get_json()
    assert data["live"] == rows


def test_pf_list_error_is_swallowed(tmp_path, monkeypatch):
    """If list_live raises, the endpoint returns 200 with error + empty list."""
    def boom(client, sid):
        raise RuntimeError("connection lost")
    monkeypatch.setattr(_pf, "list_live", boom)
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().get("/api/msf/sessions/1/portfwd")
    assert r.status_code == 200
    data = r.get_json()
    assert data["live"] == []
    assert "connection lost" in data["error"]


# ---------------------------------------------------------------- POST add

def test_pf_add_missing_fields(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().post("/api/msf/sessions/1/portfwd", json={"lport": 8080})
    assert r.status_code == 400
    assert "required" in r.get_json()["error"]


def test_pf_add_missing_rhost_only(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().post("/api/msf/sessions/1/portfwd",
                               json={"lport": 8080, "rport": 80})
    assert r.status_code == 400


def test_pf_add_calls_add_forward_and_returns_dict(tmp_path, monkeypatch):
    calls = []

    def fake_add(client, session_id, lport, rhost, rport, label):
        calls.append((session_id, lport, rhost, rport, label))
        return _pf.Forward(session_id=str(session_id), lport=int(lport),
                           rhost=str(rhost), rport=int(rport), label=label)

    monkeypatch.setattr(_pf, "add_forward", fake_add)
    app, core = _make_app(tmp_path, monkeypatch)
    r = app.test_client().post("/api/msf/sessions/7/portfwd",
                               json={"lport": 8080, "rhost": "10.0.0.9",
                                     "rport": 80, "label": "web"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["session_id"] == "7"
    assert data["lport"] == 8080
    assert data["rhost"] == "10.0.0.9"
    assert data["rport"] == 80
    assert data["label"] == "web"
    assert calls == [("7", 8080, "10.0.0.9", 80, "web")]
    # pivot edge was written
    conn = core.store._conn()
    try:
        edges = _pf.__dict__.get("_dummy")  # noqa
        from whaxon.core import pivot
        edges = pivot.list_edges(conn)
    finally:
        conn.close()
    assert any(e["parent"]["id"] == "7" and e["relation"] == "tunnels_via"
               for e in edges)


def test_pf_add_error_returns_500(tmp_path, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("socat not found on target")
    monkeypatch.setattr(_pf, "add_forward", boom)
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().post("/api/msf/sessions/1/portfwd",
                               json={"lport": 8080, "rhost": "10.0.0.9", "rport": 80})
    assert r.status_code == 500
    assert "socat" in r.get_json()["error"]


# ---------------------------------------------------------------- DELETE remove

def test_pf_del_missing_lport(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().delete("/api/msf/sessions/1/portfwd", json={})
    assert r.status_code == 400
    assert "lport required" in r.get_json()["error"]


def test_pf_del_success(tmp_path, monkeypatch):
    captured = []

    def fake_remove(client, fwd):
        captured.append(fwd)
        return {"ok": True, "method": "pid", "pid": 4242}

    monkeypatch.setattr(_pf, "remove_forward", fake_remove)
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().delete("/api/msf/sessions/3/portfwd",
                                 json={"lport": 8080})
    assert r.status_code == 200
    assert r.get_json() == {"ok": True, "method": "pid", "pid": 4242}
    assert len(captured) == 1
    fwd = captured[0]
    assert fwd.session_id == "3"
    assert fwd.lport == 8080