"""Tests for whaxon.interfaces.web.server — the Flask API.

Session 1 of 3: covers non-MSF, non-AI endpoints. MSF and AI endpoints
require mock clients and are covered in tests/test_server_msf.py and
tests/test_server_ai.py (not yet written).

Auth note: the server's `_auth_gate` skips auth for loopback requests
(remote_addr in 127.0.0.1/::1/None). Flask's test_client() defaults to
None, so auth is off by default in these tests. To test the auth path,
pass `environ_base={"REMOTE_ADDR": "10.0.0.1"}` to each request.

Known bug found while writing these tests: server.py defines two
`/api/health` routes (lines 326 and 347 in the commit prior to this
file). Flask keeps only the last one. The richer readiness probe
(MSF check + data dir writability) is unreachable. See the commit
message for details.
"""
from __future__ import annotations

import hashlib
import json

from whaxon.core import Core
from whaxon.interfaces.web.server import (
    AsyncRunner,
    JobRegistry,
    create_app,
)

# ---------------------------------------------------------------- helpers

def _make_app(tmp_path, monkeypatch, auth=False):
    """Build a Flask app for testing. Returns (app, core).

    If auth=True, sets credentials AND leaves remote_addr as loopback
    so `_auth_gate` still skips. To force the auth check, requests must
    set environ_base={"REMOTE_ADDR": "10.0.0.1"}.
    """
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    if auth:
        monkeypatch.setenv("WHAXON_AUTH_USER", "testuser")
        monkeypatch.setenv(
            "WHAXON_AUTH_PASS_HASH",
            hashlib.sha256(b"testpass").hexdigest(),
        )
    else:
        monkeypatch.delenv("WHAXON_AUTH_USER", raising=False)
        monkeypatch.delenv("WHAXON_AUTH_PASS_HASH", raising=False)

    core = Core(data_dir=tmp_path)
    registry = JobRegistry(core)
    runner = AsyncRunner(core)
    app = create_app(core, registry, runner)
    app.config["TESTING"] = True
    return app, core


def _seed_job(core, job_id="j1", findings=None, status="finished"):
    store = core.store
    store.create(job_id)
    store.set_started(job_id, "nmap", "10.0.0.5")
    for i, f in enumerate(findings or []):
        store.append_finding(job_id, f, i)
    if status == "finished":
        store.set_finished(job_id, 0, 0.1)
    elif status == "failed":
        store.set_failed(job_id, "boom")
    return job_id


def _finding(kind="open_port", severity="high", port=22):
    return {
        "kind": kind,
        "severity": severity,
        "source": "nmap",
        "data": {"port": port},
        "raw_line": f"{port}/tcp open",
    }


# ---------------------------------------------------------------- /api/health

def test_health_reachable(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/health")
    assert r.status_code in (200, 503)
    data = r.get_json()
    assert "status" in data
    assert "checks" in data


# ---------------------------------------------------------------- /api/tools

def test_tools_lists_catalog(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/tools")
    assert r.status_code == 200
    data = r.get_json()
    assert isinstance(data, list)
    for tool in data:
        assert "id" in tool
        assert "available" in tool


# ---------------------------------------------------------------- /api/history

def test_history_empty(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/history")
    assert r.status_code == 200
    assert r.get_json() == []


def test_history_returns_finished_jobs(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    _seed_job(core, "j2")
    client = app.test_client()
    r = client.get("/api/history")
    assert r.status_code == 200
    data = r.get_json()
    ids = {e["id"] for e in data}
    assert ids == {"j1", "j2"}


# ---------------------------------------------------------------- /api/jobs/<id>

def test_job_detail(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    client = app.test_client()
    r = client.get("/api/jobs/j1")
    assert r.status_code == 200
    data = r.get_json()
    assert data["id"] == "j1"
    assert data["tool"] == "nmap"
    assert data["target"] == "10.0.0.5"


def test_job_not_found(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/jobs/missing")
    assert r.status_code == 404


def test_job_findings(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding(port=22), _finding(port=80)])
    client = app.test_client()
    r = client.get("/api/jobs/j1/findings")
    assert r.status_code == 200
    data = r.get_json()
    assert len(data) == 2
    assert {f["data"]["port"] for f in data} == {22, 80}


# ---------------------------------------------------------------- /api/report

def test_report_md(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    r = client.get("/api/report?format=md")
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert "# WHAXON Engagement Report" in text


def test_report_json(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    r = client.get("/api/report?format=json")
    assert r.status_code == 200
    data = r.get_json()
    assert "job_count" in data
    assert data["job_count"] == 1
    assert "chains" in data


def test_report_fmt_alias_matches_format(tmp_path, monkeypatch):
    """?fmt= and ?format= must return the same payload (the alias fix)."""
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    a = client.get("/api/report?format=json").get_data()
    b = client.get("/api/report?fmt=json").get_data()
    da = json.loads(a)
    db = json.loads(b)
    da.pop("generated", None)
    db.pop("generated", None)
    assert da == db


def test_report_whaxon_envelope(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    r = client.get("/api/report?format=whaxon")
    assert r.status_code == 200
    env = json.loads(r.get_data(as_text=True))
    assert env["format"] == "whaxon"
    assert env["version"] == 1
    assert env["tool"].startswith("whaxon/")
    assert env["engagement"] == "default"
    assert env["integrity"].startswith("sha256:")
    assert "payload" in env


def test_report_whaxon_integrity_matches_payload(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    r = client.get("/api/report?format=whaxon")
    env = json.loads(r.get_data(as_text=True))
    canonical = json.dumps(env["payload"], default=str, sort_keys=True)
    expected = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert env["integrity"] == expected


# ---------------------------------------------------------------- /api/jobs/<id>/report

def test_per_job_report_md(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    r = client.get("/api/jobs/j1/report?format=md")
    assert r.status_code == 200
    assert r.get_data(as_text=True).startswith("# Job j1")


def test_per_job_report_fmt_alias(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    a = client.get("/api/jobs/j1/report?format=md").get_data(as_text=True)
    b = client.get("/api/jobs/j1/report?fmt=md").get_data(as_text=True)
    assert a == b


# ---------------------------------------------------------------- /api/scope

def test_scope_get(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/scope")
    assert r.status_code == 200
    data = r.get_json()
    assert "enabled" in data or "in_scope" in data


def test_scope_check_localhost_allowed(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.post("/api/scope/check", json={"target": "127.0.0.1"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["allowed"] is True


def test_scope_check_public_denied(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.post("/api/scope/check", json={"target": "8.8.8.8"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["allowed"] is False


# ---------------------------------------------------------------- /api/loot, /api/tree, /api/pivot

def test_loot_empty(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/loot")
    assert r.status_code == 200
    data = r.get_json()
    assert data["loot"] == []
    assert data["count"] == 0


def test_tree_empty(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/tree")
    assert r.status_code == 200


def test_pivot_graph_empty(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/pivot/graph")
    assert r.status_code == 200
    data = r.get_json()
    assert data["count"] == 0


# ---------------------------------------------------------------- /api/settings

def test_settings_get(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/settings")
    assert r.status_code == 200


# ---------------------------------------------------------------- UI routes

def test_ui_renders(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/ui")
    assert r.status_code == 200
    assert b"WHAXON" in r.get_data()


def test_root_redirects_to_ui(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/")
    assert r.status_code in (301, 302)


# ---------------------------------------------------------------- auth path

def test_auth_required_when_non_loopback_and_creds_set(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch, auth=True)
    client = app.test_client()
    r = client.get("/api/tools", environ_base={"REMOTE_ADDR": "10.0.0.1"})
    assert r.status_code == 401


def test_auth_accepts_correct_basic(tmp_path, monkeypatch):
    import base64
    app, _ = _make_app(tmp_path, monkeypatch, auth=True)
    client = app.test_client()
    creds = base64.b64encode(b"testuser:testpass").decode()
    r = client.get(
        "/api/tools",
        environ_base={"REMOTE_ADDR": "10.0.0.1"},
        headers={"Authorization": f"Basic {creds}"},
    )
    assert r.status_code == 200


def test_auth_rejects_wrong_password(tmp_path, monkeypatch):
    import base64
    app, _ = _make_app(tmp_path, monkeypatch, auth=True)
    client = app.test_client()
    creds = base64.b64encode(b"testuser:wrong").decode()
    r = client.get(
        "/api/tools",
        environ_base={"REMOTE_ADDR": "10.0.0.1"},
        headers={"Authorization": f"Basic {creds}"},
    )
    assert r.status_code == 401


def test_auth_skipped_for_loopback(tmp_path, monkeypatch):
    """Auth gate lets loopback through even with credentials set."""
    app, _ = _make_app(tmp_path, monkeypatch, auth=True)
    client = app.test_client()
    r = client.get("/api/tools")  # no Authorization header
    assert r.status_code == 200