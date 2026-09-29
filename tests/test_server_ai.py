"""Tests for AI, evidence, and error-path server endpoints.

Session 3 of 3 for server coverage. Complements:
  - tests/test_server.py      (non-MSF, non-AI)
  - tests/test_server_msf.py  (MSF with FakeMSF)
  - tests/test_server_portfwd.py (portfwd with mocked core.portfwd)

AI endpoints that spawn background threads (POST /api/ai/run, SSE stream)
are tested only for their synchronous parts: validation, response shape,
and the store's ai_runs table. We do not wait for the executor to finish.
"""
from __future__ import annotations

import hashlib

from whaxon.core import Core
from whaxon.interfaces.web.server import (
    AsyncRunner,
    JobRegistry,
    create_app,
)


def _make_app(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    monkeypatch.delenv("WHAXON_AUTH_USER", raising=False)
    monkeypatch.delenv("WHAXON_AUTH_PASS_HASH", raising=False)
    core = Core(data_dir=tmp_path)
    registry = JobRegistry(core)
    runner = AsyncRunner(core)
    app = create_app(core, registry, runner)
    app.config["TESTING"] = True
    return app, core


def _seed_job(core, job_id="j1", findings=None):
    store = core.store
    store.create(job_id)
    store.set_started(job_id, "nmap", "10.0.0.5")
    for i, f in enumerate(findings or []):
        store.append_finding(job_id, f, i)
    store.set_finished(job_id, 0, 0.1)
    return job_id


def _finding(kind="open_port", severity="high", port=22):
    return {
        "kind": kind, "severity": severity, "source": "nmap",
        "data": {"port": port}, "raw_line": f"{port}/tcp open",
    }


# ---------------------------------------------------------------- AI endpoints

def test_ai_run_missing_goal(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().post("/api/ai/run", json={})
    assert r.status_code == 400
    assert "goal required" in r.get_json()["error"]


def test_ai_run_accepts_goal(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    r = app.test_client().post("/api/ai/run", json={"goal": "scan 127.0.0.1"})
    assert r.status_code == 202
    data = r.get_json()
    assert "run_id" in data
    assert data["run_id"].startswith("ai-")
    # The store should have the run registered.
    stored = core.store.get_ai_run(data["run_id"])
    assert stored is not None
    assert stored["goal"] == "scan 127.0.0.1"


def test_ai_runs_list_empty(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().get("/api/ai/runs")
    assert r.status_code == 200
    assert r.get_json() == []


def test_ai_runs_list_includes_phase(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-phase", "test goal")
    r = app.test_client().get("/api/ai/runs")
    assert r.status_code == 200
    runs = r.get_json()
    assert isinstance(runs, list) and len(runs) >= 1
    match = [x for x in runs if x["id"] == "ai-phase"]
    assert len(match) == 1
    assert match[0]["phase"] == "recon"


def test_ai_runs_list_after_create(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-test1", "goal 1")
    core.store.create_ai_run("ai-test2", "goal 2")
    r = app.test_client().get("/api/ai/runs")
    assert r.status_code == 200
    data = r.get_json()
    ids = {e["id"] for e in data}
    assert {"ai-test1", "ai-test2"} <= ids


def test_ai_run_get_found(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-x", "some goal")
    r = app.test_client().get("/api/ai/runs/ai-x")
    assert r.status_code == 200
    data = r.get_json()
    assert data["id"] == "ai-x"
    assert data["goal"] == "some goal"


def test_ai_run_get_not_found(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().get("/api/ai/runs/nope")
    assert r.status_code == 404


def test_ai_stream_not_found(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().get("/api/ai/runs/nope/stream")
    assert r.status_code == 404


# ---------------------------------------------------------------- evidence

def test_evidence_list_empty(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    r = app.test_client().get("/api/jobs/j1/evidence")
    assert r.status_code == 200
    assert r.get_json() == []


def test_evidence_add_note(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    r = app.test_client().post("/api/jobs/j1/evidence",
                               json={"note": "confirmed weak cipher"})
    assert r.status_code == 201
    data = r.get_json()
    assert "seq" in data
    # list should now show one entry
    lst = app.test_client().get("/api/jobs/j1/evidence").get_json()
    assert len(lst) == 1
    assert lst[0]["note"] == "confirmed weak cipher"


def test_evidence_add_missing_body(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    r = app.test_client().post("/api/jobs/j1/evidence", json={})
    assert r.status_code == 400


def test_evidence_delete(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    r = app.test_client().post("/api/jobs/j1/evidence",
                               json={"note": "x"})
    seq = r.get_json()["seq"]
    d = app.test_client().delete(f"/api/jobs/j1/evidence/{seq}")
    assert d.status_code == 200
    assert d.get_json()["ok"] is True
    assert app.test_client().get("/api/jobs/j1/evidence").get_json() == []


def test_evidence_delete_missing(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    r = app.test_client().delete("/api/jobs/j1/evidence/999")
    assert r.status_code == 404


def test_evidence_download_note_returns_404(tmp_path, monkeypatch):
    """Notes have no file path — download must 404."""
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    r = app.test_client().post("/api/jobs/j1/evidence", json={"note": "not a file"})
    seq = r.get_json()["seq"]
    d = app.test_client().get(f"/api/jobs/j1/evidence/{seq}/download")
    assert d.status_code == 404


# ---------------------------------------------------------------- error paths

def test_output_txt_missing_job(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().get("/api/jobs/nope/output.txt")
    assert r.status_code == 404


def test_output_txt_present_job(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    core.store.append_line("j1", "stdout", "line A")
    core.store.append_line("j1", "stdout", "line B")
    r = app.test_client().get("/api/jobs/j1/output.txt")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "line A" in body
    assert "line B" in body


def test_findings_csv_content_type(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    r = app.test_client().get("/api/jobs/j1/findings.csv")
    assert r.status_code == 200
    assert "text/csv" in r.content_type
    body = r.get_data(as_text=True)
    assert "kind,severity,source" in body
    assert "open_port" in body


def test_findings_json(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    r = app.test_client().get("/api/jobs/j1/findings.json")
    assert r.status_code == 200
    import json as _j
    data = _j.loads(r.get_data(as_text=True))
    assert isinstance(data, list)
    assert data[0]["kind"] == "open_port"


def test_cancel_unknown_job(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().post("/api/jobs/nope/cancel")
    assert r.status_code == 200
    assert r.get_json()["ok"] is False