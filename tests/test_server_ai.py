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

import json
import time
from types import SimpleNamespace

from whaxon.ai.actions import Action, ActionResult
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


def test_ai_run_requires_operator_opt_in_and_points_to_v2(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    response = app.test_client().post(
        "/api/ai/run", json={
            "goal": "scan 127.0.0.1",
            "legacy_execution_enabled": True,
        },
    )
    assert response.status_code == 410
    data = response.get_json()
    assert data["legacy_execution_enabled"] is False
    assert data["v2_proposal_endpoint"] == "/api/v2/ai/proposals"
    assert data["approval_granted"] is False
    assert data["execution_submitted"] is False
    assert "mission_id" in data["error"] and "exact target" in data["error"]
    assert core.store.list_ai_runs() == []

def test_ai_run_requires_a_resolvable_target(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    response = app.test_client().post(
        "/api/ai/run",
        json={"goal": "review the security posture"},
    )
    assert response.status_code == 400
    assert "target required" in response.get_json()["error"]
    assert core.store.list_ai_runs() == []


def test_ai_run_rejects_non_string_target(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    response = app.test_client().post(
        "/api/ai/run",
        json={"target": 127001, "goal": "assess the local target"},
    )
    assert response.status_code == 400
    assert "target must be a string" in response.get_json()["error"]
    assert core.store.list_ai_runs() == []


def test_ai_run_rejects_nul_target(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    response = app.test_client().post(
        "/api/ai/run",
        json={"target": "127.0.0.1\x00evil", "goal": "assess the local target"},
    )
    assert response.status_code == 400
    assert "exceeds allowed limits" in response.get_json()["error"]
    assert core.store.list_ai_runs() == []


def test_ai_run_rejects_out_of_scope_target_server_side(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    response = app.test_client().post(
        "/api/ai/run",
        json={"target": "https://example.com", "goal": "assess this target"},
    )
    assert response.status_code == 403
    assert "out of scope" in response.get_json()["error"]
    assert core.store.list_ai_runs() == []


def test_ai_run_fails_closed_when_scope_check_raises(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)

    def broken_scope_check(_target):
        raise RuntimeError("scope file unavailable")

    monkeypatch.setattr(core.scope, "check", broken_scope_check)
    response = app.test_client().post(
        "/api/ai/run",
        json={"target": "127.0.0.1", "goal": "assess the local target"},
    )
    assert response.status_code == 503
    assert "scope evaluation failed" in response.get_json()["error"]
    assert core.store.list_ai_runs() == []


def test_ai_run_answer_records_operator_response(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_LEGACY_AI_EXECUTION_ENABLED", "true")
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-waiting", "review an authorized target")
    core.store.set_ai_run_waiting(
        "ai-waiting",
        json.dumps({"rationale": "Confirm next phase", "proposed_phase": "enum"}),
    )

    response = app.test_client().post(
        "/api/ai/runs/ai-waiting/answer",
        json={"answer": "yes", "user": "operator", "note": "Approved in UI"},
    )
    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    run = core.store.get_ai_run("ai-waiting")
    assert run["status"] == "running"
    assert run["pending_question"] in ("", None)
    approvals = core.store.list_approvals("ai-waiting")
    assert len(approvals) == 1
    assert approvals[0]["answer"] == "yes"
    assert approvals[0]["user"] == "local"  # JSON-supplied identity is not trusted


def test_ai_run_answer_is_default_denied_without_mutating_waiting_run(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-waiting", "review an authorized target")
    core.store.set_ai_run_waiting(
        "ai-waiting",
        json.dumps({"rationale": "Confirm next phase", "proposed_phase": "enum"}),
    )
    before = core.store.get_ai_run("ai-waiting")

    response = app.test_client().post(
        "/api/ai/runs/ai-waiting/answer",
        json={"answer": "yes", "user": "operator", "note": "Approved in UI"},
    )

    assert response.status_code == 410
    assert response.get_json()["legacy_execution_enabled"] is False
    assert response.get_json()["approval_granted"] is False
    after = core.store.get_ai_run("ai-waiting")
    assert after["status"] == before["status"] == "waiting"
    assert after["pending_question"] == before["pending_question"]
    assert core.store.list_approvals("ai-waiting") == []


def test_ai_run_waits_for_real_operator_answer_with_operator_opt_in(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_LEGACY_AI_EXECUTION_ENABLED", "true")
    app, core = _make_app(tmp_path, monkeypatch)

    class FakeExecutor:
        def __init__(self, ask_human):
            self.ask_human = ask_human
            self.agent = SimpleNamespace(provider=SimpleNamespace(name="test-provider"))
            self.on_result = lambda _result: None

        async def run(self, goal, job_id_prefix):
            action = Action.ask_human(
                "Confirm the proposed phase transition",
                proposed_phase="enum",
            )
            answer = await self.ask_human(action)
            self.on_result(ActionResult(action=action, ok=True, summary=action.rationale))
            ack_action = Action.stop(rationale=f"human answered: {answer!r}")
            self.on_result(ActionResult(action=ack_action, ok=True, summary=answer))
            return [
                ActionResult(action=action, ok=True, summary=action.rationale),
                ActionResult(action=ack_action, ok=True, summary=answer),
            ]

    def fake_build_executor(_core, **kwargs):
        return FakeExecutor(kwargs["ask_human"])

    monkeypatch.setattr("whaxon.core.ai_bridge.build_executor", fake_build_executor)
    client = app.test_client()
    response = client.post(
        "/api/ai/run",
        json={"target": "127.0.0.1", "goal": "inspect the authorized local target"},
    )
    assert response.status_code == 202
    run_id = response.get_json()["run_id"]

    deadline = time.monotonic() + 5
    pending = []
    while time.monotonic() < deadline:
        pending = client.get("/api/ai/pending").get_json()
        if any(item["id"] == run_id for item in pending):
            break
        time.sleep(0.02)
    assert any(item["id"] == run_id for item in pending)
    question = next(item["pending_question"] for item in pending if item["id"] == run_id)
    assert question["rationale"] == "Confirm the proposed phase transition"

    answered = client.post(
        f"/api/ai/runs/{run_id}/answer",
        json={"answer": "yes", "user": "operator", "note": "Confirmed"},
    )
    assert answered.status_code == 200

    deadline = time.monotonic() + 5
    run = None
    while time.monotonic() < deadline:
        run = client.get(f"/api/ai/runs/{run_id}").get_json()
        if run["status"] in ("done", "failed", "error"):
            break
        time.sleep(0.02)
    assert run is not None and run["status"] == "done"
    approvals = core.store.list_approvals(run_id)
    assert len(approvals) == 1
    assert approvals[0]["answer"] == "yes"
    assert len(run["steps"]) == 2



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
