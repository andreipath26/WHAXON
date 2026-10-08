"""Approval queue — v2 of docs/agent-architecture.md §16."""
from __future__ import annotations

from pathlib import Path

from whaxon.core import Core
from whaxon.core.store import JobStore
from whaxon.interfaces.web.server import AsyncRunner, JobRegistry, create_app


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


# ---------- store ----------

def test_create_ai_run_default_owner(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-1", "goal")
    r = s.get_ai_run("ai-1")
    assert r["owner"] == "local"


def test_create_ai_run_custom_owner(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-2", "goal", owner="alice")
    r = s.get_ai_run("ai-2")
    assert r["owner"] == "alice"


def test_list_pending_only_waiting(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-a", "g", owner="alice")
    s.set_ai_run_waiting("ai-a", '{"q": "?"}')
    s.create_ai_run("ai-b", "g", owner="alice")  # still running
    pending = s.list_pending_runs(owner="alice")
    assert [r["id"] for r in pending] == ["ai-a"]


def test_list_pending_filters_by_owner(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-a", "g", owner="alice")
    s.set_ai_run_waiting("ai-a", "{}")
    s.create_ai_run("ai-b", "g", owner="bob")
    s.set_ai_run_waiting("ai-b", "{}")
    assert [r["id"] for r in s.list_pending_runs(owner="alice")] == ["ai-a"]
    assert [r["id"] for r in s.list_pending_runs(owner="bob")] == ["ai-b"]
    assert {r["id"] for r in s.list_pending_runs()} == {"ai-a", "ai-b"}


def test_add_and_list_approvals(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-1", "g")
    s.add_approval("ai-1", 1, "alice", "y", "ok")
    s.add_approval("ai-1", 2, "bob", "n", "nope")
    rows = s.list_approvals("ai-1")
    assert len(rows) == 2
    assert rows[0]["user"] == "alice"
    assert rows[0]["answer"] == "y"
    assert rows[1]["user"] == "bob"
    assert rows[1]["note"] == "nope"


def test_add_approval_replace_same_seq(tmp_path: Path) -> None:
    s = JobStore(tmp_path / "db.sqlite")
    s.create_ai_run("ai-1", "g")
    s.add_approval("ai-1", 1, "alice", "y")
    s.add_approval("ai-1", 1, "alice", "n")  # replaces
    rows = s.list_approvals("ai-1")
    assert len(rows) == 1
    assert rows[0]["answer"] == "n"


# ---------- API ----------

def test_api_pending_empty(tmp_path, monkeypatch) -> None:
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().get("/api/ai/pending")
    assert r.status_code == 200
    assert r.get_json() == []


def test_api_pending_returns_waiting(tmp_path, monkeypatch) -> None:
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-p", "goal", owner="alice")
    core.store.set_ai_run_waiting("ai-p", '{"q": "?"}')
    r = app.test_client().get("/api/ai/pending")
    assert r.status_code == 200
    data = r.get_json()
    assert len(data) == 1
    assert data[0]["id"] == "ai-p"


def test_api_pending_filter_by_owner(tmp_path, monkeypatch) -> None:
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-a", "g", owner="alice")
    core.store.set_ai_run_waiting("ai-a", "{}")
    core.store.create_ai_run("ai-b", "g", owner="bob")
    core.store.set_ai_run_waiting("ai-b", "{}")
    r = app.test_client().get("/api/ai/pending?owner=alice")
    assert [x["id"] for x in r.get_json()] == ["ai-a"]


def test_api_answer_requires_body(tmp_path, monkeypatch) -> None:
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-a", "g")
    core.store.set_ai_run_waiting("ai-a", "{}")
    r = app.test_client().post("/api/ai/runs/ai-a/answer", json={})
    assert r.status_code == 400


def test_api_answer_404_unknown_run(tmp_path, monkeypatch) -> None:
    app, _ = _make_app(tmp_path, monkeypatch)
    r = app.test_client().post("/api/ai/runs/nope/answer", json={"answer": "y"})
    assert r.status_code == 404


def test_api_answer_409_not_waiting(tmp_path, monkeypatch) -> None:
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-r", "g")  # status running
    r = app.test_client().post("/api/ai/runs/ai-r/answer", json={"answer": "y"})
    assert r.status_code == 409


def test_api_answer_records_approval(tmp_path, monkeypatch) -> None:
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-a", "g", owner="alice")
    core.store.set_ai_run_waiting("ai-a", '{"q": "?"}')
    r = app.test_client().post(
        "/api/ai/runs/ai-a/answer",
        json={"answer": "y", "user": "alice", "note": "ok"},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["run_id"] == "ai-a"
    rows = core.store.list_approvals("ai-a")
    assert len(rows) == 1
    assert rows[0]["user"] == "alice"
    assert rows[0]["answer"] == "y"
    assert rows[0]["note"] == "ok"


def test_api_answer_default_user(tmp_path, monkeypatch) -> None:
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create_ai_run("ai-a", "g")
    core.store.set_ai_run_waiting("ai-a", "{}")
    r = app.test_client().post("/api/ai/runs/ai-a/answer", json={"answer": "skip"})
    assert r.status_code == 200
    rows = core.store.list_approvals("ai-a")
    assert rows[0]["user"] == "local"