"""Engine V2 core readiness remains distinct from optional integration status."""
from types import SimpleNamespace

from whaxon.core import Core
from whaxon.interfaces.web.server import AsyncRunner, JobRegistry, create_app


def _client(tmp_path):
    core = Core(tmp_path)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    return app.test_client(), core


def test_e5_optional_msf_outage_does_not_mark_durable_core_unready(tmp_path):
    client, core = _client(tmp_path)
    core.msf = SimpleNamespace(is_up=lambda: False)
    response = client.get("/api/health")
    assert response.status_code == 200
    state = response.get_json()
    assert state["status"] == "ok"
    assert state["core_ready"] is True
    assert state["checks"]["database"] == "ready"
    assert state["checks"]["data"] == "writable"
    assert state["checks"]["msf"] == "down"
    assert state["optional_degraded"] == ["msf"]


def test_e5_external_worker_is_a_readiness_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_V2_EXTERNAL_WORKER", "1")
    client, core = _client(tmp_path)
    core.msf = SimpleNamespace(is_up=lambda: True)

    unavailable = client.get("/api/health")
    assert unavailable.status_code == 503
    assert unavailable.get_json()["checks"]["v2_worker"] == "unavailable"

    core.workflow_requests.set_worker_status("ready")
    connection = core.store._conn()
    try:
        connection.execute(
            "UPDATE workflow_worker_liveness SET heartbeat_at=0 WHERE id=1",
        )
        connection.execute(
            "UPDATE workflow_worker_instances SET heartbeat_at=0",
        )
    finally:
        connection.close()
    stale = client.get("/api/health")
    assert stale.status_code == 503

    core.workflow_requests.set_worker_status("ready")
    ready = client.get("/api/health")
    assert ready.status_code == 200
    assert ready.get_json()["checks"]["v2_worker"] == "ready"


def test_e5_readiness_tracks_each_worker_without_cross_instance_stop_race(tmp_path):
    core = Core(tmp_path)
    workers = core.workflow_requests
    workers.set_worker_status("ready", worker_id="worker-a")
    workers.set_worker_status("ready", worker_id="worker-b")

    workers.set_worker_status("stopped", worker_id="worker-a")
    assert workers.worker_is_ready()

    connection = core.store._conn()
    try:
        connection.execute(
            "UPDATE workflow_worker_instances SET heartbeat_at=0 "
            "WHERE worker_id='worker-b'",
        )
    finally:
        connection.close()
    assert not workers.worker_is_ready()


def test_e5_health_tests_core_data_dir_not_unrelated_environment_path(
    tmp_path, monkeypatch,
):
    client, core = _client(tmp_path)
    unrelated = tmp_path / "not-the-core-data"
    monkeypatch.setenv("WHAXON_DATA", str(unrelated))
    core.msf = SimpleNamespace(is_up=lambda: True)
    assert client.get("/api/health").status_code == 200
    assert not unrelated.exists()
    assert list(tmp_path.glob(".healthz*")) == []


def test_e5_database_failure_is_unready_even_when_msf_is_up(tmp_path, monkeypatch):
    client, core = _client(tmp_path)
    core.msf = SimpleNamespace(is_up=lambda: True)

    def fail_database():
        raise OSError("database must not leak full exception path")

    monkeypatch.setattr(core.store, "_conn", fail_database)
    response = client.get("/api/health")
    assert response.status_code == 503
    state = response.get_json()
    assert state["core_ready"] is False
    assert state["checks"]["database"] == "unavailable"
    assert "database must not leak" not in response.get_data(as_text=True)


def test_e5_data_directory_failure_is_unready(tmp_path):
    client, core = _client(tmp_path)
    core.msf = SimpleNamespace(is_up=lambda: True)
    non_directory = tmp_path / "not-a-directory"
    non_directory.write_text("file", encoding="utf-8")
    core.data_dir = non_directory
    response = client.get("/api/health")
    assert response.status_code == 503
    assert response.get_json()["core_ready"] is False
    assert response.get_json()["checks"]["data"] == "unavailable"


def test_e5_optional_msf_probe_exception_is_informational_not_service_failure(tmp_path):
    client, core = _client(tmp_path)

    def offline():
        raise RuntimeError("optional RPC offline")

    core.msf = SimpleNamespace(is_up=offline)
    response = client.get("/api/health")
    assert response.status_code == 200
    state = response.get_json()
    assert state["core_ready"] is True
    assert state["checks"]["msf"] == "unavailable"
    assert state["optional_degraded"] == ["msf"]


def test_e5_simple_health_fails_closed_on_durable_database_failure(tmp_path, monkeypatch):
    client, core = _client(tmp_path)
    core.msf = SimpleNamespace(is_up=lambda: True)
    assert client.get("/api/health/simple").status_code == 200

    def fail_database():
        raise OSError("private database path must not leak")

    monkeypatch.setattr(core.store, "_conn", fail_database)
    simple = client.get("/api/health/simple")
    assert simple.status_code == 503
    assert simple.get_json()["ok"] is False
    assert simple.get_json()["core_ready"] is False
    assert "private database path" not in simple.get_data(as_text=True)


def test_e5_simple_health_ignores_optional_tool_outage_but_checks_storage(tmp_path):
    client, core = _client(tmp_path)
    core.msf = SimpleNamespace(is_up=lambda: False)
    response = client.get("/api/health/simple")
    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert response.get_json()["core_ready"] is True
    non_directory = tmp_path / "unwritable-storage"
    non_directory.write_text("file", encoding="utf-8")
    core.data_dir = non_directory
    degraded = client.get("/api/health/simple")
    assert degraded.status_code == 503
    assert degraded.get_json()["ok"] is False
