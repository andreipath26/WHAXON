"""Desktop destination matches the live default UI without requiring Qt."""
from urllib.parse import urlsplit

from whaxon.core import Core
from whaxon.interfaces.gui import embed
from whaxon.interfaces.web.server import AsyncRunner, JobRegistry, create_app


def test_desktop_destination_matches_default_and_renders_supplied_ui(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    core = Core(tmp_path)
    app = create_app(core, JobRegistry(core), AsyncRunner(core))
    app.config["TESTING"] = True
    client = app.test_client()

    destination = urlsplit(embed.URL)
    assert destination.hostname == "127.0.0.1"
    assert destination.port == 5001
    root = client.get("/")
    assert root.status_code == 302
    assert root.headers["Location"] == destination.path == "/ui-v2"
    response = client.get(destination.path)
    assert response.status_code == 200
    assert b'data-path="dashboard-zero-state"' in response.data
    # Existing users of the reference route keep compatibility.
    assert client.get("/ui").status_code == 200


def test_desktop_reuses_existing_service_without_spawning(monkeypatch):
    server = embed.EmbeddedServer()
    monkeypatch.setattr(server, "is_running", lambda: True)

    def unexpected_spawn(*args, **kwargs):
        raise AssertionError("an existing service must not start another process")

    monkeypatch.setattr(embed.subprocess, "Popen", unexpected_spawn)
    assert server.start()
    assert server._we_started is False
