"""Tests for MSF config, client wrapper, and store session methods."""
import pytest

from whaxon.core.msf import MSFClient, MSFConfig, MSFUnavailableError
from whaxon.core.store import JobStore


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("WHAXON_MSF_HOST", "10.0.0.1")
    monkeypatch.setenv("WHAXON_MSF_PORT", "55554")
    monkeypatch.setenv("WHAXON_MSF_USER", "admin")
    monkeypatch.setenv("WHAXON_MSF_PASS", "secret")
    monkeypatch.setenv("WHAXON_MSF_SSL", "1")
    cfg = MSFConfig.from_env()
    assert cfg.host == "10.0.0.1"
    assert cfg.port == 55554
    assert cfg.user == "admin"
    assert cfg.password == "secret"
    assert cfg.ssl is True


def test_config_display():
    cfg = MSFConfig(host="192.168.1.5", port=55553, ssl=False)
    assert cfg.display() == "http://192.168.1.5:55553"
    cfg2 = MSFConfig(host="192.168.1.5", port=55553, ssl=True)
    assert cfg2.display() == "https://192.168.1.5:55553"


def test_client_connect_fails_when_unreachable():
    """No daemon running on this port — should raise, not hang."""
    cfg = MSFConfig(host="127.0.0.1", port=65530, password="x")
    client = MSFClient(cfg)
    assert client.is_up() is False
    with pytest.raises(MSFUnavailableError):
        client.connect()


def test_store_session_upsert(tmp_path):
    store = JobStore(tmp_path / "test.db")
    store.upsert_session("1", "10.0.0.5", "meterpreter", {"arch": "x64"})
    sessions = store.list_sessions()
    assert len(sessions) == 1
    s = sessions[0]
    assert s["id"] == "1"
    assert s["host"] == "10.0.0.5"
    assert s["type"] == "meterpreter"
    assert s["status"] == "open"
    assert s["info"] == {"arch": "x64"}


def test_store_session_update(tmp_path):
    store = JobStore(tmp_path / "test.db")
    store.upsert_session("1", "10.0.0.5", "shell", {})
    store.upsert_session("1", "10.0.0.5", "meterpreter", {"arch": "x64"})
    sessions = store.list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["type"] == "meterpreter"
    assert sessions[0]["info"] == {"arch": "x64"}


def test_store_session_close(tmp_path):
    store = JobStore(tmp_path / "test.db")
    store.upsert_session("1", "10.0.0.5", "shell", {})
    store.close_session("1")
    open_sessions = store.list_sessions()
    assert len(open_sessions) == 0
    all_sessions = store.list_sessions(include_closed=True)
    assert len(all_sessions) == 1
    assert all_sessions[0]["status"] == "closed"


def test_multiple_sessions(tmp_path):
    store = JobStore(tmp_path / "test.db")
    store.upsert_session("1", "10.0.0.5", "meterpreter", {})
    store.upsert_session("2", "10.0.0.6", "shell", {})
    store.upsert_session("3", "10.0.0.7", "meterpreter", {})
    store.close_session("2")
    assert len(store.list_sessions()) == 2
    assert len(store.list_sessions(include_closed=True)) == 3
