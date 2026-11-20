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
    monkeypatch.setenv("WHAXON_MSF_TIMEOUT", "30")
    cfg = MSFConfig.from_env()
    assert cfg.host == "10.0.0.1"
    assert cfg.port == 55554
    assert cfg.user == "admin"
    assert cfg.password == "secret"
    assert cfg.ssl is True
    assert cfg.timeout == 30.0


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


def test_msf_config_has_no_insecure_builtin_password(monkeypatch):
    monkeypatch.delenv("WHAXON_MSF_PASS", raising=False)
    assert MSFConfig.from_env().password == ""


def test_client_refuses_missing_rpc_password():
    client = MSFClient(MSFConfig(host="127.0.0.1", port=65530, password=""))
    with pytest.raises(MSFUnavailableError, match="WHAXON_MSF_PASS"):
        client.connect()


def test_client_rejects_plaintext_rpc_to_remote_host():
    client = MSFClient(MSFConfig(host="10.0.0.9", password="secret", ssl=False))
    with pytest.raises(MSFUnavailableError, match="refusing plaintext"):
        client._validate_transport()


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_client_allows_loopback_plaintext_for_local_development(host):
    client = MSFClient(MSFConfig(host=host, password="secret", ssl=False))
    client._validate_transport()


def test_client_allows_remote_rpc_when_tls_is_enabled():
    client = MSFClient(MSFConfig(host="msf.internal", password="secret", ssl=True))
    client._validate_transport()


def test_msf_execute_rejects_console_command_injection_before_connect():
    client = MSFClient(MSFConfig())
    with pytest.raises(ValueError, match="command delimiter"):
        client.execute("exploit", "multi/handler", {"LHOST": "127.0.0.1; sessions -K"})


def test_msf_execute_rejects_invalid_module_path_before_connect():
    client = MSFClient(MSFConfig())
    with pytest.raises(ValueError, match="module path"):
        client.execute("exploit", "../handler", {})


def test_msf_execute_polls_for_job_without_fixed_wait(monkeypatch):
    class Console:
        def __init__(self):
            self.writes = []
            self.reads = 0

        def write(self, command):
            self.writes.append(command)

        def read(self):
            self.reads += 1
            return {"data": "Exploit running as background job 17"} if self.reads == 1 else {"data": ""}

    console = Console()
    class Consoles:
        def console(self):
            return console
    class Rpc:
        consoles = Consoles()

    client = MSFClient(MSFConfig())
    monkeypatch.setattr(client, "connect", lambda: Rpc())
    result = client.execute("exploit", "multi/handler", {"LHOST": "127.0.0.1"})
    assert result["job_id"] == 17
    assert console.reads == 1
    assert "run -j" in console.writes


def test_verified_rpc_transport_uses_default_certificate_validation(monkeypatch):
    import requests

    from whaxon.core.msf import _verified_rpc_post

    captured = {}
    def fake_post(url, **kwargs):
        captured.update(url=url, **kwargs)
        return object()

    monkeypatch.setattr(requests, "post", fake_post)
    _verified_rpc_post(
        "https://msf.internal:55553/api/", b"payload", {"Content-Type": "x"},
        timeout=(3, 3),
    )
    assert captured["verify"] is True
    assert captured["timeout"] == (3, 3)


def test_verified_rpc_transport_uses_configured_private_ca(monkeypatch):
    import requests

    from whaxon.core.msf import _verified_rpc_post

    captured = {}
    def fake_post(url, **kwargs):
        captured.update(url=url, **kwargs)
        return object()

    monkeypatch.setattr(requests, "post", fake_post)
    _verified_rpc_post(
        "https://msf.internal:55553/api/", b"payload", {"Content-Type": "x"},
        timeout=(3, 3), ca_bundle="/tmp/msf-ca.pem",
    )
    assert captured["verify"] == "/tmp/msf-ca.pem"


@pytest.mark.parametrize(
    ("requested", "expected"),
    [(0.1, 1.0), (5.0, 5.0), (30.0, 30.0), (120.0, 60.0)],
)
def test_msf_rpc_timeout_respects_configuration_with_safe_bounds(requested, expected):
    client = MSFClient(MSFConfig(timeout=requested))
    assert client._bounded_timeout() == expected

def test_msf_execute_rpc_uses_structured_module_execute(monkeypatch):
    calls = []

    class Rpc:
        def call(self, *args):
            calls.append(args)
            return {"job_id": 0, "uuid": "rpc-run-1"}

    client = MSFClient(MSFConfig())
    monkeypatch.setattr(client, "connect", lambda: Rpc())
    result = client.execute_rpc(
        "exploit", "multi/samba/usermap_script",
        {"RHOSTS": "172.28.0.10"}, payload="cmd/unix/reverse_netcat",
        timeout_s=60,
    )

    assert result["job_id"] == 0
    assert calls == [(
        "module.execute", [
            "exploit", "multi/samba/usermap_script",
            {"RHOSTS": "172.28.0.10", "PAYLOAD": "cmd/unix/reverse_netcat"},
        ],
    )]


def test_msf_execute_rpc_rejects_injection_before_connect():
    client = MSFClient(MSFConfig())
    with pytest.raises(ValueError, match="command delimiter"):
        client.execute_rpc("exploit", "multi/handler", {"RHOSTS": "127.0.0.1\nrun"})
