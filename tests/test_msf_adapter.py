"""Tests for the MSF adapter (no real RPC needed)."""
from whaxon.adapters.msf import MsfAdapter, parse_msf_tool_id, parse_kv_args


def test_parse_msf_tool_id_exploit():
    assert parse_msf_tool_id("msf:exploit:windows/smb/ms17_010_eternalblue") == (
        "exploit", "windows/smb/ms17_010_eternalblue")


def test_parse_msf_tool_id_auxiliary():
    assert parse_msf_tool_id("msf:auxiliary:scanner/smb/smb_version") == (
        "auxiliary", "scanner/smb/smb_version")


def test_parse_msf_tool_id_invalid():
    assert parse_msf_tool_id("nmap") is None
    assert parse_msf_tool_id("msf:bad:path") is None
    assert parse_msf_tool_id("msf:exploit") is None


def test_parse_kv_args_basic():
    assert parse_kv_args("RHOSTS=10.0.0.5 RPORT=445") == {
        "RHOSTS": "10.0.0.5", "RPORT": "445"}


def test_parse_kv_args_empty():
    assert parse_kv_args("") == {}
    assert parse_kv_args("no_equals_sign") == {}


def test_parse_kv_args_quoted():
    assert parse_kv_args('RHOSTS=10.0.0.5 LHOST="10.0.0.1"') == {
        "RHOSTS": "10.0.0.5", "LHOST": "10.0.0.1"}


def test_adapter_handles_msf_down(monkeypatch):
    """When MSF is down, the adapter emits a single msf_error finding."""
    from whaxon.core.msf import MSFClient, MSFConfig

    cfg = MSFConfig(host="127.0.0.1", port=65530, password="x")
    adapter = MsfAdapter(client=MSFClient(cfg))
    findings = adapter.run_module(
        "msf:exploit:windows/smb/ms17_010_eternalblue",
        "RHOSTS=10.0.0.5",
        ctx={"target": "10.0.0.5"},
    )
    assert len(findings) == 1
    assert findings[0].kind == "msf_error"
    assert findings[0].severity == "info"


def test_adapter_invalid_tool_id():
    adapter = MsfAdapter()
    try:
        adapter.run_module("nmap", "", {})
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-msf tool id")
