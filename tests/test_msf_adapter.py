"""Tests for the MSF adapter's payload and job_id handling.

Guards against the bug we fixed on 2026-09-27: the adapter passed every
option — including PAYLOAD — into the options dict, where pymetasploit3
silently dropped it, so MSF got no payload and returned uuid-only
responses with no job bound.

The fix extracts PAYLOAD from options and passes it as the payload=
kwarg to MSFClient.execute(). These tests freeze that contract.
"""
from __future__ import annotations

from typing import Any

from whaxon.adapters.msf import MsfAdapter, parse_kv_args, parse_msf_tool_id

# ---------- parsing helpers ----------

def test_parse_msf_tool_id() -> None:
    assert parse_msf_tool_id("msf:exploit:multi/samba/usermap_script") \
        == ("exploit", "multi/samba/usermap_script")
    assert parse_msf_tool_id("msf:post:multi/gather/env") \
        == ("post", "multi/gather/env")
    assert parse_msf_tool_id("not-msf") is None


def test_parse_kv_args() -> None:
    assert parse_kv_args("RHOSTS=1.2.3.4 RPORT=445") \
        == {"RHOSTS": "1.2.3.4", "RPORT": "445"}
    assert parse_kv_args("") == {}
    assert parse_kv_args("PAYLOAD=generic/shell_reverse_tcp") \
        == {"PAYLOAD": "generic/shell_reverse_tcp"}


# ---------- adapter contract ----------

class FakeClient:
    """Records what the adapter passes to MSFClient.execute()."""

    def __init__(self, result: dict | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._result = result or {"job_id": 42, "console_output": ""}
        self._sessions: dict[str, dict] = {}

    def connect(self) -> None: pass
    def sessions(self) -> dict:
        return dict(self._sessions)

    def execute(self, module_type, module_path, options, payload=None):
        self.calls.append({
            "module_type": module_type,
            "module_path": module_path,
            "options": dict(options),
            "payload": payload,
        })
        return dict(self._result)


def test_payload_is_extracted_from_options() -> None:
    """PAYLOAD must NOT stay in options — it goes as the payload= kwarg."""
    fake = FakeClient()
    adapter = MsfAdapter(client=fake)

    adapter.run_module(
        "msf:exploit:multi/samba/usermap_script",
        "RHOSTS=127.0.0.1 RPORT=445 PAYLOAD=cmd/unix/reverse_netcat "
        "LHOST=127.0.0.1 LPORT=33333",
    )

    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["payload"] == "cmd/unix/reverse_netcat", \
        "PAYLOAD must be passed as the payload= kwarg"
    assert "PAYLOAD" not in call["options"], \
        "PAYLOAD must be removed from the options dict"
    assert call["options"]["RHOSTS"] == "127.0.0.1"
    assert call["options"]["LHOST"] == "127.0.0.1"


def test_empty_job_id_produces_msf_error_not_fake_success() -> None:
    """A None job_id means MSF didn't start the module. Report that."""
    fake = FakeClient(result={"job_id": None, "console_output": "some error"})
    adapter = MsfAdapter(client=fake)

    findings = adapter.run_module(
        "msf:exploit:multi/handler",
        "PAYLOAD=generic/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444",
    )

    kinds = [f.kind for f in findings]
    assert "msf_error" in kinds, \
        f"expected msf_error on empty job_id, got kinds={kinds}"
    assert "msf_module_started" not in kinds, \
        "must not claim success when MSF returned no job_id"


def test_real_job_id_produces_msf_module_started() -> None:
    fake = FakeClient(result={"job_id": 17, "console_output": ""})
    adapter = MsfAdapter(client=fake)

    findings = adapter.run_module(
        "msf:exploit:multi/handler",
        "PAYLOAD=generic/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444",
    )

    kinds = [f.kind for f in findings]
    assert "msf_module_started" in kinds
    start = next(f for f in findings if f.kind == "msf_module_started")
    assert start.data["job_id"] == "17"
