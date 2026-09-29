"""SessionAdapter — parser dispatch and Finding conversion."""
from __future__ import annotations

from whaxon.adapters.registry import get_adapter


def test_sysinfo_adapter_parses_kv_pairs() -> None:
    a = get_adapter("msf_sysinfo")
    assert a is not None
    lines = [("stdout", "Computer        : victim"),
             ("stdout", "OS              : Windows 10"),
             ("stdout", "Arch            : x64")]
    findings = a.parse(lines, {"session_id": "3"})
    assert len(findings) >= 2
    kinds = {f.kind for f in findings}
    assert "sysinfo" in kinds
    for f in findings:
        assert f.data.get("session_id") == "3"


def test_hashdump_adapter_parses_ntlm() -> None:
    a = get_adapter("msf_hashdump")
    assert a is not None
    lines = [("stdout", "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::")]
    findings = a.parse(lines, {"session_id": "3"})
    assert len(findings) == 1
    assert findings[0].kind == "ntlm_hash"
    assert findings[0].data.get("user") == "Administrator"
    assert findings[0].data.get("session_id") == "3"


def test_getuid_adapter_parses_username() -> None:
    a = get_adapter("msf_getuid")
    assert a is not None
    lines = [("stdout", "Server username: NT AUTHORITY\\SYSTEM")]
    findings = a.parse(lines, {"session_id": "3"})
    assert len(findings) == 1
    assert findings[0].kind == "sysinfo"
    assert findings[0].data.get("field") == "current_user"
    assert "SYSTEM" in findings[0].data.get("value", "")


def test_session_adapter_returns_empty_on_unrecognized_output() -> None:
    a = get_adapter("msf_sysinfo")
    assert a is not None
    findings = a.parse([("stdout", "garbage output with no kv pairs")], {})
    assert findings == []


def test_session_adapter_attaches_session_id_from_ctx() -> None:
    a = get_adapter("msf_getuid")
    assert a is not None
    findings = a.parse([("stdout", "Server username: root")], {"session_id": "42"})
    assert findings[0].data.get("session_id") == "42"


def test_all_three_session_adapters_registered() -> None:
    for tid in ("msf_sysinfo", "msf_getuid", "msf_hashdump"):
        assert get_adapter(tid) is not None, f"{tid} not registered"