"""SMB session transport + Phase E.2 pivot route rewrite."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

from whaxon.core.events import EventBus
from whaxon.core.routes import Route, resolve, rewrite_target
from whaxon.core.runner import ToolRunner


class _FakeCatalog:
    def __init__(self, tools):
        self._tools = {t["id"]: t for t in tools}
    def get(self, tool_id):
        t = self._tools.get(tool_id)
        return SimpleNamespace(**t) if t else None
    def list(self):
        return list(self._tools.values())


def _smb_catalog():
    return _FakeCatalog([
        {"id": "smb_shares", "category": "session", "transport": "smb",
         "command": "shares", "binary": "", "args": ""},
    ])


# ---------- route resolver ----------

def test_resolve_finds_matching_host():
    rows = [{"session_id": "3", "lport": 18080, "rhost": "10.0.0.7", "rport": 80}]
    r = resolve(rows, "10.0.0.7")
    assert r is not None
    assert r.local_port == 18080
    assert r.via_session == "3"


def test_resolve_miss():
    rows = [{"session_id": "3", "lport": 18080, "rhost": "10.0.0.7", "rport": 80}]
    assert resolve(rows, "10.0.0.8") is None


def test_resolve_empty_target():
    assert resolve([], "") is None


def test_rewrite_target():
    r = Route(target_host="10.0.0.7", target_port=80, local_port=18080, via_session="3")
    assert rewrite_target(r) == "127.0.0.1:18080"


# ---------- SMB transport ----------

def test_smb_requires_smb_prefix():
    r = ToolRunner(EventBus(), catalog=_smb_catalog())
    with pytest.raises(ValueError, match="smb:user@host"):
        asyncio.run(r.run_in_session("smb_shares", "3"))


def test_smb_requires_password_env(monkeypatch):
    monkeypatch.delenv("WHAXON_SMB_PASS", raising=False)
    r = ToolRunner(EventBus(), catalog=_smb_catalog())
    out = asyncio.run(r._run_smb_session("smb:user@10.0.0.5", "shares", 5.0))
    assert "WHAXON_SMB_PASS not set" in out


def test_smb_happy_path(monkeypatch):
    monkeypatch.setenv("WHAXON_SMB_PASS", "pw")
    r = ToolRunner(EventBus(), catalog=_smb_catalog())
    captured = {}
    async def fake_exec(*args, **kwargs):
        captured["argv"] = args
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"Share1 Disk\nShare2 Disk\n", b""))
        proc.returncode = 0
        return proc
    async def run():
        with patch("asyncio.create_subprocess_exec", fake_exec):
            return await r._run_smb_session("smb:user@10.0.0.5", "shares", 5.0)
    out = asyncio.run(run())
    assert "Share1" in out
    assert captured["argv"][0] == "impacket-smbclient"
    assert "user:pw@10.0.0.5" in captured["argv"][1]


def test_smb_scope_check(monkeypatch):
    monkeypatch.setenv("WHAXON_SMB_PASS", "pw")
    class _Scope:
        def check(self, target):
            return SimpleNamespace(allowed=False, reason="outside", matched_rule="x")
    r = ToolRunner(EventBus(), catalog=_smb_catalog(), scope=_Scope())
    with pytest.raises(Exception, match="outside"):
        asyncio.run(r._run_smb_session("smb:user@10.0.0.5", "shares", 5.0))


# ---------- SMB adapter ----------

def test_smb_shares_adapter_parses():
    from whaxon.adapters.registry import get_adapter
    a = get_adapter("smb_shares")
    assert a is not None
    lines = [("stdout", "Share1  Disk  "), ("stdout", "IPC$   IPC   ")]
    fs = a.parse(lines, {"session_id": "3"})
    assert len(fs) >= 1
    assert any(f.kind == "smb_share" for f in fs)
    assert all(f.data.get("session_id") == "3" for f in fs)


def test_smb_ls_adapter_parses():
    from whaxon.adapters.registry import get_adapter
    a = get_adapter("smb_ls")
    assert a is not None
    lines = [("stdout", "-rwxr-xr-x  1  user  group  file.txt")]
    fs = a.parse(lines, {"session_id": "3"})
    assert len(fs) >= 1
    assert fs[0].kind == "smb_entry"


# ---------- pivot rewrite in run_tool ----------

def test_run_tool_rewrites_target_when_route_exists(monkeypatch):
    from whaxon.core.events import JobOutput
    cat = _FakeCatalog([
        {"id": "nikto", "category": "web", "transport": "cli",
         "binary": "/bin/echo", "args": "{target}", "pivot_capable": True},
    ])
    seen = {}
    def resolver(host):
        seen["host"] = host
        return Route(target_host=host, target_port=80, local_port=18080, via_session="3")
    bus = EventBus()
    captured = []
    def _on_out(e):
        captured.append(e.line)
    bus.subscribe(JobOutput, _on_out)
    r = ToolRunner(bus, catalog=cat, route_resolver=resolver)
    async def _go():
        return await r.run_tool("nikto", "10.0.0.7", timeout_s=5.0)
    asyncio.run(_go())
    assert seen["host"] == "10.0.0.7"
    joined = " ".join(captured)
    assert "127.0.0.1:18080" in joined


def test_run_tool_no_rewrite_when_not_pivot_capable():
    from whaxon.core.events import JobOutput
    cat = _FakeCatalog([
        {"id": "nmap", "category": "recon", "transport": "cli",
         "binary": "/bin/echo", "args": "{target}", "pivot_capable": False},
    ])
    def resolver(host):
        return Route(target_host=host, target_port=80, local_port=18080, via_session="3")
    bus = EventBus()
    captured = []
    def _on_out(e):
        captured.append(e.line)
    bus.subscribe(JobOutput, _on_out)
    r = ToolRunner(bus, catalog=cat, route_resolver=resolver)
    async def _go():
        return await r.run_tool("nmap", "10.0.0.7", timeout_s=5.0)
    asyncio.run(_go())
    joined = " ".join(captured)
    assert "10.0.0.7" in joined
    assert "18080" not in joined

