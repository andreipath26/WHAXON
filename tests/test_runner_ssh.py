"""SSH transport in ToolRunner — v2 of docs/session-execution.md §9."""
from __future__ import annotations

import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

from whaxon.core.events import EventBus
from whaxon.core.runner import ToolRunner


class _FakeCatalog:
    def __init__(self, tools):
        self._tools = {t["id"]: t for t in tools}
    def get(self, tool_id):
        from types import SimpleNamespace
        t = self._tools.get(tool_id)
        if t is None:
            return None
        return SimpleNamespace(**t)
    def list(self):
        return list(self._tools.values())


def _ssh_catalog():
    return _FakeCatalog([
        {"id": "ssh_cmd", "name": "SSH command", "category": "session",
         "transport": "ssh", "command": "{command}",
         "binary": "", "args": ""},
        {"id": "nmap", "name": "Nmap", "category": "recon",
         "transport": "cli", "command": "",
         "binary": "/usr/bin/nmap", "args": "{target}"},
    ])


def _runner(catalog, scope=None):
    bus = EventBus()
    r = ToolRunner(bus, catalog=catalog, scope=scope)
    return r, bus


def test_ssh_session_requires_ssh_prefix() -> None:
    r, _ = _runner(_ssh_catalog())
    with pytest.raises(ValueError, match="ssh:user@host"):
        asyncio.run(r.run_in_session("ssh_cmd", "3"))


def test_ssh_session_rejects_out_of_scope_host() -> None:
    class _Scope:
        def check(self, target):
            from types import SimpleNamespace
            return SimpleNamespace(allowed=False, reason="outside",
                                   matched_rule="default")
    r, _ = _runner(_ssh_catalog(), scope=_Scope())
    with pytest.raises(Exception, match="outside"):
        asyncio.run(r.run_in_session("ssh_cmd", "ssh:user@10.0.0.5"))


def test_ssh_session_cli_tool_rejected() -> None:
    r, _ = _runner(_ssh_catalog())
    with pytest.raises(ValueError, match="not session-scoped"):
        asyncio.run(r.run_in_session("nmap", "ssh:user@10.0.0.5"))


def test_ssh_session_happy_path_with_mocked_subprocess(monkeypatch) -> None:
    r, bus = _runner(_ssh_catalog())

    async def fake_subprocess_exec(*args, **kwargs):
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"hello\nworld\n", b""))
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec",
                        fake_subprocess_exec)
    job_id = asyncio.run(r.run_in_session("ssh_cmd", "ssh:user@10.0.0.5",
                                          job_id="j-ssh"))
    assert job_id == "j-ssh"


def test_ssh_session_timeout_returns_error() -> None:
    r, _ = _runner(_ssh_catalog())

    async def slow_exec(*args, **kwargs):
        proc = MagicMock()
        async def never():
            await asyncio.sleep(10)
        proc.communicate = never
        proc.kill = MagicMock()
        return proc

    async def run():
        with patch("asyncio.create_subprocess_exec", slow_exec):
            return await r._run_ssh_session("ssh:user@10.0.0.5", "id", 0.05)

    out = asyncio.run(run())
    assert "ssh timeout" in out


def test_ssh_session_port_parsing() -> None:
    """ssh:user@host:2222 should parse port 2222."""
    r, _ = _runner(_ssh_catalog())
    captured = {}

    async def fake_exec(*args, **kwargs):
        captured["argv"] = args
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"ok\n", b""))
        return proc

    async def run():
        with patch("asyncio.create_subprocess_exec", fake_exec):
            return await r._run_ssh_session("ssh:user@10.0.0.5:2222", "id", 5.0)

    asyncio.run(run())
    assert "-p" in captured["argv"]
    assert "2222" in captured["argv"]
    assert "user@10.0.0.5" in captured["argv"]