"""required_session_type hint and whaxon run session dispatch."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from whaxon.core.catalog import Tool
from whaxon.core.events import EventBus
from whaxon.core.runner import ToolRunner


class _FakeCatalog:
    def __init__(self, tools):
        self._tools = {t['id']: t for t in tools}
    def get(self, tool_id):
        t = self._tools.get(tool_id)
        return SimpleNamespace(**t) if t else None
    def list(self):
        return list(self._tools.values())


def test_tool_has_required_session_type_default() -> None:
    t = Tool(id='x', name='x', category='c', binary='b')
    assert t.required_session_type == ''


def test_runner_rejects_wrong_session_type() -> None:
    cat = _FakeCatalog([
        {'id': 'msf_sysinfo', 'category': 'session',
         'transport': 'msf_session', 'command': 'sysinfo',
         'required_session_type': 'meterpreter'},
    ])
    r = ToolRunner(EventBus(), catalog=cat)
    fake = MagicMock()
    fake.is_up.return_value = True
    fake.sessions.return_value = {'1': {'type': 'shell'}}
    with patch('whaxon.core.msf.MSFClient', return_value=fake):
        with pytest.raises(ValueError, match='requires'):
            asyncio.run(r.run_in_session('msf_sysinfo', '1'))


def test_runner_allows_matching_session_type() -> None:
    cat = _FakeCatalog([
        {'id': 'msf_sysinfo', 'category': 'session',
         'transport': 'msf_session', 'command': 'sysinfo',
         'required_session_type': 'meterpreter'},
    ])
    r = ToolRunner(EventBus(), catalog=cat)
    fake = MagicMock()
    fake.is_up.return_value = True
    fake.sessions.return_value = {'1': {'type': 'meterpreter'}}
    fake.session_exec.return_value = 'Computer: test\n'
    with patch('whaxon.core.msf.MSFClient', return_value=fake):
        jid = asyncio.run(r.run_in_session('msf_sysinfo', '1', job_id='j1'))
    assert jid == 'j1'
    assert r._lines_by_job[jid]


def test_runner_no_hint_allows_any_session_type() -> None:
    cat = _FakeCatalog([
        {'id': 'msf_getuid', 'category': 'session',
         'transport': 'msf_session', 'command': 'getuid'},
    ])
    r = ToolRunner(EventBus(), catalog=cat)
    fake = MagicMock()
    fake.is_up.return_value = True
    fake.sessions.return_value = {'1': {'type': 'shell'}}
    fake.session_exec.return_value = 'Server username: root\n'
    with patch('whaxon.core.msf.MSFClient', return_value=fake):
        jid = asyncio.run(r.run_in_session('msf_getuid', '1', job_id='j2'))
    assert jid == 'j2'

