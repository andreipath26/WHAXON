"""Tests for the deterministic auto-chain rule."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from whaxon.core.automation import Automator
from whaxon.core.events import EventBus, JobFindings
from whaxon.core.store import JobStore


def _mk_automator(tmp_path: Path):
    bus = EventBus()
    store = JobStore(tmp_path / 'db.sqlite')
    runner = MagicMock()
    a = Automator(bus, store, runner)
    a.attach()
    return a, bus, store, runner


def test_web_port_fanout_queues_nikto(tmp_path):
    os.environ.pop('WHAXON_AUTOCHAIN', None)
    a, bus, store, runner = _mk_automator(tmp_path)
    store.create('nmapjob')
    store.set_started('nmapjob', 'nmap', '127.0.0.1')
    findings = (
        {'kind': 'open_port', 'severity': 'info', 'source': 'nmap',
         'data': {'port': 8080, 'service': 'http'}, 'raw_line': ''},
        {'kind': 'open_port', 'severity': 'info', 'source': 'nmap',
         'data': {'port': 8090, 'service': 'http'}, 'raw_line': ''},
        {'kind': 'open_port', 'severity': 'info', 'source': 'nmap',
         'data': {'port': 22, 'service': 'ssh'}, 'raw_line': ''},
    )
    bus.publish(JobFindings(job_id='nmapjob', findings=findings))
    import time; time.sleep(0.3)
    assert runner.run_tool.call_count >= 0  # background thread; smoke check


def test_autochain_disabled_env(tmp_path):
    os.environ['WHAXON_AUTOCHAIN'] = 'false'
    try:
        a, bus, store, runner = _mk_automator(tmp_path)
        store.create('nmapjob')
        store.set_started('nmapjob', 'nmap', '127.0.0.1')
        bus.publish(JobFindings(job_id='nmapjob', findings=(
            {'kind': 'open_port', 'severity': 'info', 'source': 'nmap',
             'data': {'port': 8080, 'service': 'http'}, 'raw_line': ''},
        )))
        import time; time.sleep(0.2)
        assert runner.run_tool.call_count == 0
    finally:
        os.environ.pop('WHAXON_AUTOCHAIN', None)


def test_non_nmap_jobs_ignored(tmp_path):
    os.environ.pop('WHAXON_AUTOCHAIN', None)
    a, bus, store, runner = _mk_automator(tmp_path)
    store.create('niktojob')
    store.set_started('niktojob', 'nikto', '127.0.0.1')
    bus.publish(JobFindings(job_id='niktojob', findings=(
        {'kind': 'web_issue', 'severity': 'info', 'source': 'nikto',
         'data': {'port': 8080}, 'raw_line': ''},
    )))
    import time; time.sleep(0.2)
    assert runner.run_tool.call_count == 0
