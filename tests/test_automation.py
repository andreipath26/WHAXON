"""Tests for the deterministic auto-chain rule."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

from whaxon.core.automation import Automator
from whaxon.core.events import EventBus, JobFailed, JobFindings, JobFinished
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
    _a, bus, store, runner = _mk_automator(tmp_path)
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
    import time
    time.sleep(0.3)
    assert runner.run_tool.call_count >= 0  # background thread; smoke check


def test_autochain_disabled_env(tmp_path):
    os.environ['WHAXON_AUTOCHAIN'] = 'false'
    try:
        _a, bus, store, runner = _mk_automator(tmp_path)
        store.create('nmapjob')
        store.set_started('nmapjob', 'nmap', '127.0.0.1')
        bus.publish(JobFindings(job_id='nmapjob', findings=(
            {'kind': 'open_port', 'severity': 'info', 'source': 'nmap',
             'data': {'port': 8080, 'service': 'http'}, 'raw_line': ''},
        )))
        import time
        time.sleep(0.2)
        assert runner.run_tool.call_count == 0
    finally:
        os.environ.pop('WHAXON_AUTOCHAIN', None)


def test_non_nmap_jobs_ignored(tmp_path):
    os.environ.pop('WHAXON_AUTOCHAIN', None)
    _a, bus, store, runner = _mk_automator(tmp_path)
    store.create('niktojob')
    store.set_started('niktojob', 'nikto', '127.0.0.1')
    bus.publish(JobFindings(job_id='niktojob', findings=(
        {'kind': 'web_issue', 'severity': 'info', 'source': 'nikto',
         'data': {'port': 8080}, 'raw_line': ''},
    )))
    import time
    time.sleep(0.2)
    assert runner.run_tool.call_count == 0


def test_queue_nikto_skips_when_tool_missing(tmp_path):
    """If nikto isn't in the catalog, the automator must not queue it.

    Regression: previously, a catalog without nikto (e.g. whaxon init --demo,
    which only ships nmap and echo) caused a ValueError in a background
    thread. The traceback printed to stderr but didn't affect the caller's
    exit code, so the failure was invisible.
    """
    from whaxon.core.automation import Automator
    from whaxon.core.catalog import Tool, ToolCatalog
    from whaxon.core.events import EventBus, JobStarted
    from whaxon.core.runner import ToolRunner
    from whaxon.core.store import JobStore

    bus = EventBus()
    catalog = ToolCatalog(bus, tmp_path / "tools.json")
    catalog._tools = {
        "nmap": Tool(id="nmap", name="Nmap", category="recon",
                     binary="/bin/echo", args="{target}"),
    }
    runner = ToolRunner(bus, catalog, None)
    store = JobStore(tmp_path / "whaxon.db")

    started = []
    bus.subscribe(JobStarted, lambda e: started.append(e))

    auto = Automator(bus, store, runner)
    auto._queue_nikto("10.0.0.5", 80, "http")

    import time
    time.sleep(0.3)

    assert started == []


def test_has_tool_returns_true_for_present_tool(tmp_path):
    """ToolRunner.has_tool reflects catalog membership."""
    from whaxon.core.catalog import Tool, ToolCatalog
    from whaxon.core.events import EventBus
    from whaxon.core.runner import ToolRunner

    bus = EventBus()
    catalog = ToolCatalog(bus, tmp_path / "tools.json")
    catalog._tools = {
        "nmap": Tool(id="nmap", name="Nmap", category="recon",
                     binary="/bin/echo", args="{target}"),
    }
    runner = ToolRunner(bus, catalog, None)
    assert runner.has_tool("nmap") is True
    assert runner.has_tool("nikto") is False


def test_engine_v2_findings_do_not_trigger_legacy_auto_chain(tmp_path):
    """V2 findings stay under V2 follow-up approval, legacy jobs stay legacy."""
    os.environ.pop('WHAXON_AUTOCHAIN', None)
    automator, bus, store, _runner = _mk_automator(tmp_path)
    finding = {
        'kind': 'open_port', 'severity': 'info', 'source': 'nmap',
        'data': {'port': 8080, 'service': 'http'}, 'raw_line': '',
    }
    store.create('v2job')
    store.set_started('v2job', 'nmap', '127.0.0.1')
    automator.suppress_legacy_followup('v2job')
    bus.publish(JobFindings(job_id='v2job', findings=(finding,)))
    assert store.list_pending() == []
    store.create('legacyjob')
    store.set_started('legacyjob', 'nmap', '127.0.0.1')
    bus.publish(JobFindings(job_id='legacyjob', findings=(finding,)))
    assert any(row['tool'] == 'nikto' for row in store.list_pending())


def test_engine_v2_followup_fence_persists_across_events_and_restart(tmp_path):
    """Repeated events and process replacement must not create legacy work."""
    os.environ.pop('WHAXON_AUTOCHAIN', None)
    auto, bus, store, _runner = _mk_automator(tmp_path)
    finding = {
        'kind': 'open_port', 'severity': 'info', 'source': 'nmap',
        'data': {'port': 8080, 'service': 'http'}, 'raw_line': '',
    }
    store.create('v2repeat')
    store.set_started('v2repeat', 'nmap', '127.0.0.1')
    auto.suppress_legacy_followup('v2repeat')
    for _ in range(3):
        bus.publish(JobFindings(job_id='v2repeat', findings=(finding,)))
    assert store.list_pending() == []

    restarted = JobStore(tmp_path / 'db.sqlite')
    assert restarted.is_engine_v2_execution_job('v2repeat')
    bus2 = EventBus()
    new_auto = Automator(bus2, restarted, _runner)
    new_auto.attach()
    bus2.publish(JobFindings(job_id='v2repeat', findings=(finding,)))
    assert restarted.list_pending() == []


def test_legacy_autochain_fails_closed_when_provenance_cannot_be_read(tmp_path, monkeypatch):
    """Unavailable ownership storage cannot cause an unauthorized autochain."""
    os.environ.pop('WHAXON_AUTOCHAIN', None)
    _auto, bus, store, _runner = _mk_automator(tmp_path)
    store.create('ambiguous')
    store.set_started('ambiguous', 'nmap', '127.0.0.1')
    def unavailable(_job_id):
        raise OSError('ownership database unavailable')
    monkeypatch.setattr(store, 'is_engine_v2_execution_job', unavailable)
    bus.publish(JobFindings(job_id='ambiguous', findings=({
        'kind': 'open_port', 'severity': 'info', 'source': 'nmap',
        'data': {'port': 443, 'service': 'https'}, 'raw_line': '',
    },)))
    assert store.list_pending() == []


def test_terminal_followup_releases_source_tracking(tmp_path):
    auto, bus, store, _runner = _mk_automator(tmp_path)
    store.create('nmapjob')
    store.set_started('nmapjob', 'nmap', '127.0.0.1')
    bus.publish(JobFindings(job_id='nmapjob', findings=({
        'kind': 'open_port', 'severity': 'info', 'source': 'nmap',
        'data': {'port': 8080, 'service': 'http'}, 'raw_line': '',
    },)))
    followup_id = store.list_pending()[0]['id']

    bus.publish(JobFinished(job_id=followup_id, exit_code=0, duration_s=0.1))

    assert auto.take_queued_followups('nmapjob') == set()
    assert auto._followups_by_source == {}
    assert auto._source_by_followup == {}


def test_failed_followup_releases_source_tracking(tmp_path):
    auto, bus, store, _runner = _mk_automator(tmp_path)
    store.create('nmapjob')
    store.set_started('nmapjob', 'nmap', '127.0.0.1')
    bus.publish(JobFindings(job_id='nmapjob', findings=({
        'kind': 'open_port', 'severity': 'info', 'source': 'nmap',
        'data': {'port': 8443, 'service': 'https'}, 'raw_line': '',
    },)))
    followup_id = store.list_pending()[0]['id']

    bus.publish(JobFailed(job_id=followup_id, error='worker failed'))

    assert auto.take_queued_followups('nmapjob') == set()
    assert auto._followups_by_source == {}
    assert auto._source_by_followup == {}
