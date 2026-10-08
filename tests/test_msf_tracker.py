"""Tests for whaxon.core.msf_tracker.MSFTracker.

Strategy:
  - Logic tests call tracker._poll() directly — deterministic, no timing.
  - Lifecycle tests start() the real thread with a short interval and wait
    for an effect with a bounded timeout. Kept to two tests so the suite
    stays fast and doesn't flake.
"""
from __future__ import annotations

import time

from whaxon.core.events import EventBus, SessionClosed, SessionStarted
from whaxon.core.msf import MSFUnavailableError
from whaxon.core.msf_tracker import MSFTracker
from whaxon.core.store import JobStore

# ---------------------------------------------------------------- fakes

class FakeClient:
    def __init__(self, up=True, sessions=None):
        self._up = up
        self._sessions = sessions or {}
        self.raise_on_sessions = None

    def is_up(self):
        return self._up

    def sessions(self):
        if self.raise_on_sessions is not None:
            raise self.raise_on_sessions
        return dict(self._sessions)


class Recorder:
    def __init__(self, bus):
        self.started = []
        self.closed = []
        bus.subscribe(SessionStarted, lambda e: self.started.append(e))
        bus.subscribe(SessionClosed, lambda e: self.closed.append(e))


def _make(tmp_path, live_sessions=None, up=True):
    bus = EventBus()
    store = JobStore(tmp_path / "t.db")
    client = FakeClient(up=up, sessions=live_sessions or {})
    tracker = MSFTracker(bus, store, client=client, interval_s=5.0)
    rec = Recorder(bus)
    return tracker, client, store, rec


# ---------------------------------------------------------------- _poll logic

def test_poll_no_op_when_msf_down(tmp_path):
    tracker, _, store, rec = _make(tmp_path, up=False)
    tracker._poll()
    assert rec.started == []
    assert rec.closed == []
    assert store.list_sessions() == []


def test_poll_first_sighting_creates_session(tmp_path):
    live = {"1": {"target_host": "10.0.0.5", "type": "shell"}}
    tracker, _, store, rec = _make(tmp_path, live_sessions=live)
    tracker._poll()

    # event fired
    assert len(rec.started) == 1
    ev = rec.started[0]
    assert ev.session_id == "1"
    assert ev.host == "10.0.0.5"
    assert ev.session_type == "shell"

    # store updated
    sessions = store.list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["id"] == "1"
    assert sessions[0]["host"] == "10.0.0.5"
    assert sessions[0]["status"] == "open"

    # known set updated
    assert tracker.known_session_ids() == {"1"}


def test_poll_second_sighting_does_not_refire(tmp_path):
    live = {"1": {"target_host": "10.0.0.5", "type": "shell"}}
    tracker, _, _, rec = _make(tmp_path, live_sessions=live)
    tracker._poll()
    tracker._poll()
    # Only one SessionStarted, even though _poll ran twice
    assert len(rec.started) == 1


def test_poll_closed_session_fires_close(tmp_path):
    live = {"1": {"target_host": "10.0.0.5", "type": "shell"}}
    tracker, client, store, rec = _make(tmp_path, live_sessions=live)
    tracker._poll()
    assert len(rec.started) == 1

    # Session disappears
    client._sessions = {}
    tracker._poll()

    assert len(rec.closed) == 1
    assert rec.closed[0].session_id == "1"
    # store shows closed (list_sessions filters to open by default)
    assert store.list_sessions() == []
    closed = store.list_sessions(include_closed=True)
    assert len(closed) == 1
    assert closed[0]["status"] == "closed"


def test_poll_tolerates_msf_unavailable_mid_flight(tmp_path):
    tracker, client, _, rec = _make(tmp_path, live_sessions={"1": {}})
    client.raise_on_sessions = MSFUnavailableError("gone")
    tracker._poll()  # must not raise
    assert rec.started == []
    assert rec.closed == []


def test_poll_updates_last_seen_for_existing(tmp_path):
    live = {"1": {"target_host": "10.0.0.5", "type": "shell"}}
    tracker, _, store, _ = _make(tmp_path, live_sessions=live)
    tracker._poll()
    first = store.list_sessions()[0]["last_seen"]

    time.sleep(0.05)
    # Same session, still present, richer info
    tracker._sessions = None  # not used, tracker holds its own client
    tracker._client._sessions = {"1": {"target_host": "10.0.0.5",
                                       "type": "shell",
                                       "extra": "yes"}}
    tracker._poll()

    sessions = store.list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["info"].get("extra") == "yes"
    assert sessions[0]["last_seen"] >= first


# ---------------------------------------------------------------- lifecycle

def test_start_then_stop(tmp_path):
    """Lifecycle: start() spawns a thread, stop() joins it."""
    live = {"1": {"target_host": "10.0.0.5", "type": "shell"}}
    tracker, _, store, rec = _make(tmp_path, live_sessions=live)
    tracker._interval = 0.05

    tracker.start()
    # First poll happens immediately; wait up to 1s for the store row.
    deadline = time.time() + 1.0
    while time.time() < deadline and not store.list_sessions():
        time.sleep(0.02)

    assert len(rec.started) == 1
    tracker.stop()
    assert tracker._thread is None or not tracker._thread.is_alive()


def test_start_is_idempotent(tmp_path):
    tracker, _, _, _ = _make(tmp_path)
    tracker._interval = 0.05
    tracker.start()
    t1 = tracker._thread
    tracker.start()  # second call must not spawn a second thread
    t2 = tracker._thread
    assert t1 is t2
    tracker.stop()


def test_loop_swallows_poll_exceptions(tmp_path):
    """A broken client that raises in is_up() must not crash the thread."""
    class BrokenClient:
        def is_up(self):
            raise RuntimeError("boom")

    bus = EventBus()
    store = JobStore(tmp_path / "b.db")
    tracker = MSFTracker(bus, store, client=BrokenClient(), interval_s=0.05)
    tracker.start()
    time.sleep(0.15)  # give it time to run and swallow the error
    assert tracker._thread is not None
    assert tracker._thread.is_alive()
    tracker.stop()