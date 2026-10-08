"""Polls the Metasploit RPC for session changes and emits events.

Runs in a background thread. Safe to start/stop at any time. If the RPC
daemon is unreachable, polling silently does nothing — no exceptions.
"""
from __future__ import annotations

import threading

from .events import EventBus, SessionClosed, SessionStarted
from .msf import MSFClient, MSFUnavailableError


class MSFTracker:
    def __init__(
        self,
        bus: EventBus,
        store,
        client: MSFClient | None = None,
        interval_s: float = 5.0,
    ) -> None:
        self._bus = bus
        self._store = store
        self._client = client or MSFClient()
        self._interval = interval_s
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._known: set[str] = set()

    # ---- lifecycle ----

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    # ---- internals ----

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception:
                # Never crash the tracker on a poll failure
                pass
            self._stop.wait(self._interval)

    def _poll(self) -> None:
        if not self._client.is_up():
            return
        try:
            live = self._client.sessions()
        except MSFUnavailableError:
            return
        current = set(live.keys())

        # New sessions
        for sid in current - self._known:
            info = live.get(sid, {})
            host = (info.get("target_host")
                    or info.get("tunnel_peer")
                    or "?")
            stype = info.get("type") or "?"
            self._store.upsert_session(sid, host, stype, info)
            self._bus.publish(SessionStarted(
                session_id=sid, host=host, session_type=stype, info=info,
            ))

        # Closed sessions
        for sid in self._known - current:
            self._store.close_session(sid)
            self._bus.publish(SessionClosed(session_id=sid))

        # Update last_seen for still-open ones
        for sid in current & self._known:
            info = live.get(sid, {})
            self._store.upsert_session(
                sid, info.get("target_host", "?"),
                info.get("type", "?"), info,
            )

        self._known = current

    # ---- introspection ----

    def known_session_ids(self) -> set[str]:
        return set(self._known)
