"""Deterministic auto-chain rules.

Watches JobFindings. When a job finishes and matches a rule condition,
queues a follow-up job — no AI involved. Disabled via
WHAXON_AUTOCHAIN=false.

Rule 1 (web_port_fanout):
  After an nmap job, for each open_port finding with an HTTP-ish
  service or a standard web port number, queue one nikto run against
  that specific port — unless a nikto job already ran against it in
  this engagement.
"""
from __future__ import annotations

import os
import threading
import traceback
from typing import Any

from .events import EventBus, JobFindings


_WEB_SERVICES = {'http', 'http-proxy', 'http-alt', 'https', 'ssl', 'https-alt'}
_WEB_PORTS = {80, 443, 8000, 8080, 8188, 8180, 8443, 8888, 9000}


def _autochain_enabled() -> bool:
    return os.environ.get('WHAXON_AUTOCHAIN', 'true').lower() in ('1', 'true', 'yes', 'on')


class Automator:
    """Fires deterministic follow-up jobs. Attaches to JobFindings."""

    def __init__(self, bus: EventBus, store, runner) -> None:
        self.bus = bus
        self.store = store
        self.runner = runner
        self._inflight: set[tuple[str, int]] = set()
        self._lock = threading.Lock()

    def attach(self) -> None:
        self.bus.subscribe(JobFindings, self._on_findings)

    def _on_findings(self, e: JobFindings) -> None:
        if not _autochain_enabled():
            return
        try:
            job = self.store.get(e.job_id)
        except Exception:
            return
        if not job or job.get('tool') != 'nmap':
            return
        target = job.get('target') or ''
        if not target:
            return

        web_ports: list[tuple[str, int, str]] = []
        for f in e.findings or ():
            if f.get('kind') != 'open_port':
                continue
            d = f.get('data') or {}
            port = d.get('port')
            svc = str(d.get('service') or '').lower()
            if not isinstance(port, int):
                continue
            if port in _WEB_PORTS or svc in _WEB_SERVICES:
                web_ports.append((target, port, svc))

        for tgt, port, svc in web_ports:
            key = (tgt, port)
            with self._lock:
                if key in self._inflight:
                    continue
                if self._already_ran_nikto(tgt, port):
                    continue
                self._inflight.add(key)
            self._queue_nikto(tgt, port, svc)

    def _already_ran_nikto(self, target: str, port: int) -> bool:
        """True if a nikto job already ran against target:port."""
        want = f'{target}:{port}'
        try:
            for j in self.store.history(limit=200):
                if j.get('tool') == 'nikto' and (j.get('target') or '') == want:
                    return True
        except Exception:
            return False
        return False

    def _queue_nikto(self, target: str, port: int, service: str) -> None:
        """Start a nikto job in a daemon thread against target:port.

        Skipped silently if nikto is not in the catalog (e.g. whaxon init --demo,
        which only ships nmap and echo).
        """
        try:
            if not self.runner.has_tool('nikto'):
                return
        except Exception:
            return

        def _run() -> None:
            import asyncio
            try:
                asyncio.run(self.runner.run_tool(
                    tool_id='nikto',
                    target=f'{target}:{port}',
                ))
            except Exception:
                traceback.print_exc()
        threading.Thread(target=_run, daemon=True, name=f'autochain-nikto-{port}').start()
