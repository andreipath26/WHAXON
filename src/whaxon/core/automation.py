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

from .events import EventBus, JobFailed, JobFindings, JobFinished

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
        self._followups_by_source: dict[str, set[str]] = {}
        self._source_by_followup: dict[str, str] = {}
        self._lock = threading.Lock()
        # V2 ownership is persisted in JobStore, never a bounded in-memory
        # flag that is consumed on the first findings event.

    def suppress_legacy_followup(self, job_id: str) -> None:
        """Persist a V2-origin fence before ToolRunner can emit findings."""
        self.store.mark_engine_v2_execution_job(job_id)

    def attach(self) -> None:
        self.bus.subscribe(JobFindings, self._on_findings)
        self.bus.subscribe(JobFinished, self._on_followup_terminal)
        self.bus.subscribe(JobFailed, self._on_followup_terminal)

    def _on_findings(self, e: JobFindings) -> None:
        # Missing durable ownership metadata must not be guessed from a
        # transient callback. If provenance storage is unavailable, do not
        # initiate legacy follow-up work.
        try:
            if self.store.is_engine_v2_execution_job(e.job_id):
                return
        except Exception:
            return
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
            self._queue_nikto(tgt, port, svc, source_job_id=e.job_id)

    def _on_followup_terminal(self, event: JobFinished | JobFailed) -> None:
        """Drop source tracking once a queued follow-up reaches a terminal state."""
        with self._lock:
            source_job_id = self._source_by_followup.pop(event.job_id, None)
            if source_job_id is None:
                return
            followups = self._followups_by_source.get(source_job_id)
            if followups is not None:
                followups.discard(event.job_id)
                if not followups:
                    self._followups_by_source.pop(source_job_id, None)

    def take_queued_followups(self, source_job_id: str) -> set[str]:
        """Return and clear pending follow-ups caused by one source job."""
        with self._lock:
            followups = self._followups_by_source.pop(source_job_id, set())
            for followup_id in followups:
                self._source_by_followup.pop(followup_id, None)
            return followups

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

    def _queue_nikto(
        self, target: str, port: int, service: str, *, source_job_id: str = "",
    ) -> str | None:
        """Queue a nikto job as a durable pending row against target:port.

        The row survives process exit. A worker (started by any long-lived
        host, or by the jobs drain command) claims and runs it. Replaces the
        old daemon-thread design, which died with the CLI process and left
        the job stuck at 'running' forever.
        """
        try:
            if not self.runner.has_tool('nikto'):
                return None
        except Exception:
            return None
        import uuid
        job_id = uuid.uuid4().hex[:12]
        # Register provenance while holding the same lock used by terminal
        # cleanup. A fast worker may finish as soon as the durable row exists.
        with self._lock:
            if source_job_id:
                self._followups_by_source.setdefault(source_job_id, set()).add(job_id)
                self._source_by_followup[job_id] = source_job_id
            try:
                self.store.create_pending(job_id, 'nikto', f'{target}:{port}')
            except Exception:
                if source_job_id:
                    self._source_by_followup.pop(job_id, None)
                    followups = self._followups_by_source.get(source_job_id)
                    if followups is not None:
                        followups.discard(job_id)
                        if not followups:
                            self._followups_by_source.pop(source_job_id, None)
                raise
        return job_id

