"""WHAXON core — headless, UI-agnostic."""
from __future__ import annotations

import asyncio
from pathlib import Path

from .events import EventBus, JobFailed, JobFinished, JobFindings, JobOutput, JobStarted
from .store import JobStore
from .scope import ScopeManager
from .msf import MSFClient
from .msf_tracker import MSFTracker
from .catalog import ToolCatalog
from .runner import ToolRunner


class Core:
    """Single entry point for every interface. Holds no UI state."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.bus = EventBus()
        self.catalog = ToolCatalog(self.bus, self.data_dir / "tools.json")
        self.scope = ScopeManager(self.data_dir / "scope.json")
        from .settings import Settings
        self.settings = Settings(self.data_dir / "settings.json")
        self.runner = ToolRunner(self.bus, self.catalog, self.scope)
        # SQLite-backed persistence for all UIs
        state_path = self.data_dir / "whaxon.db"
        self.store = JobStore(state_path)
        self._wire_store()
        # Metasploit RPC + session tracker
        self.msf = MSFClient()
        self.msf_tracker = MSFTracker(self.bus, self.store, self.msf)
        # Scope enforcement
        if self.catalog.path.exists():
            self.catalog.load()

    def _wire_store(self) -> None:
        """Subscribe the store to every job event so history persists."""
        def _on_started(e):
            self.store.create(e.job_id)
            self.store.set_started(e.job_id, e.tool_id, e.target)
        def _on_output(e):
            self.store.append_line(e.job_id, e.stream, e.line)
        def _on_finished(e):
            self.store.set_finished(e.job_id, e.exit_code, e.duration_s)
        def _on_failed(e):
            self.store.set_failed(e.job_id, e.error)
        def _on_findings(e):
            for i, f in enumerate(e.findings):
                self.store.append_finding(e.job_id, f, i)
        self.bus.subscribe(JobStarted, _on_started)
        self.bus.subscribe(JobOutput, _on_output)
        self.bus.subscribe(JobFinished, _on_finished)
        self.bus.subscribe(JobFailed, _on_failed)
        self.bus.subscribe(JobFindings, _on_findings)

    async def initialize(self) -> None:
        """Called once by any interface. Awaitable inside a splash screen."""
        self.bus.bind_loop(asyncio.get_running_loop())
        if self.catalog.path.exists():
            self.catalog.load()
