"""WHAXON core — headless, UI-agnostic."""
from __future__ import annotations

import asyncio
from pathlib import Path

from .catalog import ToolCatalog
from .events import EventBus, JobFailed, JobFindings, JobFinished, JobOutput, JobStarted
from .msf import MSFClient
from .msf_tracker import MSFTracker
from .runner import ToolRunner
from .scope import ScopeManager
from .store import JobStore


class Core:
    """Single entry point for every interface. Holds no UI state."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.bus = EventBus()
        self.catalog = ToolCatalog(self.bus, self.data_dir / "tools.json")
        self.scope = ScopeManager(self.data_dir / "scope.json")
        from .settings import Settings
        self.settings = Settings(self.data_dir / "settings.json")
        # Phase E.2: a resolver that queries live portfwd state on demand.
        # Returns None on any MSF failure, so the runner behaves normally
        # when Metasploit is not running.
        from .routes import live_resolver
        _route_resolver = live_resolver()
        self.runner = ToolRunner(self.bus, self.catalog, self.scope,
                                 route_resolver=_route_resolver)
        # SQLite-backed persistence for all UIs
        state_path = self.data_dir / "whaxon.db"
        self.store = JobStore(state_path)
        # Cross-finding correlation (deterministic, no AI).
        from .correlator import Correlator
        self.correlator = Correlator(self.bus, self.store)
        self.correlator.attach()

        # Attach next-step suggestions from adapters to findings.
        from .suggester import Suggester
        def _adapter_lookup(tool_id):
            try:
                from ..adapters import get_adapter
                return get_adapter(tool_id)
            except Exception:
                return None
        self.suggester = Suggester(self.bus, self.store, _adapter_lookup)
        self.suggester.attach()

        # Deterministic auto-chain rules (nmap -> nikto per web port).
        from .automation import Automator
        self.automator = Automator(self.bus, self.store, self.runner)
        self.automator.attach()
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
