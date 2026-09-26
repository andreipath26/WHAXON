"""BACKFORGE core — headless, UI-agnostic."""
from __future__ import annotations

import asyncio
from pathlib import Path

from .events import EventBus
from .catalog import ToolCatalog
from .runner import ToolRunner


class Core:
    """Single entry point for every interface. Holds no UI state."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.bus = EventBus()
        self.catalog = ToolCatalog(self.bus, self.data_dir / "tools.json")
        self.runner = ToolRunner(self.bus, self.catalog)
        # Load synchronously so any UI can query the catalog immediately.
        if self.catalog.path.exists():
            self.catalog.load()

    async def initialize(self) -> None:
        """Called once by any interface. Awaitable inside a splash screen."""
        self.bus.bind_loop(asyncio.get_running_loop())
        if self.catalog.path.exists():
            self.catalog.load()
