"""Tool catalog: reads a JSON manifest, emits ToolDiscovered events."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .events import EventBus, ToolDiscovered


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    category: str
    binary: str
    description: str = ""
    available: bool = False


class ToolCatalog:
    def __init__(self, bus: EventBus, catalog_path: Path) -> None:
        self._bus = bus
        self.path = Path(catalog_path)
        self._tools: dict[str, Tool] = {}

    def load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        for entry in raw.get("tools", []):
            tool = Tool(**entry)
            self._tools[tool.id] = tool
            self._bus.publish(ToolDiscovered(
                tool_id=tool.id, name=tool.name, category=tool.category,
            ))

    def list(self) -> list[Tool]:
        return list(self._tools.values())

    def get(self, tool_id: str) -> Tool | None:
        return self._tools.get(tool_id)
