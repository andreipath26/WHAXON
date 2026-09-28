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
    args: str = ""
    package: str = ""
    available: bool = False
    # If set, the runner appends '<outfile_flag> <per-job-tempfile>' to
    # argv before user extra_args. Empty means the tool writes to stdout
    # only. Examples: '-f' (theHarvester), '-j' (dnsrecon).
    outfile_flag: str = ""


class ToolCatalog:
    def __init__(self, bus: EventBus, catalog_path: Path) -> None:
        self._bus = bus
        self.path = Path(catalog_path)
        self._tools: dict[str, Tool] = {}

    def load(self) -> None:
        import shutil
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        for entry in raw.get("tools", []):
            from dataclasses import fields as _dc_fields; _K={x.name for x in _dc_fields(Tool)}; tool = Tool(**{k:v for k,v in entry.items() if k in _K})
            # Detect whether the binary is on PATH
            available = shutil.which(tool.binary) is not None
            if available != tool.available:
                from dataclasses import replace
                tool = replace(tool, available=available)
            self._tools[tool.id] = tool
            self._bus.publish(ToolDiscovered(
                tool_id=tool.id, name=tool.name, category=tool.category,
            ))

    def list(self) -> list[Tool]:
        return list(self._tools.values())

    def get(self, tool_id: str) -> Tool | None:
        return self._tools.get(tool_id)
