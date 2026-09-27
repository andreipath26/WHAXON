"""User settings — single source of truth for theme, autochain, etc.

Persists to data/settings.json. Any UI (web, TUI, GUI) reads and writes
the same file, so a change in one is visible to the others.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()

_DEFAULTS: dict[str, Any] = {
    "theme": "system",
    "autochain": False,
    "confirm_destructive": True,
}


class Settings:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._data: dict[str, Any] = dict(_DEFAULTS)
        self.load()

    def load(self) -> dict[str, Any]:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    merged = dict(_DEFAULTS)
                    merged.update(raw)
                    self._data = merged
            except Exception:
                pass
        return dict(self._data)

    def save(self, data: dict[str, Any]) -> dict[str, Any]:
        with _LOCK:
            current = dict(self._data)
            for k, v in (data or {}).items():
                if k in _DEFAULTS:
                    current[k] = v
            self._data = current
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(current, indent=2), encoding="utf-8")
            return dict(current)

    def get(self) -> dict[str, Any]:
        return dict(self._data)
