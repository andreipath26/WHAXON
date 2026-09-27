"""Prompt templates, loaded from disk so they can be versioned."""
from __future__ import annotations

from pathlib import Path

_DIR = Path(__file__).parent


def load(name: str) -> str:
    path = _DIR / name
    return path.read_text(encoding="utf-8")


def planner_v1() -> str:
    return load("planner_v1.md")
