"""Typed events emitted by the core. Interfaces subscribe; core never knows."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

# ---------- Event types ----------

@dataclass(frozen=True, kw_only=True)
class Event:
    """Base class. All events carry a UTC timestamp."""
    ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True, kw_only=True)
class ToolDiscovered(Event):
    tool_id: str
    name: str
    category: str


@dataclass(frozen=True, kw_only=True)
class JobStarted(Event):
    job_id: str
    tool_id: str
    target: str


@dataclass(frozen=True, kw_only=True)
class JobOutput(Event):
    job_id: str
    stream: str
    line: str


@dataclass(frozen=True, kw_only=True)
class JobFinished(Event):
    job_id: str
    exit_code: int
    duration_s: float


@dataclass(frozen=True, kw_only=True)
class JobFailed(Event):
    job_id: str
    error: str


# ---------- Bus ----------

E = TypeVar("E", bound=Event)


class EventBus:
    """Async pub/sub. Thread-safe publish via loop.call_soon_threadsafe."""

    def __init__(self) -> None:
        self._subs: dict[type[Event], list[Callable[[Any], None]]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self, event_type: type[E], handler: Callable[[E], None]) -> Callable[[], None]:
        self._subs.setdefault(event_type, []).append(handler)
        def _unsub() -> None:
            self._subs[event_type].remove(handler)
        return _unsub

    def subscribe_queue(self, event_type: type[E]) -> "asyncio.Queue[E]":
        q: asyncio.Queue[E] = asyncio.Queue()
        self.subscribe(event_type, q.put_nowait)
        return q

    def publish(self, event: Event) -> None:
        handlers: list[Callable[[Any], None]] = []
        for cls in type(event).__mro__:
            handlers.extend(self._subs.get(cls, []))
        for h in handlers:
            if self._loop is not None and self._loop.is_running():
                self._loop.call_soon_threadsafe(h, event)
            else:
                h(event)
