"""Typed events emitted by the core. Interfaces subscribe; core never knows."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeVar

# ---------- Event types ----------

@dataclass(frozen=True, kw_only=True)
class Event:
    """Base class. All events carry a UTC timestamp."""
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))


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
class JobFindings(Event):
    job_id: str
    findings: tuple = ()


@dataclass(frozen=True, kw_only=True)
class JobFailed(Event):
    job_id: str
    error: str




@dataclass(frozen=True, kw_only=True)
class SessionStarted(Event):
    session_id: str
    host: str
    session_type: str
    info: dict = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class SessionClosed(Event):
    session_id: str


@dataclass(frozen=True, kw_only=True)
class SessionOutput(Event):
    session_id: str
    text: str

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

    def subscribe_queue(self, event_type: type[E]) -> asyncio.Queue[E]:
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
