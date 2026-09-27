"""Backend ABC: chat(messages) -> str. Stdlib only."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BackendError(RuntimeError):
    """Raised by a backend when the request cannot be completed."""


class LLMBackend(ABC):
    """One provider API behind a uniform chat interface.

    A backend is responsible for:
      - serialising the message list into the provider request shape
      - authenticating
      - parsing the response into a plain assistant string

    It is NOT responsible for planning, JSON parsing, or action
    validation. That belongs to LLMProvider.
    """

    name: str = "backend"

    def __init__(self, model: str, **options: Any) -> None:
        self.model = model
        self.options = options

    @abstractmethod
    def chat(self, messages: list[dict], timeout: float = 60.0) -> str:
        """Send messages, return assistant text. Raise BackendError on failure."""

    def available(self) -> tuple[bool, str]:
        """Return (ok, reason). Default: ok unless a subclass overrides."""
        return True, ""
