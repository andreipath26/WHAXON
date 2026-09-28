"""Kill-chain phase vocabulary. Design reference: docs/agent-architecture.md §5."""
from __future__ import annotations

PHASES: tuple[str, ...] = (
    "recon",
    "enumeration",
    "vulnerability",
    "initial-access",
    "post-access",
    "lateral",
    "done",
)

DEFAULT_PHASE = "recon"


def is_valid(phase: str) -> bool:
    return phase in PHASES
