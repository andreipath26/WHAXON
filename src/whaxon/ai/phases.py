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
# Categories the planner may see in each phase, when phase gating is
# enabled (WHAXON_AI_PHASE_GATING=true). A tool whose category is not
# listed for the current phase is hidden from CATALOG. Session-scoped
# tools only appear at post-access and lateral — matching the session
# ladder in RulesProvider.
CATEGORY_BY_PHASE: dict[str, tuple[str, ...]] = {
    "recon": ("recon",),
    "enumeration": ("web",),
    "vulnerability": ("vuln", "web"),
    "initial-access": ("exploit", "vuln"),
    "post-access": ("session", "msf", "loot"),
    "lateral": ("session", "msf", "recon"),
    "done": (),
}


def categories_for(phase: str) -> tuple[str, ...]:
    return CATEGORY_BY_PHASE.get(phase, ())


def filter_catalog(catalog: list[dict], phase: str) -> list[dict]:
    """Drop tools whose category is not allowed for the given phase."""
    allowed = set(categories_for(phase))
    if not allowed:
        return []
    return [t for t in catalog if (t.get("category") or "") in allowed]
