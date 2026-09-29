"""Objective parsing and terminal-phase mapping.

Design reference: docs/autonomous-loop.md §3.1.

An objective is a goal string like "enumerate 10.0.0.5". The parser
extracts a verb and maps it to the kill-chain phase at which the
objective is considered met. Verbs that don't parse leave the loop
in its current behavior: model decides stop, budget decides stop.
"""
from __future__ import annotations

import re

# Verb -> terminal phase. An objective is done when the loop reaches
# this phase for the parsed verb.
TERMINAL_PHASE = {
    "recon": "recon",
    "scan": "recon",
    "enumerate": "enumeration",
    "test": "vulnerability",
    "foothold": "initial-access",
    "exploit": "post-access",
}

_VERB_RX = re.compile(r"^\s*([a-zA-Z]+)\b")


def parse_verb(goal: str) -> str | None:
    """Extract the leading verb from a goal string, or None.

    Only returns verbs in TERMINAL_PHASE. Unknown verbs return None,
    which means "no terminal phase known" and the loop keeps its
    default stop conditions.
    """
    if not goal:
        return None
    m = _VERB_RX.match(goal)
    if not m:
        return None
    verb = m.group(1).lower()
    return verb if verb in TERMINAL_PHASE else None


def terminal_phase(goal: str) -> str | None:
    """Return the phase at which the objective is met, or None."""
    verb = parse_verb(goal)
    return TERMINAL_PHASE.get(verb) if verb else None


def is_terminal(goal: str, current_phase: str) -> bool:
    """True if the current phase matches the objective's terminal phase."""
    tp = terminal_phase(goal)
    if tp is None:
        return False
    return current_phase == tp
