"""Auto-answer policy for --auto mode. Design ref: docs/autonomous-loop.md §3.3, §3.4."""
from __future__ import annotations

import logging
import os

_log = logging.getLogger(__name__)

HIGH_RISK_PHASES = ("initial-access", "post-access", "lateral")


def _allowed_phases(env=None):
    src = env if env is not None else os.environ
    raw = (src.get("WHAXON_AI_AUTO_PHASES") or "").strip()
    if not raw:
        return set()
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def _confirm_required(env=None):
    src = env if env is not None else os.environ
    return (src.get("WHAXON_AI_AUTO_CONFIRM") or "").strip().lower() in ("1", "true", "yes")


def warn_high_risk(env=None):
    allowed = _allowed_phases(env)
    return [p for p in HIGH_RISK_PHASES if p in allowed]


def answer_question(action, goal="", env=None):
    proposed = getattr(action, "proposed_phase", None)
    if proposed:
        p = str(proposed).strip().lower()
        if _confirm_required(env):
            return ""
        if p in _allowed_phases(env):
            return "y"
        return "n"
    return "skip"
