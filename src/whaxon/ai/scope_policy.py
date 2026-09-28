"""Scope-expansion policy vocabulary.

Design reference: docs/agent-architecture.md §9.

v1 ships "strict" only: every discovered host is out of scope until
the human adds it to data/scope.json. "inherited" and "recommended"
are documented but not implemented; selecting either logs a warning
and falls back to strict. Starting strict and moving to looser is
easy. Starting loose and trying to tighten is a rewrite.
"""
from __future__ import annotations

import logging
import os

POLICIES: tuple[str, ...] = ("strict", "inherited", "recommended")
DEFAULT_POLICY = "strict"

_log = logging.getLogger(__name__)


def is_valid(policy: str) -> bool:
    return policy in POLICIES


def read_policy(env: dict[str, str] | None = None) -> str:
    """Read WHAXON_AI_SCOPE_EXPANSION. Default strict.

    Unknown or non-strict values warn and fall back to strict. v1
    implements strict only; the other two are v2 deferrals.
    """
    src = env if env is not None else os.environ
    raw = (src.get("WHAXON_AI_SCOPE_EXPANSION") or "").strip().lower()
    if not raw:
        return DEFAULT_POLICY
    if raw not in POLICIES:
        _log.warning(
            "WHAXON_AI_SCOPE_EXPANSION=%r is not a known policy; using strict",
            raw,
        )
        return DEFAULT_POLICY
    if raw != "strict":
        _log.warning(
            "WHAXON_AI_SCOPE_EXPANSION=%r is not implemented in v1; using strict",
            raw,
        )
        return DEFAULT_POLICY
    return raw
