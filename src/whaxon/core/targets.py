"""Extract a target host from free-text. Deterministic, no AI."""
from __future__ import annotations

import re

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOSTNAME = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def extract_target(text):
    """Return the first IPv4 or hostname found in text, or None.

    IPv4 wins over hostname. Returns the literal string as it appears.
    """
    if not text:
        return None
    m = _IPV4.search(text)
    if m:
        return m.group(0)
    m = _HOSTNAME.search(text)
    if m:
        return m.group(0)
    return None
