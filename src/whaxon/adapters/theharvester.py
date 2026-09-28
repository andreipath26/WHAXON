"""theHarvester adapter — OSINT hostnames and emails.

theHarvester writes a JSON file when invoked with -f. The adapter
reads it via ctx["extra_args"] (looking for --log-json=... or -f ...)
or falls back to stdout if the file is not present.

The JSON shape (v4.x):
    {"cmd": "...", "hosts": ["a.example.com", "b.example.com", ...],
     "shops": [], "emails": [], "people": []}
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..core.findings import Finding
from .base import Adapter
from .registry import register


_F_PATH_RE = re.compile(r"(?:-f|--output-file)\s+(\S+)")

_log = logging.getLogger(__name__)

# Valid hostname: 1-253 chars, labels 1-63 chars, alnum + hyphen,
# dot-separated, optional trailing dot.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.[A-Za-z0-9-]{1,63})*\.?$"
)


def _clean_host(h: str) -> str | None:
    """Normalize a hostname from theHarvester output.

    theHarvester 4.11.1 with the DuckDuckGo source occasionally emits
    entries like ``2Fdocs.kali.org`` where a percent-encoded ``%2F``
    redirect artifact leaked into the first label. Strip a leading
    ``2F`` when the remainder still looks like a hostname, then
    validate against a conservative hostname regex. Returns None for
    anything that doesn't survive both checks.
    """
    h = (h or "").strip().strip(".")
    if not h:
        return None
    if h.startswith("2F") and "." in h:
        stripped = h[2:]
        if _HOSTNAME_RE.match(stripped):
            h = stripped
    if not _HOSTNAME_RE.match(h):
        return None
    return h


class TheHarvesterAdapter(Adapter):
    tool_id = "theharvester"

    def _json_path(self, ctx):
        """Find the output JSON path from ctx.

        Prefer ctx["outfile"] (set by the runner when the catalog
        tool declares an outfile_flag); fall back to scanning
        extra_args for legacy callers.
        """
        ctx = ctx or {}
        explicit = ctx.get("outfile") or ""
        if explicit:
            p = Path(explicit)
            if p.suffix != ".json":
                p = p.with_suffix(".json")
            return p if p.exists() else None
        extra = ctx.get("extra_args") or ""
        m = _F_PATH_RE.search(extra)
        if not m:
            return None
        # theHarvester writes both .json and .xml; we want the .json
        p = Path(m.group(1))
        if p.suffix != ".json":
            p = p.with_suffix(".json")
        return p if p.exists() else None

    def _from_json(self, path):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        findings = []
        for host in data.get("hosts") or []:
            raw = host
            clean = _clean_host(host)
            if clean is None:
                _log.debug("theharvester: dropped malformed host %r", raw)
                continue
            host = clean
            findings.append(Finding(
                kind="hostname",
                severity="info",
                source="theharvester",
                data={"host": host},
                raw_line=host,
                impact=(
                    "Subdomain disclosed via OSINT. Subdomains often expose "
                    "staging, internal, or forgotten systems that are less "
                    "hardened than the main domain."
                ),
            ))
        for email in data.get("emails") or []:
            email = (email or "").strip()
            if not email:
                continue
            findings.append(Finding(
                kind="email",
                severity="info",
                source="theharvester",
                data={"email": email},
                raw_line=email,
                impact=(
                    "Email address disclosed via OSINT. Useful for phishing, "
                    "credential stuffing, and identifying account naming "
                    "conventions."
                ),
            ))
        return findings

    def parse(self, lines, ctx=None):
        ctx = ctx or {}
        path = self._json_path(ctx)
        if path is None:
            if ctx.get("outfile") or _F_PATH_RE.search(ctx.get("extra_args") or ""):
                _log.warning(
                    "theharvester: output file expected but not found "
                    "(outfile=%r extra_args=%r)",
                    ctx.get("outfile"), ctx.get("extra_args"),
                )
            return []
        return self._from_json(path)


register(TheHarvesterAdapter())
