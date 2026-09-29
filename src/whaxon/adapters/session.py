"""Session-scoped adapter — dispatches to msf_parsers per tool_id.

Three session tools ship in v1: msf_sysinfo, msf_getuid, msf_hashdump.
Each has a literal command (defined in data/tools.json) whose output
maps to one of the msf_parsers functions.

The adapter converts each parser's Result dict into a Finding. The
Finding kinds match what the msf adapter already produces for the
same data (sysinfo, ntlm_hash), so correlators and reports see the
same shapes regardless of whether the data came from a module run or
a session command.
"""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .msf_parsers import parse_sysinfo, parse_hashdump
from .registry import register


# getuid output: "Server username: <user>"
_GETUID_RE = re.compile(r"Server username:\s*(.+?)\s*$", re.MULTILINE)


def _parse_getuid(out: str) -> list[dict]:
    results = []
    for m in _GETUID_RE.finditer(out or ""):
        username = m.group(1).strip()
        if username:
            results.append({
                "kind": "sysinfo",
                "data": {"field": "current_user", "value": username},
                "raw": f"current_user: {username}",
            })
    return results


_PARSERS = {
    "msf_sysinfo": parse_sysinfo,
    "msf_getuid": _parse_getuid,
    "msf_hashdump": parse_hashdump,
}


class SessionAdapter(Adapter):
    """Adapter for session-scoped tools.

    One instance per tool_id: the registry maps tool_id -> adapter, so
    this class is registered three times with different tool_id values.
    """

    def __init__(self, tool_id: str) -> None:
        self.tool_id = tool_id

    def parse(self, lines, ctx=None):
        text = "\n".join(t for _stream, t in (lines or []))
        parser = _PARSERS.get(self.tool_id)
        if parser is None:
            return []
        raw_results = parser(text)
        findings = []
        for r in raw_results:
            data = dict(r.get("data") or {})
            ctx = ctx or {}
            if ctx.get("session_id"):
                data["session_id"] = str(ctx["session_id"])
            findings.append(Finding(
                kind=r.get("kind", "session_output"),
                severity="info",
                source=self.tool_id,
                data=data,
                raw_line=(r.get("raw") or "")[:200],
            ))
        return findings


# Register one instance per session tool_id.
for _tid in _PARSERS:
    register(SessionAdapter(_tid))