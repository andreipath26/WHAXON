"""SMB session adapter — impacket-smbclient output to Findings."""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register

_SHARE_RE = re.compile(r"^\s*(\S+)\s+(Disk|IPC|Printer|Device)", re.MULTILINE)
_FILE_RE = re.compile(r"^\s*(-?[d-][rwx-]{9}\s+.*)$", re.MULTILINE)


def _parse_shares(out: str) -> list[dict]:
    results = []
    for m in _SHARE_RE.finditer(out or ""):
        name, kind = m.group(1), m.group(2)
        results.append({
            "kind": "smb_share",
            "data": {"name": name, "type": kind},
            "raw": name + " " + kind,
        })
    return results


def _parse_ls(out: str) -> list[dict]:
    results = []
    for m in _FILE_RE.finditer(out or ""):
        line = m.group(1).strip()
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        perms, _links, _owner, rest = parts
        results.append({
            "kind": "smb_entry",
            "data": {"perms": perms, "path": rest[:200]},
            "raw": line[:200],
        })
    return results


_PARSERS = {
    "smb_shares": _parse_shares,
    "smb_ls": _parse_ls,
}


class SmbSessionAdapter(Adapter):
    def __init__(self, tool_id: str) -> None:
        self.tool_id = tool_id

    def parse(self, lines, ctx=None):
        text = "\n".join(t for _s, t in (lines or []))
        parser = _PARSERS.get(self.tool_id)
        if parser is None:
            return []
        ctx = ctx or {}
        findings = []
        for r in parser(text):
            data = dict(r.get("data") or {})
            if ctx.get("session_id"):
                data["session_id"] = str(ctx["session_id"])
            findings.append(Finding(
                kind=r.get("kind", "smb_output"),
                severity="info",
                source=self.tool_id,
                data=data,
                raw_line=(r.get("raw") or "")[:200],
            ))
        return findings


for _tid in _PARSERS:
    register(SmbSessionAdapter(_tid))
