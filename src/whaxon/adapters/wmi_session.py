"""WMI session adapter — impacket-wmiexec output to Findings."""
from __future__ import annotations

from ..core.findings import Finding
from .base import Adapter
from .registry import register


class WmiSessionAdapter(Adapter):
    def __init__(self, tool_id: str) -> None:
        self.tool_id = tool_id

    def parse(self, lines, ctx=None):
        if isinstance(lines, list):
            text = "\n".join(
                str(item[1]) if isinstance(item, tuple) and len(item) == 2 else str(item)
                for item in lines
            )
        else:
            text = lines or ""
        ctx = ctx or {}
        findings = []
        for line in text.splitlines():
            s = line.strip()
            if not s:
                continue
            data = {"line": s[:200]}
            if ctx.get("session_id"):
                data["session_id"] = str(ctx["session_id"])
            findings.append(Finding(
                kind="wmi_result", severity="info", source=self.tool_id,
                data=data, raw_line=s[:200],
            ))
        return findings


for _tid in ("wmi_exec",):
    register(WmiSessionAdapter(_tid))
