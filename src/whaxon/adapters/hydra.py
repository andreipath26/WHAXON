"""Hydra adapter — credential attack results."""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register

# "[80][http-post-form] host: 172.17.0.3   login: admin   password: password"
_SUCCESS_RE = re.compile(
    r"^\[(?P<port>\d+)\]\[(?P<module>[^\]]+)\]\s+host:\s*(?P<host>\S+)"
    r"(?:\s+misc:\s*.*?)?\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)"
)


class HydraAdapter(Adapter):
    tool_id = "hydra"

    def parse(self, lines, ctx=None):
        out = []
        seen = set()
        for _stream, text in (lines or []):
            m = _SUCCESS_RE.match((text or "").strip())
            if not m:
                continue
            key = (m.group("host"), m.group("login"), m.group("password"))
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                kind="weak_credential",
                severity="high",
                source="hydra",
                data={
                    "host": m.group("host"),
                    "port": int(m.group("port")),
                    "module": m.group("module"),
                    "login": m.group("login"),
                    "password": m.group("password"),
                },
                raw_line=text.strip()[:200],
            ))
        return out


register(HydraAdapter())
