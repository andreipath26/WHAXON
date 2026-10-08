"""Arjun adapter — HTTP parameter discovery via JSON output."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..core.findings import Finding
from .base import Adapter
from .registry import register

_JSON_PATH_RE = re.compile(r"-oJ?\s+(\S+\.json)")


def _json_path(ctx: dict) -> Path | None:
    """Prefer ctx[outfile]; fall back to extra_args regex."""
    of = (ctx or {}).get("outfile")
    if of:
        p = Path(str(of))
        if p.exists():
            return p
    extra = (ctx or {}).get("extra_args") or ""
    m = _JSON_PATH_RE.search(extra)
    if m:
        p = Path(m.group(1))
        if p.exists():
            return p
    return None


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


class ArjunAdapter(Adapter):
    tool_id = "arjun"

    def parse(self, lines, ctx=None):
        ctx = ctx or {}
        path = _json_path(ctx)
        if path is None:
            return []
        data = _load_json(path)
        if not data:
            return []
        findings: list[Finding] = []
        target = str(ctx.get("target") or "")
        for url, params in data.items():
            if not isinstance(params, list):
                continue
            for p in params:
                if not isinstance(p, str):
                    continue
                findings.append(Finding(
                    kind="http_param", severity="low", source="arjun",
                    data={"url": url, "parameter": p, "target": target},
                    raw_line=(url + " ?" + p)[:200],
                    remediation="Review parameter handling and input validation.",
                    impact="Hidden HTTP parameter discovered. Attack surface expanded.",
                    cwe="CWE-200",
                ))
        return findings


register(ArjunAdapter())
