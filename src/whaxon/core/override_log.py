"""Append-only override log — one writer for every override surface.

Scope overrides (web/GUI/TUI) and bounty program-policy overrides share
this. One format, one place to read, no per-interface guessing about
where the data dir is.

Format, tab-separated, append-only:

    <ISO-8601-UTC timestamp>\t<tool_id>\t<target>[\t<program>]

The program column is absent for scope overrides, present for policy
overrides. Readers tolerate three or four fields.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

_log = logging.getLogger(__name__)

LOG_NAME = "scope_overrides.log"


def log_path(data_dir: str | Path) -> Path:
    return Path(data_dir) / LOG_NAME


def log_override(data_dir: str | Path, tool_id: str, target: str,
                 *, program: str | None = None) -> bool:
    """Append one override line. True on write, False on OSError.

    Never raises on a filesystem error; logs a warning so the failed
    audit trail is visible.
    """
    p = log_path(data_dir)
    ts = datetime.now(UTC).isoformat()
    parts = [ts, (tool_id or "").strip(), (target or "").strip()]
    if program:
        parts.append(str(program).strip())
    line = "\t".join(parts) + "\n"
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(line)
        return True
    except OSError as e:
        _log.warning("override log not written (%s): %s", p, e)
        return False


def read_overrides(data_dir: str | Path) -> list[dict]:
    """Return every override as a dict. Tolerates historical epoch-float
    timestamps and the three- or four-field shapes."""
    p = log_path(data_dir)
    if not p.exists():
        return []
    out: list[dict] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) < 3:
            continue
        out.append({"ts": parts[0], "tool_id": parts[1],
                    "target": parts[2],
                    "program": parts[3] if len(parts) > 3 else ""})
    return out


def read_overrides_json(data_dir: str | Path) -> str:
    return json.dumps(read_overrides(data_dir), indent=2)
