"""Route resolver — v2 Phase E.2. Design ref: docs/session-execution.md §11."""
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class Route:
    target_host: str
    target_port: int
    local_port: int
    via_session: str

    def to_dict(self) -> dict:
        return asdict(self)


def resolve(portfwd_rows: list[dict], target_host: str) -> Route | None:
    """Return the first route that reaches the given host, or None.

    portfwd_rows: list of {session_id, lport, rhost, rport} dicts.
    Lookup is exact-host match on rhost.
    """
    if not target_host:
        return None
    for row in portfwd_rows or []:
        rhost = str(row.get("rhost") or "")
        if rhost != target_host:
            continue
        try:
            return Route(
                target_host=rhost,
                target_port=int(row.get("rport") or 0),
                local_port=int(row.get("lport") or 0),
                via_session=str(row.get("session_id") or ""),
            )
        except (TypeError, ValueError):
            continue
    return None


def rewrite_target(route: Route) -> str:
    """Return the local-side address a tool should be pointed at."""
    return "127.0.0.1:" + str(route.local_port)
