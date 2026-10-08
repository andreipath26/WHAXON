"""Route resolver — v2 Phase E.2. Design ref: docs/session-execution.md §11."""
from __future__ import annotations

from dataclasses import asdict, dataclass


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


def live_resolver(msf_client=None):
    """Return a route_resolver callable backed by live MSF portfwd state.

    On any failure (MSF unreachable, no sessions, no forwards) the
    returned callable returns None — the runner then behaves exactly
    as if no resolver were configured.
    """
    def _resolve(host: str):
        if not host:
            return None
        try:
            from .msf import MSFClient
            from .portfwd import list_live
            client = msf_client or MSFClient()
            if not client.is_up():
                return None
            rows: list[dict] = []
            for sid in client.sessions():
                try:
                    live = list_live(client, sid)
                except Exception:
                    continue
                for r in live:
                    r = dict(r)
                    r.setdefault("session_id", sid)
                    rows.append(r)
            return resolve(rows, host)
        except Exception:
            return None
    return _resolve
