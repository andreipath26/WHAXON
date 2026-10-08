"""Auto-detect additional networks a session can reach."""
from __future__ import annotations

import ipaddress
import re

from .msf import MSFClient

_PRIVATE = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _read_session(client: MSFClient, sid: str, cmd: str, wait: float = 3.0) -> str:
    import time
    rpc = client.sessions.session(str(sid)) if hasattr(client, "sessions") and not callable(client.sessions) else client.connect().sessions.session(str(sid))
    rpc.write(cmd)
    time.sleep(wait)
    try:
        return rpc.read() or ""
    except Exception:
        return ""


def detect(client: MSFClient, sid: str) -> list[dict]:
    """Return candidate subnets the session can reach that the host cannot."""
    out = _read_session(client, sid, "ip route 2>/dev/null || route -n 2>/dev/null || netstat -rn 2>/dev/null", wait=3.0)
    cands = []
    seen = set()
    for line in out.splitlines():
        line = line.strip()
        # matches: "10.10.10.0/24 dev eth1 ...", "10.0.0.0 255.0.0.0 ...", "10.0.0.0/8 via ..."
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+(?:/\d+)?)", line):
            cidr = m.group(1)
            try:
                if "/" in cidr:
                    net = ipaddress.ip_network(cidr, strict=False)
                else:
                    # bare IP -> treat as /24 heuristic
                    net = ipaddress.ip_network(cidr + "/24", strict=False)
            except ValueError:
                continue
            if net.prefixlen < 8 or net.prefixlen > 30:
                continue
            if not any(net.subnet_of(p) for p in _PRIVATE):
                continue
            if net.is_loopback:
                continue
            key = str(net)
            if key in seen:
                continue
            seen.add(key)
            cands.append({"cidr": str(net), "source_line": line[:120]})
    return cands
