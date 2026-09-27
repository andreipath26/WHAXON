"""Local port forwarding through a raw shell session.

WHAXON sends `socat` to the target, listening on `<lport>` and forwarding
to `<rhost>:<rport>` from the target's perspective. Caller connects to
<target-ip>:<lport> and reaches the service.

Works on shell sessions (no Meterpreter required). PID tracking lets
DELETE actually kill the listener.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, asdict, field


@dataclass
class Forward:
    session_id: str
    lport: int
    rhost: str
    rport: int
    target_pid: int | None = None
    started_at: float = 0.0
    label: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _session_obj(client, session_id: str):
    """Return the pymetasploit3 session handle (has .write()/.read()).

    MSFClient.sessions is a *convenience method* returning dict[str, dict].
    The write/read capable handle is on client.connect().sessions.session(id).
    """
    raw = client.connect()  # pymetasploit3 MsfRpcClient
    return raw.sessions.session(str(session_id))

_PID_RE = re.compile(r"SOCAT_PID=(\d+)", re.I)


def _read(rpc_session, quiet: float = 0.8, total: float = 3.0) -> str:
    """Read until output has been quiet for `quiet` seconds or `total` elapsed."""
    deadline = time.time() + total
    chunks: list[str] = []
    last_data = time.time()
    while time.time() < deadline:
        try:
            data = rpc_session.read() or ""
        except Exception:
            data = ""
        if data:
            chunks.append(data)
            last_data = time.time()
        elif time.time() - last_data >= quiet:
            break
        time.sleep(0.15)
    return "".join(chunks)


def _exec(rpc_session, cmd: str, wait: float = 2.5) -> str:
    rpc_session.write(cmd)
    time.sleep(0.25)
    return _read(rpc_session, total=wait)


def add_forward(client, session_id: str, lport: int, rhost: str, rport: int,
                label: str = "") -> Forward:
    """Spawn socat on the target and return a Forward record."""
    rpc = _session_obj(client, session_id)
    # fork  = accept concurrent connections
    # reuseaddr = allow restart when socket is in TIME_WAIT
    inner = (
        f"nohup socat TCP-LISTEN:{lport},fork,reuseaddr "
        f"TCP:{rhost}:{rport} >/dev/null 2>&1 & echo SOCAT_PID=$!"
    )
    raw = _exec(rpc, inner, wait=3.0)
    pid = None
    m = _PID_RE.search(raw)
    if m:
        pid = int(m.group(1))

    # sanity: confirm the port is bound
    check = _exec(rpc, f"(ss -tln 2>/dev/null || netstat -tln 2>/dev/null) | grep ':{lport} '", wait=1.5)
    if str(lport) not in check and "LISTEN" not in check:
        # not conclusive — some shells hide background output; still return
        pass

    return Forward(
        session_id=str(session_id),
        lport=int(lport),
        rhost=str(rhost),
        rport=int(rport),
        target_pid=pid,
        started_at=time.time(),
        label=label,
    )


def remove_forward(client, fwd: Forward) -> dict:
    """Kill the target-side socat by PID, falling back to port-based cleanup."""
    rpc = _session_obj(client, fwd.session_id)

    if fwd.target_pid:
        out = _exec(rpc, f"kill {fwd.target_pid} 2>/dev/null; echo KILLED_$?", wait=1.5)
        if "KILLED_0" in out:
            return {"ok": True, "method": "pid", "pid": fwd.target_pid}

    out = _exec(
        rpc,
        f"fuser -k {fwd.lport}/tcp 2>/dev/null; "
        f"pkill -f 'socat TCP-LISTEN:{fwd.lport}' 2>/dev/null; "
        f"echo CLEANUP_DONE",
        wait=2.0,
    )
    return {"ok": "CLEANUP_DONE" in out, "method": "port", "port": fwd.lport}


def list_live(client, session_id: str) -> list[dict]:
    """Ask the target which socat listeners are running."""
    rpc = _session_obj(client, session_id)
    out = _exec(rpc, "ps -eo pid,args 2>/dev/null | grep 'socat TCP-LISTEN' | grep -v grep", wait=2.0)
    rows: list[dict] = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(.+)$", line.strip())
        if m:
            cmd = m.group(2)
            lm = re.search(r"TCP-LISTEN:(\d+)", cmd)
            rm = re.search(r"TCP:([\d\.\w\-]+):(\d+)", cmd)
            rows.append({
                "pid": int(m.group(1)),
                "lport": int(lm.group(1)) if lm else None,
                "rhost": rm.group(1) if rm else None,
                "rport": int(rm.group(2)) if rm else None,
                "cmd": cmd,
            })
    return rows
