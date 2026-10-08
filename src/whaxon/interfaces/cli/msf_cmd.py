"""whaxon msf — check Metasploit RPC status and sessions."""
from __future__ import annotations

import sys
from pathlib import Path

from whaxon.core import Core
from whaxon.core.msf import MSFClient, MSFConfig, MSFUnavailableError


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    action = "status"
    data_dir = Path("data")

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif a in ("--status", "status"):
            action = "status"; i += 1
        elif a in ("--sessions", "sessions"):
            action = "sessions"; i += 1
        elif a in ("--modules", "modules"):
            action = "modules"; i += 1
        elif a in ("-h", "--help"):
            _help(); return
        else:
            print(f"Unknown arg: {a}")
            _help()
            sys.exit(2)

    cfg = MSFConfig.from_env()
    client = MSFClient(cfg)

    if action == "status":
        print(f"Metasploit RPC @ {cfg.display()}")
        print(f"User: {cfg.user}")
        print()
        if not client.is_up():
            print("Status: DOWN (daemon not reachable)")
            print()
            print("To start the daemon:")
            print(f"  msfrpcd -U {cfg.user} -P <password> -a {cfg.host} -p {cfg.port} -f")
            sys.exit(1)
        print("Status: UP")
        try:
            print(f"Version: {client.version()}")
        except MSFUnavailableError as e:
            print(f"Version: (error: {e})")
        return

    if action == "modules":
        if not client.is_up():
            print("Metasploit daemon not reachable.")
            sys.exit(1)
        counts = client.module_counts()
        for kind, n in counts.items():
            print(f"  {kind:12} {n}")
        return

    if action == "sessions":
        core = Core(data_dir=data_dir)
        stored = core.store.list_sessions()
        print(f"Stored sessions: {len(stored)}")
        for s in stored:
            print(f"  #{s['id']:5} {s['type']:12} {s['host']:20} {s['status']}")

        if client.is_up():
            live = client.sessions()
            print()
            print(f"Live sessions (from RPC): {len(live)}")
            for sid, info in live.items():
                host = info.get("target_host") or info.get("tunnel_peer") or "?"
                stype = info.get("type") or "?"
                print(f"  #{sid:5} {stype:12} {host}")
        else:
            print()
            print("(RPC unreachable — showing stored sessions only)")
        return


def _help() -> None:
    print("Usage:")
    print("  whaxon msf --status     Check RPC daemon status and version")
    print("  whaxon msf --modules    List module counts")
    print("  whaxon msf --sessions   List live + stored sessions")
