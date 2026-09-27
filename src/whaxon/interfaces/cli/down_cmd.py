"""whaxon down — stop WHAXON, msfrpcd, and the lab container."""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

TARGET_NAME = "msf-target"


def _rc(cmd: list[str]) -> int:
    return subprocess.run(cmd, capture_output=True, text=True, check=False).returncode


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    p = argparse.ArgumentParser(prog="whaxon down")
    p.add_argument("--keep-docker", action="store_true")
    p.add_argument("--keep-msfrpcd", action="store_true")
    p.add_argument("--keep-network", action="store_true")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return

    pidfile = Path("data/whaxon.pid")
    if pidfile.exists():
        try:
            pid = int(pidfile.read_text().strip())
            print(f"[*] killing WHAXON (pid {pid})")
            subprocess.run(["kill", str(pid)], check=False)
        except (ValueError, FileNotFoundError):
            pass
    _rc(["pkill", "-f", "whaxon serve"])

    if not ns.keep_msfrpcd:
        if _rc(["pgrep", "-f", "msfrpcd"]) == 0:
            print("[*] stopping msfrpcd")
            subprocess.run(["sudo", "pkill", "-f", "msfrpcd"], check=False)

    if not ns.keep_docker:
        print(f"[*] removing container {TARGET_NAME}")
        subprocess.run(["docker", "rm", "-f", TARGET_NAME], check=False)
        if not ns.keep_network:
            print("[*] removing network whaxon-lab")
            subprocess.run(["docker", "network", "rm", "whaxon-lab"], check=False)

    print("[+] down")


if __name__ == "__main__":
    main()
