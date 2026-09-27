"""whaxon init — first-run setup. Detects Docker bridge, writes data/whaxon.env."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

DEFAULT_NETWORK = "whaxon-lab"
DEFAULT_SUBNET = "172.28.0.0/16"
DEFAULT_TARGET_IP = "172.28.0.10"


def _docker(*args: str) -> str:
    try:
        r = subprocess.run(["docker", *args], capture_output=True, text=True, check=False)
        return r.stdout.strip()
    except FileNotFoundError:
        return ""


def _detect_gateway(network: str) -> str:
    out = _docker("network", "inspect", network,
                  "--format", "{{(index .IPAM.Config 0).Gateway}}")
    if out:
        return out
    base = DEFAULT_SUBNET.split("/")[0].rsplit(".", 1)[0]
    return f"{base}.1"


def _detect_subnet(network: str) -> str | None:
    return _docker("network", "inspect", network,
                   "--format", "{{(index .IPAM.Config 0).Subnet}}") or None


def _detect_target_ip(network: str, container: str = "msf-target") -> str | None:
    fmt = ('{{range $k,$v := .NetworkSettings.Networks}}'
           '{{if eq $k "' + network + '"}}{{$v.IPAddress}}{{end}}{{end}}')
    return _docker("inspect", container, "--format", fmt) or None


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    p = argparse.ArgumentParser(prog="whaxon init")
    p.add_argument("--force", action="store_true")
    p.add_argument("--msf-pass", default="test123")
    p.add_argument("--msf-user", default="msf")
    p.add_argument("--msf-ssl", default="0", choices=["0", "1"])
    p.add_argument("--data", default="data")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return

    data = Path(ns.data)
    data.mkdir(parents=True, exist_ok=True)
    env_path = data / "whaxon.env"
    scope_path = data / "scope.json"

    print(f"[*] inspecting docker network {DEFAULT_NETWORK!r} ...")
    gateway = _detect_gateway(DEFAULT_NETWORK)
    subnet = _detect_subnet(DEFAULT_NETWORK) or DEFAULT_SUBNET
    target_ip = _detect_target_ip(DEFAULT_NETWORK) or DEFAULT_TARGET_IP
    print(f"[*] gateway  : {gateway}")
    print(f"[*] subnet   : {subnet}")
    print(f"[*] target   : {target_ip}")

    if env_path.exists() and not ns.force:
        print(f"[=] {env_path} exists — pass --force to overwrite")
    else:
        env_path.write_text(
            "# Auto-written by `whaxon init`. Edit freely.\n"
            f"WHAXON_MSF_SSL={ns.msf_ssl}\n"
            f"WHAXON_MSF_USER={ns.msf_user}\n"
            f"WHAXON_MSF_PASS={ns.msf_pass}\n"
            "WHAXON_MSF_AUTOCHAIN=0\n"
            f"WHAXON_LAB_TARGET={target_ip}\n"
            f"WHAXON_LAB_LHOST={gateway}\n"
            f"WHAXON_LAB_SUBNET={subnet}\n",
            encoding="utf-8",
        )
        print(f"[+] wrote {env_path}")

    if scope_path.exists() and not ns.force:
        print(f"[=] {scope_path} exists — pass --force to overwrite")
    else:
        scope_path.write_text(json.dumps({
            "engagement": "whaxon-lab",
            "enabled": True,
            "in_scope": [
                "127.0.0.1", "::1",
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                target_ip, subnet,
            ],
            "out_of_scope": [],
            "notes": "Auto-written by whaxon init.",
        }, indent=2), encoding="utf-8")
        print(f"[+] wrote {scope_path}")

    print()
    print("[+] init complete. Next:")
    print("      whaxon up")


if __name__ == "__main__":
    main()
