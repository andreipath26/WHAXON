"""whaxon up — bring up the whole lab in one command."""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

TARGET_NAME = "msf-target"
TARGET_IMAGE = "tleemcjr/metasploitable2"
TARGET_NETWORK = "whaxon-lab"
TARGET_SUBNET = "172.28.0.0/16"
TARGET_IP = "172.28.0.10"


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, check=False, **kw)


def _load_env(env_path):
    if not env_path.exists():
        print(f"[!] {env_path} missing — run `whaxon init` first")
        sys.exit(1)
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())


def _wait_tcp(host, port, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _container_status(name):
    r = _run(["docker", "inspect", name, "--format", "{{.State.Status}}"])
    out = (r.stdout or "").strip()
    return out or None


def _ensure_network():
    r = _run(["docker", "network", "inspect", TARGET_NETWORK, "--format", "{{.Id}}"])
    if r.returncode == 0:
        print(f"[=] docker network {TARGET_NETWORK} exists")
        return
    print(f"[*] creating docker network {TARGET_NETWORK} ({TARGET_SUBNET}) ...")
    r = _run(["docker", "network", "create", "--subnet", TARGET_SUBNET, TARGET_NETWORK])
    if r.returncode != 0:
        print("[!] failed to create network:")
        print(r.stderr)
        sys.exit(1)
    print(f"[+] network {TARGET_NETWORK} created")


def _ensure_target():
    status = _container_status(TARGET_NAME)
    if status == "running":
        print(f"[=] container {TARGET_NAME} already running")
        return
    if status is not None:
        print(f"[*] removing container {TARGET_NAME} (state={status})")
        _run(["docker", "rm", "-f", TARGET_NAME])

    entrypoint = str(Path.cwd() / "scripts" / "target-entrypoint.sh")
    if not Path(entrypoint).exists():
        print(f"[!] {entrypoint} not found — run from the repo root")
        sys.exit(1)

    print(f"[*] starting {TARGET_NAME} on {TARGET_NETWORK} at {TARGET_IP} ...")
    r = _run([
        "docker", "run", "-d",
        "--name", TARGET_NAME,
        "--hostname", TARGET_NAME,
        "--network", TARGET_NETWORK,
        "--ip", TARGET_IP,
        "-v", f"{entrypoint}:/opt/entrypoint.sh:ro",
        "--cap-add", "NET_ADMIN",
        "--health-cmd", "ss -tln | grep -q ':445 ' || exit 1",
        "--health-interval", "5s",
        "--health-timeout", "3s",
        "--health-retries", "20",
        "--health-start-period", "20s",
        "--restart", "unless-stopped",
        TARGET_IMAGE,
        "/opt/entrypoint.sh",
    ])
    if r.returncode != 0:
        print("[!] docker run failed:")
        print(r.stderr)
        sys.exit(1)
    print("[+] container started")


def _dump_health_log(name, tail=5):
    r = _run(["docker", "inspect", name, "--format",
              "{{if .State.Health}}{{json .State.Health.Log}}{{end}}"])
    raw = (r.stdout or "").strip()
    if not raw:
        print(f"    (no healthcheck log — check docker logs {name})")
        return
    try:
        entries = json.loads(raw)
        n = min(tail, len(entries))
        print(f"    last {n} healthcheck results:")
        for e in entries[-tail:]:
            out = (e.get("Output") or "").strip()[:120]
            print(f"      exit={e.get('ExitCode')}  out={out}")
    except Exception:
        pass


def _wait_healthy(name, timeout=90.0):
    ip_proc = _run(["docker", "inspect", name, "--format",
                    "{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}}{{end}}"])
    ip = (ip_proc.stdout or "").strip()

    hc_proc = _run(["docker", "inspect", name, "--format",
                    "{{if .State.Health}}{{.State.Health.Status}}{{end}}"])
    has_healthcheck = bool((hc_proc.stdout or "").strip())

    deadline = time.time() + timeout
    tick = 0
    print("   ", end="", flush=True)
    while time.time() < deadline:
        tick += 1
        if has_healthcheck:
            r = _run(["docker", "inspect", name, "--format", "{{.State.Health.Status}}"])
            status = (r.stdout or "").strip()
            if status == "healthy":
                print(" healthy")
                return True
            if status == "unhealthy":
                print(" unhealthy")
                _dump_health_log(name)
                return False
        else:
            if ip:
                try:
                    with socket.create_connection((ip, 445), timeout=1.0):
                        print(" port-open")
                        return True
                except OSError:
                    pass
        if tick % 5 == 0:
            print(".", end="", flush=True)
        time.sleep(1.0)
    print(" timeout")
    _dump_health_log(name)
    return False


def main(args=None):
    args = list(args or [])
    p = argparse.ArgumentParser(prog="whaxon up")
    p.add_argument("--no-msfrpcd", action="store_true")
    p.add_argument("--no-docker", action="store_true")
    p.add_argument("--foreground", action="store_true")
    p.add_argument("--data", default="data")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return

    data = Path(ns.data)
    _load_env(data / "whaxon.env")
    print(f"[+] loaded {data / 'whaxon.env'}")

    if not ns.no_docker:
        _ensure_network()
        _ensure_target()
        print("[*] waiting for msf-target healthcheck ...")
        if not _wait_healthy(TARGET_NAME, timeout=120):
            print("[!] msf-target did not become healthy")
            sys.exit(1)
        print("[+] msf-target healthy")

    if not ns.no_msfrpcd:
        port = int(os.environ.get("WHAXON_MSF_PORT", "55553"))
        if _wait_tcp("127.0.0.1", port, timeout=1.0):
            print(f"[=] msfrpcd already listening on {port}")
        else:
            user = os.environ.get("WHAXON_MSF_USER", "msf")
            passwd = os.environ.get("WHAXON_MSF_PASS", "test123")
            ssl_flag = os.environ.get("WHAXON_MSF_SSL", "0")
            cmd = ["sudo", "msfrpcd", "-P", passwd, "-U", user,
                   "-a", "127.0.0.1", "-p", str(port)]
            if ssl_flag in ("1", "true", "yes"):
                cmd.append("-S")
            print(f"[*] starting msfrpcd on 127.0.0.1:{port} ...")
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not _wait_tcp("127.0.0.1", port, timeout=20):
                print(f"[!] msfrpcd didn't come up on {port} within 20s")
                print("    start msfrpcd manually then re-run with --no-msfrpcd")
                sys.exit(1)
            print("[+] msfrpcd up")

    print("[*] starting WHAXON ...")

    if ns.foreground:
        from ..web.serve import main as serve_main
        serve_main([])
        return

    # Run serve as a subprocess: its daemonizer double-forks and the parent
    # branch calls sys.exit(0). If we called serve_main() directly, that
    # sys.exit(0) would terminate *us* before the port poll below could run.
    import shutil as _shutil
    whaxon_bin = _shutil.which("whaxon") or sys.executable
    cmd = [
        whaxon_bin, "serve",
        "--daemon",
        "--log", str(data / "whaxon.log"),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        print(f"[!] whaxon serve failed (exit {r.returncode}):")
        print(r.stdout)
        print(r.stderr)
        sys.exit(1)

    port = int(os.environ.get("WHAXON_PORT", "5001"))
    print(f"[*] waiting for WHAXON to bind 127.0.0.1:{port} ...")
    deadline = time.time() + 15
    print("   ", end="", flush=True)
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                print(" up")
                break
        except OSError:
            print(".", end="", flush=True)
            time.sleep(0.5)
    else:
        print(" timeout")
        print(f"[!] WHAXON didn't bind 127.0.0.1:{port} within 15s")
        print(f"    check {data / 'whaxon.log'}")
        sys.exit(1)

    print(f"[+] WHAXON running at http://127.0.0.1:{port}/ui")


if __name__ == "__main__":
    main()
