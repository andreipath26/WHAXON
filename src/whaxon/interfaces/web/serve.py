"""whaxon serve — production WSGI server (waitress) with daemon support.

Usage:
    whaxon serve                         foreground, waitress
    whaxon serve --daemon                fork, write data/whaxon.pid
    whaxon serve --log data/whaxon.log   redirect stdout/stderr to a file
    whaxon serve --host 0.0.0.0 --port 5001
    whaxon serve --threads 8

Environment (same as `whaxon web`):
    WHAXON_AUTH_USER / WHAXON_AUTH_PASS / WHAXON_DATA
    WHAXON_HOST / WHAXON_PORT
"""
from __future__ import annotations

import os
import signal
import sys
from pathlib import Path


def _daemonize(log_path, pid_path):
    """Double-fork into the background; write the pidfile; redirect stdio."""
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)

    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        f = open(log_path, "a", buffering=1)
        sys.stdout = f
        sys.stderr = f
        os.dup2(f.fileno(), 1)
        os.dup2(f.fileno(), 2)
    else:
        devnull = open(os.devnull, "a")
        os.dup2(devnull.fileno(), 0)
        os.dup2(devnull.fileno(), 1)
        os.dup2(devnull.fileno(), 2)

    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(os.getpid()), encoding="utf-8")

    def _cleanup(*_a):
        try:
            pid_path.unlink()
        except FileNotFoundError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)


def main(args=None):
    args = list(args or [])

    host = os.environ.get("WHAXON_HOST", "127.0.0.1")
    port = int(os.environ.get("WHAXON_PORT", "5001"))
    threads = 8
    daemon = False
    log_path = None
    data_dir = Path(os.environ.get("WHAXON_DATA", "data"))
    pid_path = data_dir / "whaxon.pid"

    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-h", "--help"):
            print(__doc__)
            return
        elif a == "--daemon":
            daemon = True
            i += 1
        elif a == "--host" and i + 1 < len(args):
            host = args[i + 1]
            i += 2
        elif a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif a == "--threads" and i + 1 < len(args):
            threads = int(args[i + 1])
            i += 2
        elif a == "--log" and i + 1 < len(args):
            log_path = Path(args[i + 1])
            i += 2
        elif a == "--pidfile" and i + 1 < len(args):
            pid_path = Path(args[i + 1])
            i += 2
        else:
            print(f"Unknown arg: {a}")
            sys.exit(2)

    # refuse to start if another instance is running
    if pid_path.exists():
        try:
            old_pid = int(pid_path.read_text().strip())
            os.kill(old_pid, 0)
            print(f"[!] whaxon already running (pid {old_pid}, pidfile {pid_path})")
            sys.exit(1)
        except (ProcessLookupError, ValueError):
            pid_path.unlink(missing_ok=True)

    if daemon:
        _daemonize(log_path, pid_path)

    # auth defaults matching server.main()
    os.environ.setdefault("WHAXON_AUTH_USER", "whaxon")
    if "WHAXON_AUTH_PASS_HASH" not in os.environ:
        from .server import _hash_pw
        os.environ["WHAXON_AUTH_PASS_HASH"] = _hash_pw(
            os.environ.get("WHAXON_AUTH_PASS", "whaxon")
        )

    from .server import create_app_factory
    app = create_app_factory()

    try:
        from waitress import serve as waitress_serve
    except ImportError:
        print("[!] waitress is not installed. Run: pip install waitress")
        sys.exit(1)

    if not daemon:
        print()
        print("  WHAXON production server (waitress)")
        print(f"  -> http://{host}:{port}/ui")
        print(f"  -> threads: {threads}")
        print(f"  -> data:    {os.environ.get('WHAXON_DATA', 'data')}")
        if pid_path.exists():
            print(f"  -> pidfile: {pid_path}")
        print()

    waitress_serve(app, host=host, port=port, threads=threads)


if __name__ == "__main__":
    main()
