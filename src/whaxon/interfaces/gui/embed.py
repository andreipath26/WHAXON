"""Server lifecycle manager for the GUI's embedded web view."""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HOST = "127.0.0.1"
PORT = 5001
URL = f"http://{HOST}:{PORT}/ui"


def _port_open(host: str = HOST, port: int = PORT, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _project_root() -> Path:
    # gui/embed.py -> interfaces/gui/embed.py ; go up 4 to repo root
    return Path(__file__).resolve().parents[4]


class EmbeddedServer:
    """Start/stop the whaxon serve daemon on demand."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._we_started = False

    def is_running(self) -> bool:
        return _port_open()

    def start(self, timeout: float = 15.0) -> bool:
        if self.is_running():
            self._we_started = False
            return True

        root = _project_root()
        data = root / "data"
        data.mkdir(exist_ok=True)
        log = data / "whaxon.log"

        # find the installed whaxon console script
        import shutil
        bin_path = shutil.which("whaxon")
        if not bin_path:
            # fall back to python -m
            cmd = [sys.executable, "-m", "whaxon.cli", "serve",
                   "--daemon", "--log", str(log)]
        else:
            cmd = [bin_path, "serve", "--daemon", "--log", str(log)]

        env = os.environ.copy()
        # GUI embedded web view runs on loopback; skip auth for it.
        env["WHAXON_AUTH_DISABLED"] = "1"
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(root),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            self._proc = proc
            self._we_started = True
        except Exception as e:
            print(f"[embed] failed to spawn whaxon serve: {e}", file=sys.stderr)
            return False

        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.is_running():
                return True
            time.sleep(0.3)
        return False

    def stop(self) -> None:
        """Stop the server we started. No-op if we didn't start it."""
        if not self._we_started:
            return
        root = _project_root()
        pidfile = root / "data" / "whaxon.pid"
        if pidfile.exists():
            try:
                pid = int(pidfile.read_text().strip())
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        # belt and braces
        subprocess.run(["pkill", "-f", "whaxon serve"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._we_started = False
