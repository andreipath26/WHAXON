"""Deployment proof: isolated wheel installation serves an offline-safe Dashboard."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def get(url: str) -> tuple[int, bytes, str]:
    with urllib.request.urlopen(url, timeout=4) as result:
        return result.status, result.read(), result.headers.get("Content-Type", "")


def main() -> None:
    wheel = list((ROOT / "dist").glob("*.whl"))
    assert len(wheel) == 1, "Expected a single built wheel"
    with tempfile.TemporaryDirectory(prefix="whaxon-dashboard-smoke-") as temp:
        base = Path(temp)
        venv = base / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=45)
        python = venv / "bin" / "python"
        binary = venv / "bin" / "whaxon"
        subprocess.run([
            str(python), "-m", "pip", "install", "--disable-pip-version-check",
            str(wheel[0]) + "[web]",
        ], check=True, timeout=210)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        env = os.environ.copy()
        env.update({
            "WHAXON_HOST": "127.0.0.1",
            "WHAXON_PORT": str(port),
            "WHAXON_DATA": str(base / "data"),
            "WHAXON_AUTH_DISABLED": "1",
        })
        proc = subprocess.Popen(
            [str(binary), "serve"], cwd=str(base), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        url = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise AssertionError(f"Installed service exited early: {proc.stderr.read()!r}")
                try:
                    if get(url + "/api/health/simple")[0] == 200:
                        break
                except (urllib.error.URLError, TimeoutError, OSError):
                    time.sleep(0.3)
            else:
                raise AssertionError("Installed web service did not start")
            status, body, kind = get(url + "/ui-v2")
            assert status == 200 and b"Security Operations Engine" in body
            assert b"/static/dashboard-v2.css" in body
            assert b"fonts.googleapis.com" not in body
            assert b"lh3.googleusercontent.com" not in body
            manifest = json.loads((
                ROOT / "src/whaxon/interfaces/web/static/dashboard-assets-manifest.json"
            ).read_text(encoding="utf-8"))
            paths = [
                "dashboard-v2.css", "dashboard-fonts.css",
                "dashboard-logo.jpg", "dashboard-profile.jpg",
            ]
            paths += [
                "dashboard-fonts/" + item["file"]
                for item in manifest["files"] if item["file"].endswith(".woff2")
            ]
            for path in paths:
                code, data, content_type = get(url + "/static/" + path)
                assert code == 200 and data, (path,code)
                if path.endswith(".css"):
                    assert "text/css" in content_type, (path,content_type)
            print(f"Installed Dashboard served HTML and {len(paths)} local assets")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=8)


if __name__ == "__main__":
    main()
