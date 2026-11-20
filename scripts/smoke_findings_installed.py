"""Fresh-wheel smoke check for the Findings UI's packaged local assets."""
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
    with urllib.request.urlopen(url, timeout=4) as response:
        return response.status, response.read(), response.headers.get("Content-Type", "")


def main() -> None:
    wheels = list((ROOT / "dist").glob("*.whl"))
    assert len(wheels) == 1, "Expected one built wheel"
    with tempfile.TemporaryDirectory(prefix="whaxon-findings-smoke-") as temp:
        base = Path(temp)
        venv = base / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=45)
        python, binary = venv / "bin/python", venv / "bin/whaxon"
        subprocess.run([
            str(python), "-m", "pip", "install", "--disable-pip-version-check",
            str(wheels[0]) + "[web]",
        ], check=True, timeout=210)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = os.environ.copy()
        env.update({
            "WHAXON_HOST": "127.0.0.1",
            "WHAXON_PORT": str(port),
            "WHAXON_DATA": str(base / "data"),
            "WHAXON_AUTH_DISABLED": "1",
        })
        proc = subprocess.Popen([str(binary), "serve"], cwd=str(base), env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
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

            status, body, _ = get(url + "/ui-v2/findings")
            assert status == 200 and "WHAXON — Trust Layer &amp; Findings".encode() in body
            for external in (b"fonts.googleapis.com", b"cdn.tailwindcss.com", b"lh3.googleusercontent.com"):
                assert external not in body, external
            for asset in ("findings-v2.css", "dashboard-fonts.css", "dashboard-logo.jpg"):
                code, data, content_type = get(url + "/static/" + asset)
                assert code == 200 and data, (asset, code)
                if asset.endswith(".css"):
                    assert "text/css" in content_type, (asset, content_type)
            manifest = json.loads((ROOT / "src/whaxon/interfaces/web/static/dashboard-assets-manifest.json").read_text())
            fonts = [item["file"] for item in manifest["files"] if item["file"].endswith(".woff2")]
            for font in fonts:
                code, data, _ = get(url + "/static/dashboard-fonts/" + font)
                assert code == 200 and data, font
            print(f"Installed Findings page served and loaded {len(fonts) + 4} local assets")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=8)


if __name__ == "__main__":
    main()
