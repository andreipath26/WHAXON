"""Shared pytest fixtures for the WHAXON web UI test suite.

Two session-scoped fixtures:

- live_server: starts `whaxon serve` on a free port with an isolated data
  directory seeded with two jobs and a handful of findings, waits for
  /api/health, yields the base URL, kills the server on teardown.

- browser: launches Playwright's Chromium. Uses the WHAXON_TEST_CHROMIUM
  env var when set (CI uses Playwright's bundled Chromium); falls back to
  the system Google Chrome (which is what Kali ships and what a local dev
  run uses).

Every test that drives a page uses both fixtures.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parent.parent


def _whaxon_bin() -> str:
    """Find the whaxon executable, preferring the venv beside the test
    process, then PATH. CI installs into system Python; local dev uses
    .venv. Both must work."""
    import shutil
    import sys
    venv_bin = Path(sys.executable).parent / "whaxon"
    if venv_bin.exists():
        return str(venv_bin)
    found = shutil.which("whaxon")
    if found:
        return found
    raise RuntimeError("whaxon executable not found on PATH or beside " + sys.executable)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_health(url: str, timeout: float = 30.0) -> None:
    import urllib.error
    import urllib.request
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/api/health/simple", timeout=2) as r:
                if r.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            last_err = e
            time.sleep(0.3)
    raise RuntimeError(f"server did not become healthy within {timeout}s: {last_err}")


def _seed(data_dir: Path) -> None:
    """Create two jobs with findings so the UI has something real to render,
    and copy the real tool catalog so /api/tools is populated."""
    import shutil
    src_catalog = REPO / "data" / "tools.json"
    if src_catalog.exists():
        shutil.copy(src_catalog, data_dir / "tools.json")
    sys.path.insert(0, str(REPO / "src"))
    from whaxon.core import Core

    core = Core(data_dir=data_dir)
    store = core.store

    # Job 1 — nmap-style findings
    store.create("seed-job-1")
    store.set_started("seed-job-1", "nmap", "127.0.0.1")
    store.append_finding("seed-job-1", {
        "kind": "open_port",
        "severity": "medium",
        "title": "22/tcp open ssh",
        "target": "127.0.0.1",
        "source": "nmap",
        "raw_line": "22/tcp open ssh OpenSSH 9.6",
        "data": {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 9.6"},
    }, 0)
    store.append_finding("seed-job-1", {
        "kind": "open_port",
        "severity": "low",
        "title": "80/tcp open http",
        "target": "127.0.0.1",
        "source": "nmap",
        "raw_line": "80/tcp open http Apache httpd 2.4.58",
        "data": {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache httpd 2.4.58"},
    }, 1)
    store.set_finished("seed-job-1", 0, 1.2)

    # Job 2 — a critical web finding
    store.create("seed-job-2")
    store.set_started("seed-job-2", "nikto", "127.0.0.1:80")
    store.append_finding("seed-job-2", {
        "kind": "web_issue",
        "severity": "critical",
        "title": "SQL injection on /login",
        "target": "127.0.0.1:80",
        "source": "nikto",
        "raw_line": "+ [000287] /login: SQL injection",
        "data": {"path": "/login", "message": "SQL injection"},
    }, 0)
    store.set_finished("seed-job-2", 0, 0.8)

    # One AI run waiting on a human answer, so the Approvals page has
    # something real to render (§4.4).
    store.create_ai_run("seed-ai-run", "test goal: enumerate 127.0.0.1",
                        provider="rules", phase="recon", owner="local")
    import json as _json
    store.set_ai_run_waiting("seed-ai-run", _json.dumps({
        "rationale": "recon complete; move to enumeration?",
        "confidence": 0.9,
        "proposed_phase": "enumeration",
        "ai_source": "rules",
    }))


@pytest.fixture(scope="session")
def live_server(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("whaxon-test-data")
    _seed(data_dir)

    port = _free_port()
    env = os.environ.copy()
    env["WHAXON_DATA"] = str(data_dir)
    env["WHAXON_PORT"] = str(port)
    env["WHAXON_HOST"] = "127.0.0.1"
    env["WHAXON_AUTH_DISABLED"] = "1"

    proc = subprocess.Popen(
        [_whaxon_bin(), "serve"],
        env=env,
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_health(url)
    except RuntimeError as e:
        proc.terminate()
        out, err = proc.communicate(timeout=5)
        raise RuntimeError(f"server failed to start: {e}\nstdout: {out.decode()}\nstderr: {err.decode()}") from e

    yield url

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="session")
def browser():
    # Prefer an explicit path from env. Otherwise use the system Chrome if it
    # exists (fast local runs), and fall back to Playwright's bundled Chromium
    # (which CI installs) when neither is present.
    explicit = os.environ.get("WHAXON_TEST_CHROMIUM")
    system_chrome = "/usr/bin/google-chrome"
    with sync_playwright() as p:
        if explicit and Path(explicit).exists():
            b = p.chromium.launch(executable_path=explicit, headless=True)
        elif Path(system_chrome).exists():
            b = p.chromium.launch(executable_path=system_chrome, headless=True)
        else:
            b = p.chromium.launch(headless=True)
        yield b
        b.close()


@pytest.fixture
def page(browser):
    ctx = browser.new_context(viewport={"width": 1600, "height": 1000})
    pg = ctx.new_page()
    yield pg
    ctx.close()

def make_report_dict(data_dir, seed_fn):
    """Build a real report dict by calling _load on a seeded store.
    seed_fn(store) populates the store. The helper does the Core setup and
    the _load call. This keeps the report dict shape defined in exactly one
    place (core.report._load), so a shape change fails every render test
    instead of silently producing empty sections."""
    sys.path.insert(0, str(REPO / "src"))
    from whaxon.core import Core
    from whaxon.core.report import _load
    core = Core(data_dir=Path(data_dir))
    seed_fn(core.store)
    return _load(core.store, "default")
