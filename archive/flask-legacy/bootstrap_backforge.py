#!/usr/bin/env python3
"""
BACKFORGE / WHAXON Phase 1 bootstrap.

Creates the headless core, the interface scaffolding, splash screens for both
Textual and PySide6, pyproject.toml, .gitignore updates, and a smoke test.

Idempotent: existing files are skipped unless --force is passed.
Run with:  python bootstrap_backforge.py [--force] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# CONFIG — edit these if your repo layout differs
# ---------------------------------------------------------------------------

PACKAGE = "whaxon"                 # python import name (keep as whaxon)
BRAND = "BACKFORGE"                # display name in splash / window title
REPO_ROOT = Path.cwd()             # script assumes it's run from repo root
SRC = REPO_ROOT / "src" / PACKAGE
ASSETS = REPO_ROOT / "assets"

# If you want a hard 3-second splash minimum, flip this to 3.0.
# Recommendation: leave at 0.0 — splash hides as soon as init finishes
# (capped at MAX_SPLASH_SECONDS as a safety net).
MIN_SPLASH_SECONDS = 0.0
MAX_SPLASH_SECONDS = 3.0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class Writer:
    def __init__(self, force: bool, dry_run: bool):
        self.force = force
        self.dry_run = dry_run
        self.created: list[Path] = []
        self.skipped: list[Path] = []

    def write(self, path: Path, content: str) -> None:
        if path.exists() and not self.force:
            self.skipped.append(path)
            print(f"  skip   {path.relative_to(REPO_ROOT)} (exists)")
            return
        if self.dry_run:
            print(f"  would  {path.relative_to(REPO_ROOT)}")
            self.created.append(path)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self.created.append(path)
        print(f"  write  {path.relative_to(REPO_ROOT)}")

    def mkdir(self, path: Path) -> None:
        if self.dry_run:
            return
        path.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# File contents
# ---------------------------------------------------------------------------

PYPROJECT = f"""[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "{PACKAGE}"
version = "0.1.0"
description = "{BRAND} — modular, portable cybersecurity testing platform"
readme = "README.md"
requires-python = ">=3.11"
license = {{ text = "AGPL-3.0-or-later" }}
authors = [{{ name = "Andrei", email = "you@example.com" }}]
dependencies = [
    "platformdirs>=4.0",
]

[project.optional-dependencies]
tui = ["textual>=0.80", "rich>=13", "textual-image>=0.8"]
gui = ["PySide6>=6.7", "qasync>=0.27"]
web = ["flask>=3.0"]      # transitional, removed in Phase 5
dev = ["pytest>=8", "pytest-asyncio>=0.23", "ruff>=0.5", "mypy>=1.10"]

[project.scripts]
{PACKAGE} = "{PACKAGE}.cli:main"
{PACKAGE}-tui = "{PACKAGE}.interfaces.tui.app:main"
{PACKAGE}-gui = "{PACKAGE}.interfaces.gui.app:main"

[tool.hatch.build.targets.wheel]
packages = ["src/{PACKAGE}"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py311"
"""

GITIGNORE_ADDITIONS = """
# BACKFORGE additions
build/
dist/
*.tmp
.venv/
venv/
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
.env
.env.*
*.pem
*.key
secrets/
*.db
*.sqlite
enterprise/
"""

CORE_INIT = '''"""BACKFORGE core — headless, UI-agnostic."""
from __future__ import annotations

import asyncio
from pathlib import Path

from .events import EventBus
from .catalog import ToolCatalog
from .runner import ToolRunner


class Core:
    """Single entry point for every interface. Holds no UI state."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.bus = EventBus()
        self.catalog = ToolCatalog(self.bus, self.data_dir / "tools.json")
        self.runner = ToolRunner(self.bus)

    async def initialize(self) -> None:
        """Called once by any interface. Awaitable inside a splash screen."""
        self.bus.bind_loop(asyncio.get_running_loop())
        if self.catalog.path.exists():
            self.catalog.load()
'''

CORE_EVENTS = '''"""Typed events emitted by the core. Interfaces subscribe; core never knows."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

# ---------- Event types ----------

@dataclass(frozen=True)
class Event:
    """Base class. All events carry a UTC timestamp."""
    ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class ToolDiscovered(Event):
    tool_id: str
    name: str
    category: str


@dataclass(frozen=True)
class JobStarted(Event):
    job_id: str
    tool_id: str
    target: str


@dataclass(frozen=True)
class JobOutput(Event):
    job_id: str
    stream: str          # "stdout" | "stderr"
    line: str


@dataclass(frozen=True)
class JobFinished(Event):
    job_id: str
    exit_code: int
    duration_s: float


@dataclass(frozen=True)
class JobFailed(Event):
    job_id: str
    error: str


# ---------- Bus ----------

E = TypeVar("E", bound=Event)


class EventBus:
    """
    Async pub/sub. Interfaces subscribe with a handler or an asyncio.Queue.
    Thread-safe publish via loop.call_soon_threadsafe.
    """

    def __init__(self) -> None:
        self._subs: dict[type[Event], list[Callable[[Any], None]]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(
        self,
        event_type: type[E],
        handler: Callable[[E], None],
    ) -> Callable[[], None]:
        self._subs.setdefault(event_type, []).append(handler)

        def _unsub() -> None:
            self._subs[event_type].remove(handler)

        return _unsub

    def subscribe_queue(self, event_type: type[E]) -> "asyncio.Queue[E]":
        q: asyncio.Queue[E] = asyncio.Queue()
        self.subscribe(event_type, q.put_nowait)
        return q

    def publish(self, event: Event) -> None:
        handlers: list[Callable[[Any], None]] = []
        for cls in type(event).__mro__:
            handlers.extend(self._subs.get(cls, []))
        for h in handlers:
            if self._loop is not None and self._loop.is_running():
                self._loop.call_soon_threadsafe(h, event)
            else:
                h(event)
'''

CORE_CATALOG = '''"""Tool catalog: reads a JSON manifest, emits ToolDiscovered events."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .events import EventBus, ToolDiscovered


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    category: str
    binary: str
    description: str = ""
    available: bool = False


class ToolCatalog:
    def __init__(self, bus: EventBus, catalog_path: Path) -> None:
        self._bus = bus
        self.path = Path(catalog_path)
        self._tools: dict[str, Tool] = {}

    def load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        for entry in raw.get("tools", []):
            tool = Tool(**entry)
            self._tools[tool.id] = tool
            self._bus.publish(ToolDiscovered(
                tool_id=tool.id, name=tool.name, category=tool.category,
            ))

    def list(self) -> list[Tool]:
        return list(self._tools.values())

    def get(self, tool_id: str) -> Tool | None:
        return self._tools.get(tool_id)
'''

CORE_RUNNER = '''"""Executes external tools, streams output through the event bus."""
from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from typing import Sequence

from .events import (
    EventBus, JobStarted, JobOutput, JobFinished, JobFailed,
)


class ToolRunner:
    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._procs: dict[str, asyncio.subprocess.Process] = {}

    async def run(
        self,
        tool_id: str,
        argv: Sequence[str],
        target: str = "",
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout_s: float | None = None,
    ) -> str:
        job_id = uuid.uuid4().hex[:12]
        self._bus.publish(JobStarted(job_id=job_id, tool_id=tool_id, target=target))
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=env,
            )
        except FileNotFoundError as e:
            self._bus.publish(JobFailed(job_id=job_id, error=f"tool not found: {e}"))
            raise

        self._procs[job_id] = proc

        async def pump(stream: asyncio.StreamReader | None, name: str) -> None:
            if stream is None:
                return
            while True:
                line = await stream.readline()
                if not line:
                    break
                self._bus.publish(JobOutput(
                    job_id=job_id, stream=name,
                    line=line.decode(errors="replace").rstrip("\\n"),
                ))

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    pump(proc.stdout, "stdout"),
                    pump(proc.stderr, "stderr"),
                    proc.wait(),
                ),
                timeout=timeout_s,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            self._bus.publish(JobFailed(job_id=job_id, error="timeout"))
            self._procs.pop(job_id, None)
            return job_id

        self._procs.pop(job_id, None)
        self._bus.publish(JobFinished(
            job_id=job_id,
            exit_code=proc.returncode or 0,
            duration_s=time.monotonic() - start,
        ))
        return job_id

    async def cancel(self, job_id: str) -> None:
        proc = self._procs.get(job_id)
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
'''

CLI = '''"""Single dispatcher CLI. Defaults to TUI."""
from __future__ import annotations

import sys


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "tui"
    args = sys.argv[2:]

    if mode == "gui":
        from .interfaces.gui.app import main as gui_main
        gui_main(args)
    elif mode == "tui":
        from .interfaces.tui.app import main as tui_main
        tui_main(args)
    elif mode in ("--help", "-h"):
        print("Usage: whaxon [tui|gui]")
    else:
        print(f"Unknown mode: {mode}. Use 'tui' or 'gui'.")
        sys.exit(2)
'''

TUI_INIT = '''"""Textual terminal interface."""
'''

TUI_APP = f'''"""BACKFORGE Textual terminal interface."""
from __future__ import annotations

import asyncio
from pathlib import Path

from platformdirs import user_data_dir
from textual.app import App, ComposeResult
from textual.widgets import Footer, Header

from {PACKAGE}.core import Core
from {PACKAGE}.interfaces.tui.screens.splash import SplashScreen
from {PACKAGE}.interfaces.tui.screens.main import MainScreen

BRAND = "{BRAND}"
MIN_SPLASH_SECONDS = {MIN_SPLASH_SECONDS}
MAX_SPLASH_SECONDS = {MAX_SPLASH_SECONDS}


class WhaxonApp(App):
    CSS_PATH = "app.tcss"
    SCREENS = {{"main": MainScreen}}

    def __init__(self) -> None:
        super().__init__()
        data_dir = Path(user_data_dir(BRAND))
        data_dir.mkdir(parents=True, exist_ok=True)
        self.core = Core(data_dir=data_dir)

    def on_mount(self) -> None:
        self.push_screen(SplashScreen())


def main(args: list[str] | None = None) -> None:
    WhaxonApp().run()


if __name__ == "__main__":
    main()
'''

TUI_APP_TCSS = """Screen {
    background: $surface;
}

#splash-logo {
    text-align: center;
    color: $accent;
    text-style: bold;
}

#splash-title {
    text-align: center;
    color: $accent;
    text-style: bold;
}

#splash-tagline {
    text-align: center;
    color: $text-muted;
}
"""

TUI_SPLASH = f'''"""Splash screen for the Textual TUI. Shows logo, waits for core init."""
from __future__ import annotations

import asyncio
from pathlib import Path

from textual.containers import Center, Middle
from textual.screen import Screen
from textual.widgets import Static

MIN_SPLASH_SECONDS = {MIN_SPLASH_SECONDS}
MAX_SPLASH_SECONDS = {MAX_SPLASH_SECONDS}

ASSET_LOGO = Path(__file__).resolve().parents[4] / "assets" / "backforge.png"

# Try to use textual-image if the terminal supports it; fall back to ASCII.
try:
    from textual_image.widget import Image as TImage
    HAVE_IMAGE = True
except Exception:
    HAVE_IMAGE = False


ASCII_LOGO = r"""
   __   ___   __   _  __ ___
  / _\\ / __| / /_ | |/ // _ \\
 | (_) | |   / _ \\|   <| |_| |
  \\___/|_|  /_/\\_\\_|\\_\\\\___/
"""


class SplashScreen(Screen):
    """Shows branding while `core.initialize()` runs. Hides when done or at max."""

    def compose(self):
        with Middle(), Center():
            if HAVE_IMAGE and ASSET_LOGO.exists():
                yield TImage(ASSET_LOGO)
            else:
                yield Static(ASCII_LOGO, id="splash-logo")
            yield Static("{BRAND}", id="splash-title")
            yield Static("MODULAR SECURITY TESTING PLATFORM", id="splash-tagline")

    async def on_mount(self) -> None:
        init = asyncio.create_task(self.app.core.initialize())
        min_wait = asyncio.create_task(asyncio.sleep(MIN_SPLASH_SECONDS))
        try:
            await asyncio.wait_for(
                asyncio.gather(init, min_wait),
                timeout=MAX_SPLASH_SECONDS,
            )
        except asyncio.TimeoutError:
            pass
        self.app.switch_screen("main")
'''

TUI_MAIN = f'''"""Main TUI screen. Placeholder until Phase 3 fleshes it out."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, RichLog

from {PACKAGE}.core.events import JobOutput, ToolDiscovered


class MainScreen(Screen):
    BINDINGS = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            yield DataTable(id="catalog")
            yield RichLog(id="output", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#catalog", DataTable)
        table.add_columns("ID", "Name", "Category")
        for tool in self.app.core.catalog.list():
            table.add_row(tool.id, tool.name, tool.category)

        self.app.core.bus.subscribe(ToolDiscovered, self._on_tool)
        self.app.core.bus.subscribe(JobOutput, self._on_output)

    def _on_tool(self, evt: ToolDiscovered) -> None:
        table = self.query_one("#catalog", DataTable)
        table.add_row(evt.tool_id, evt.name, evt.category)

    def _on_output(self, evt: JobOutput) -> None:
        log = self.query_one("#output", RichLog)
        log.write(f"[dim]{{evt.job_id}}[/] {{evt.line}}")
'''

GUI_INIT = '''"""PySide6 desktop interface."""
'''

GUI_APP = f'''"""BACKFORGE PySide6 desktop interface."""
from __future__ import annotations

import asyncio
from pathlib import Path

import qasync
from PySide6.QtWidgets import QApplication

from platformdirs import user_data_dir

from {PACKAGE}.core import Core
from {PACKAGE}.interfaces.gui.splash import make_splash
from {PACKAGE}.interfaces.gui.main_window import MainWindow

BRAND = "{BRAND}"
MIN_SPLASH_SECONDS = {MIN_SPLASH_SECONDS}
MAX_SPLASH_SECONDS = {MAX_SPLASH_SECONDS}

ASSET_LOGO = Path(__file__).resolve().parents[4] / "assets" / "backforge.png"


async def _boot(app, splash, core: Core) -> MainWindow:
    init = asyncio.create_task(core.initialize())
    min_wait = asyncio.create_task(asyncio.sleep(MIN_SPLASH_SECONDS))
    await asyncio.gather(init, min_wait)

    win = MainWindow(core)
    win.show()
    splash.finish(win)
    return win


def main(args: list[str] | None = None) -> None:
    app = QApplication.instance() or QApplication([])
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    data_dir = Path(user_data_dir(BRAND))
    data_dir.mkdir(parents=True, exist_ok=True)
    core = Core(data_dir=data_dir)

    splash = make_splash(ASSET_LOGO, BRAND, MAX_SPLASH_SECONDS)

    with loop:
        loop.create_task(_boot(app, splash, core))
        loop.run_forever()


if __name__ == "__main__":
    main()
'''

GUI_SPLASH = f'''"""PySide6 splash screen."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter, QPixmap
from PySide6.QtWidgets import QSplashScreen

MAX_SPLASH_SECONDS = {MAX_SPLASH_SECONDS}


def make_splash(logo_path: Path, brand: str, max_seconds: float) -> QSplashScreen:
    """
    Build a splash from the logo. If the logo is missing, draws a text-only splash.
    Must be called AFTER QApplication exists (Qt requirement for QPixmap).
    """
    if logo_path.exists():
        pix = QPixmap(str(logo_path))
        pix = pix.scaled(480, 480, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    else:
        pix = QPixmap(480, 200)
        pix.fill(QColor("#1e1e1e"))
        painter = QPainter(pix)
        painter.setPen(QColor("#ff8c42"))
        f = QFont(); f.setPointSize(32); f.setBold(True)
        painter.setFont(f)
        painter.drawText(pix.rect(), Qt.AlignCenter, brand)
        painter.end()

    splash = QSplashScreen(pix, Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    splash.setWindowTitle(brand)
    splash.show()

    # Safety net: kill splash if init hangs.
    QTimer.singleShot(int(max_seconds * 1000) + 1000, splash.close)
    return splash
'''

GUI_MAIN_WINDOW = f'''"""Main PySide6 window. Placeholder until Phase 4 fleshes it out."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QMainWindow, QPlainTextEdit, QSplitter, QTableWidget, QTableWidgetItem,
)

from {PACKAGE}.core import Core
from {PACKAGE}.core.events import JobOutput, ToolDiscovered

BRAND = "{BRAND}"


class MainWindow(QMainWindow):
    def __init__(self, core: Core) -> None:
        super().__init__()
        self.core = core
        self.setWindowTitle(BRAND)
        self.resize(1200, 720)

        self.catalog = QTableWidget(0, 3)
        self.catalog.setHorizontalHeaderLabels(["ID", "Name", "Category"])
        self.output = QPlainTextEdit(readOnly=True)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.catalog)
        splitter.addWidget(self.output)
        splitter.setSizes([400, 800])
        self.setCentralWidget(splitter)

        # Menu
        file_menu = self.menuBar().addMenu("&File")
        quit_act = QAction("&Quit", self)
        quit_act.triggered.connect(self.close)
        file_menu.addAction(quit_act)

        self._populate()
        core.bus.subscribe(ToolDiscovered, self._on_tool)
        core.bus.subscribe(JobOutput, self._on_output)

    def _populate(self) -> None:
        self.catalog.setRowCount(0)
        for tool in self.core.catalog.list():
            self._add_row(tool.id, tool.name, tool.category)

    def _add_row(self, tid: str, name: str, cat: str) -> None:
        r = self.catalog.rowCount()
        self.catalog.insertRow(r)
        for c, val in enumerate((tid, name, cat)):
            self.catalog.setItem(r, c, QTableWidgetItem(val))

    def _on_tool(self, evt: ToolDiscovered) -> None:
        self._add_row(evt.tool_id, evt.name, evt.category)

    def _on_output(self, evt: JobOutput) -> None:
        self.output.appendPlainText(f"[{{evt.job_id}}] {{evt.line}}")
'''

TUI_INIT_PY = TUI_INIT
GUI_INIT_PY = GUI_INIT

SMOKE_TEST = '''"""Phase 1 smoke test: core loads a catalog and emits events."""
from __future__ import annotations

import asyncio
import json

import pytest

from whaxon.core import Core
from whaxon.core.events import ToolDiscovered


def _write_catalog(data_dir):
    (data_dir / "tools.json").write_text(json.dumps({
        "tools": [
            {"id": "nmap", "name": "Nmap", "category": "recon", "binary": "nmap"},
            {"id": "nikto", "name": "Nikto", "category": "web", "binary": "nikto"},
        ]
    }))


def test_catalog_emits_discovered_events(tmp_path):
    _write_catalog(tmp_path)
    core = Core(tmp_path)
    seen = []
    core.bus.subscribe(ToolDiscovered, seen.append)

    asyncio.run(core.initialize())

    assert len(seen) == 2
    assert {e.tool_id for e in seen} == {"nmap", "nikto"}


def test_catalog_list_after_load(tmp_path):
    _write_catalog(tmp_path)
    core = Core(tmp_path)
    asyncio.run(core.initialize())

    tools = core.catalog.list()
    assert len(tools) == 2
    assert core.catalog.get("nmap") is not None
    assert core.catalog.get("does-not-exist") is None
'''

SAMPLE_CATALOG = {
    "tools": [
        {"id": "nmap", "name": "Nmap", "category": "recon", "binary": "nmap",
         "description": "Network mapper"},
        {"id": "nikto", "name": "Nikto", "category": "web", "binary": "nikto",
         "description": "Web server scanner"},
        {"id": "gobuster", "name": "Gobuster", "category": "web", "binary": "gobuster",
         "description": "Directory/DNS busting"},
    ]
}

README_ASSETS = f"""# Assets

Drop `backforge.png` (the phoenix-forge logo) into this folder.
The splash screens in both interfaces look for it here.
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="BACKFORGE Phase 1 bootstrap")
    ap.add_argument("--force", action="store_true", help="overwrite existing files")
    ap.add_argument("--dry-run", action="store_true", help="show what would happen")
    args = ap.parse_args()

    if not (REPO_ROOT / ".git").exists():
        print("WARNING: no .git directory here. Run from repo root.")
        if not args.dry_run:
            ans = input("Continue anyway? [y/N] ").strip().lower()
            if ans != "y":
                return 1

    w = Writer(force=args.force, dry_run=args.dry_run)

    print(f"\n[{BRAND}] Creating tree under {SRC.relative_to(REPO_ROOT)}/")
    for p in [
        SRC,
        SRC / "core",
        SRC / "interfaces",
        SRC / "interfaces" / "tui" / "screens",
        SRC / "interfaces" / "gui",
        SRC / "interfaces" / "web",   # transitional home for the Flask app
        REPO_ROOT / "tests",
        ASSETS,
        REPO_ROOT / "data",
    ]:
        w.mkdir(p)

    print("\n[core]")
    w.write(SRC / "__init__.py", f'__version__ = "0.1.0"\n')
    w.write(SRC / "core" / "__init__.py", CORE_INIT)
    w.write(SRC / "core" / "events.py", CORE_EVENTS)
    w.write(SRC / "core" / "catalog.py", CORE_CATALOG)
    w.write(SRC / "core" / "runner.py", CORE_RUNNER)
    w.write(SRC / "cli.py", CLI)

    print("\n[interfaces/tui]")
    w.write(SRC / "interfaces" / "__init__.py", "")
    w.write(SRC / "interfaces" / "tui" / "__init__.py", TUI_INIT_PY)
    w.write(SRC / "interfaces" / "tui" / "app.py", TUI_APP)
    w.write(SRC / "interfaces" / "tui" / "app.tcss", TUI_APP_TCSS)
    w.write(SRC / "interfaces" / "tui" / "screens" / "__init__.py", "")
    w.write(SRC / "interfaces" / "tui" / "screens" / "splash.py", TUI_SPLASH)
    w.write(SRC / "interfaces" / "tui" / "screens" / "main.py", TUI_MAIN)

    print("\n[interfaces/gui]")
    w.write(SRC / "interfaces" / "gui" / "__init__.py", GUI_INIT_PY)
    w.write(SRC / "interfaces" / "gui" / "app.py", GUI_APP)
    w.write(SRC / "interfaces" / "gui" / "splash.py", GUI_SPLASH)
    w.write(SRC / "interfaces" / "gui" / "main_window.py", GUI_MAIN_WINDOW)

    print("\n[interfaces/web] (placeholder — move Flask app here)")
    w.write(
        SRC / "interfaces" / "web" / "__init__.py",
        '"""Transitional home for the legacy Flask app. Removed in Phase 5."""\n',
    )

    print("\n[tests]")
    w.write(REPO_ROOT / "tests" / "__init__.py", "")
    w.write(REPO_ROOT / "tests" / "test_core_smoke.py", SMOKE_TEST)

    print("\n[project files]")
    w.write(REPO_ROOT / "pyproject.toml", PYPROJECT)
    w.write(ASSETS / "README.md", README_ASSETS)

    # Sample catalog — only create if data/tools.json is missing.
    catalog_path = REPO_ROOT / "data" / "tools.json"
    if not catalog_path.exists() and not args.dry_run:
        catalog_path.parent.mkdir(parents=True, exist_ok=True)
        catalog_path.write_text(json.dumps(SAMPLE_CATALOG, indent=2))
        w.created.append(catalog_path)
        print(f"  write  {catalog_path.relative_to(REPO_ROOT)}")

    # Append to .gitignore without clobbering.
    gi = REPO_ROOT / ".gitignore"
    if not args.dry_run:
        existing = gi.read_text() if gi.exists() else ""
        if "BACKFORGE additions" not in existing:
            with gi.open("a", encoding="utf-8") as f:
                f.write(GITIGNORE_ADDITIONS)
            print("  append .gitignore")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"Created: {len(w.created)}  Skipped: {len(w.skipped)}")
    print("=" * 60)
    print(f"""
Next steps:

  1. Drop your logo into:  {ASSETS.relative_to(REPO_ROOT)}/backforge.png
     (rename it to backforge.png if needed)

  2. Install in editable mode with the interfaces you want:
       pip install -e ".[dev,tui]"
       pip install -e ".[dev,gui]"
       pip install -e ".[dev,tui,gui]"

  3. Run the smoke test:
       pytest -q

  4. Try each interface:
       whaxon tui           # Textual TUI with splash
       whaxon gui           # PySide6 with splash

  5. Move your existing Flask app into:
       {SRC.relative_to(REPO_ROOT)}/interfaces/web/
     Then rewire its routes to call core.catalog / core.runner
     instead of its current inline logic. (Phase 2 — not done here.)

Note: MIN_SPLASH_SECONDS = {MIN_SPLASH_SECONDS}. The splash hides as soon as
core.initialize() finishes (capped at MAX_SPLASH_SECONDS = {MAX_SPLASH_SECONDS}).
To force a minimum 3-second splash, edit the constant near the top of
src/whaxon/interfaces/{{tui,gui}}/splash.py and app.py.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
