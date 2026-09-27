"""WHAXON Textual terminal interface."""
from __future__ import annotations

import asyncio
from pathlib import Path

from platformdirs import user_data_dir
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header

from whaxon.core import Core
from whaxon.interfaces.tui.screens.splash import SplashScreen
from whaxon.interfaces.tui.screens.main import MainScreen

BRAND = "WHAXON"
MIN_SPLASH_SECONDS = 0.0
MAX_SPLASH_SECONDS = 3.0


class WhaxonApp(App):
    CSS_PATH = "app.tcss"
    SCREENS = {"main": MainScreen}

    def __init__(self) -> None:
        super().__init__()
        data_dir = Path(__file__).resolve().parents[4] / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        self.core = Core(data_dir=data_dir)

    BINDINGS = [
        Binding("ctrl+t", "cycle_theme", "theme", show=True),
    ]

    def _theme_from_settings(self) -> str:
        try:
            return self.core.settings.get().get("theme", "system")
        except Exception:
            return "system"

    def _resolve_theme(self, pref: str) -> str:
        """Return 'textual-dark' or 'textual-light' based on pref."""
        if pref == "dark":
            return "textual-dark"
        if pref == "light":
            return "textual-light"
        # system: use Textual's default heuristic (dark)
        return "textual-dark"

    def _apply_theme_from_settings(self) -> None:
        pref = self._theme_from_settings()
        try:
            self.theme = self._resolve_theme(pref)
        except Exception:
            pass

    def action_cycle_theme(self) -> None:
        """Cycle system -> dark -> light -> system, persist, apply."""
        order = ["system", "dark", "light"]
        cur = self._theme_from_settings()
        try:
            nxt = order[(order.index(cur) + 1) % len(order)]
        except ValueError:
            nxt = "system"

        try:
            self.core.settings.save({"theme": nxt})
        except Exception:
            pass

        # best-effort: inform the web server if it's running
        try:
            import json, urllib.request
            req = urllib.request.Request(
                "http://127.0.0.1:5001/api/settings",
                data=json.dumps({"theme": nxt}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            import base64
            req.add_header("Authorization", "Basic " + base64.b64encode(b"whaxon:whaxon").decode())
            urllib.request.urlopen(req, timeout=2).read()
        except Exception:
            pass

        self._apply_theme_from_settings()
        try:
            self.notify(f"theme: {nxt}", timeout=2)
        except Exception:
            pass

    def on_mount(self) -> None:
        # Splash temporarily disabled — it hangs on some terminals.
        # TODO: fix splash.py on_mount and re-enable.
        self._apply_theme_from_settings()
        self.push_screen("main")


def main(args: list[str] | None = None) -> None:
    WhaxonApp().run()


if __name__ == "__main__":
    main()
