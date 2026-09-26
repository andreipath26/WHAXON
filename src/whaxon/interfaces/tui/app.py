"""WHAXON Textual terminal interface."""
from __future__ import annotations

import asyncio
from pathlib import Path

from platformdirs import user_data_dir
from textual.app import App, ComposeResult
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

    def on_mount(self) -> None:
        # Splash temporarily disabled — it hangs on some terminals.
        # TODO: fix splash.py on_mount and re-enable.
        self.push_screen("main")


def main(args: list[str] | None = None) -> None:
    WhaxonApp().run()


if __name__ == "__main__":
    main()
