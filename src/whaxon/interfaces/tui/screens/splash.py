"""Splash screen for the Textual TUI. Shows logo, waits for core init."""
from __future__ import annotations

import asyncio
from pathlib import Path

from textual.containers import Center, Middle
from textual.screen import Screen
from textual.widgets import Static

MIN_SPLASH_SECONDS = 0.0
MAX_SPLASH_SECONDS = 3.0

ASSET_LOGO = Path(__file__).resolve().parents[4] / "assets" / "backforge.png"

# Try to use textual-image if the terminal supports it; fall back to ASCII.
try:
    from textual_image.widget import Image as TImage
    HAVE_IMAGE = True
except Exception:
    HAVE_IMAGE = False


ASCII_LOGO = r"""
   __   ___   __   _  __ ___
  / _\ / __| / /_ | |/ // _ \
 | (_) | |   / _ \|   <| |_| |
  \___/|_|  /_/\_\_|\_\\___/
"""


class SplashScreen(Screen):
    """Shows branding while `core.initialize()` runs. Hides when done or at max."""

    def compose(self):
        with Middle(), Center():
            if HAVE_IMAGE and ASSET_LOGO.exists():
                yield TImage(ASSET_LOGO)
            else:
                yield Static(ASCII_LOGO, id="splash-logo")
            yield Static("BACKFORGE", id="splash-title")
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
