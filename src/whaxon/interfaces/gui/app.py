"""WHAXON PySide6 desktop interface."""
from __future__ import annotations

import asyncio
from pathlib import Path

import qasync
from PySide6.QtWidgets import QApplication


from whaxon.core import Core
from whaxon.interfaces.gui.splash import make_splash
from whaxon.interfaces.gui.main_window import MainWindow

BRAND = "WHAXON"
MIN_SPLASH_SECONDS = 0.0
MAX_SPLASH_SECONDS = 3.0

ASSET_LOGO = Path(__file__).resolve().parents[4] / "assets" / "backforge.png"


async def _boot(app, splash, core: Core) -> MainWindow:
    init = asyncio.create_task(core.initialize())
    min_wait = asyncio.create_task(asyncio.sleep(MIN_SPLASH_SECONDS))
    await asyncio.gather(init, min_wait)

    win = MainWindow(core)
    win.show()
    win._populate_catalog()  # re-populate now that core.initialize() has finished
    splash.finish(win)
    return win


def main(args: list[str] | None = None) -> None:
    app = QApplication.instance() or QApplication([])
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    data_dir = Path(__file__).resolve().parents[4] / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    core = Core(data_dir=data_dir)

    splash = make_splash(ASSET_LOGO, BRAND, MAX_SPLASH_SECONDS)

    with loop:
        loop.create_task(_boot(app, splash, core))
        loop.run_forever()


if __name__ == "__main__":
    main()
