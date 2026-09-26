"""Single dispatcher CLI. Defaults to TUI."""
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
