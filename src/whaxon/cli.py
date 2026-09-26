"""Single dispatcher CLI. Defaults to TUI."""
from __future__ import annotations

import sys


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "tui"
    args = sys.argv[2:]

    if mode == "gui":
        from .interfaces.gui.app import main as gui_main
        gui_main(args)
    elif mode == "web":
        from .interfaces.web.server import main as web_main
        web_main(args)
    elif mode == "evidence":
        from .interfaces.cli.evidence_cmd import main as ev_main
        ev_main(args)
    elif mode == "report":
        from .interfaces.cli.report_cmd import main as report_main
        report_main(args)
    elif mode == "tui":
        from .interfaces.tui.app import main as tui_main
        tui_main(args)
    elif mode in ("--help", "-h"):
        print("Usage: whaxon [tui|gui|web|report <job_id>|evidence <job_id>]")
    else:
        print(f"Unknown mode: {mode}. Use 'tui', 'gui', or 'web'.")
        sys.exit(2)
