"""Single dispatcher CLI. Defaults to TUI."""
from __future__ import annotations

import sys


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "tui"
    args = sys.argv[2:]

    if mode in ("tui", "gui") and args and args[0] in ("--help", "-h"):
        print(f"Usage: whaxon {mode}")
        print(f"  Launch the {mode} interface. No arguments accepted.")
        return

    if mode == "gui":
        from .interfaces.gui.app import main as gui_main
        gui_main(args)
    elif mode == "web":
        from .interfaces.web.server import main as web_main
        web_main(args)
    elif mode == "serve":
        from .interfaces.web.serve import main as serve_main
        serve_main(args)
    elif mode == "init":
        from .interfaces.cli.init_cmd import main as init_main
        init_main(args)
    elif mode == "up":
        from .interfaces.cli.up_cmd import main as up_main
        up_main(args)
    elif mode == "down":
        from .interfaces.cli.down_cmd import main as down_main
        down_main(args)
    elif mode == "msf":
        from .interfaces.cli.msf_cmd import main as msf_main
        msf_main(args)
    elif mode == "scope":
        from .interfaces.cli.scope_cmd import main as scope_main
        scope_main(args)
    elif mode == "install":
        from .interfaces.cli.install_cmd import main as install_main
        install_main(args)
    elif mode == "suggest":
        from .interfaces.cli.suggest_cmd import main as suggest_main
        suggest_main(args)
    elif mode == "burp-import":
        from .interfaces.cli.burp_cmd import main as burp_main
        burp_main(args)
    elif mode == "evidence":
        from .interfaces.cli.evidence_cmd import main as ev_main
        ev_main(args)
    elif mode == "report":
        from .interfaces.cli.report_cmd import main as report_main
        report_main(args)
    elif mode == "jobs":
        from .interfaces.cli.jobs_cmd import main as jobs_main
        jobs_main(args)
    elif mode == "ai":
        from .interfaces.cli.ai_cmd import main as ai_main
        ai_main(args)
    elif mode == "cve":
        from .interfaces.cli.cve_cmd import main as cve_main
        cve_main(args)
    elif mode == "lookup":
        from .interfaces.cli.lookup_cmd import main as lookup_main
        lookup_main(args)
    elif mode == "findings":
        from .interfaces.cli.findings_cmd import main as findings_main
        findings_main(args)
    elif mode == "run":
        from .interfaces.cli.run_cmd import main as run_main
        run_main(args)
    elif mode == "state":
        from .tools.state import main as state_main
        state_main(args)
    elif mode == "tui":
        from .interfaces.tui.app import main as tui_main
        tui_main(args)
    elif mode in ("--help", "-h"):
        print("Usage: whaxon [init|up|down|serve|web|tui|gui|msf|scope|install|suggest|burp-import|evidence|report|run|findings|lookup|cve|state]")
    else:
        print(f"Unknown mode: {mode}. Use 'tui', 'gui', 'web', or 'serve'.")
        sys.exit(2)


if __name__ == "__main__":
    main()
