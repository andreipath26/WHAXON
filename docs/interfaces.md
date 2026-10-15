# Interfaces

WHAXON ships four interfaces on the same core: a CLI dispatcher, a terminal UI, a desktop app, and a web app.

## CLI (whaxon <subcommand>)

Twenty-one subcommands, dispatched by `whaxon.cli.main`. Running `whaxon` with no arguments launches the TUI.

- `init` — create `data/` with strict default scope
- `up` / `down` — lifecycle helper (no docker-compose dependency)
- `serve` — production WSGI server (waitress, daemon-capable)
- `web` — dev web server (foreground, reload on change)
- `tui` — terminal UI (Textual)
- `gui` — desktop UI (PySide6)
- `run` — run a catalog tool against a target
- `report` — per-job (md/html/pdf/json) or engagement (md/pdf/json/whaxon) report. Each finding carries both technical severity and business impact; cost ranges per class are cited per finding in docs/business-impact.md.
- `findings` — cross-job target lookup
- `evidence` — attach notes/files to a job
- `scope` — scope management
- `msf` — Metasploit RPC commands
- `burp-import` — import a Burp XML scan
- `install` — install a catalog tool package
- `suggest` — next-step suggestions for a job's findings
- `jobs` — list recent jobs
- `ai` — AI planner commands (opt-in; `--auto` and `--resume` modes)
- `lookup` — offline exploit search (searchsploit)
- `cve` — online CVE lookup (NVD, cached)
- `state` — dump full project state to `~/Desktop/whaxon_state.md`

`whaxon --help` prints the full list.

## Terminal (whaxon tui)

Textual-based. Header with clock; left pane catalog; right pane target input and extra args; bottom pane live log; pivot chain viewer toggled with `g`.

Keys:

- Arrows / Tab: navigate catalog
- Enter: select tool
- `r`: run selected tool
- `x`: cancel running job
- `g`: show pivot chain for the current job
- `s`: save report for the current job
- `i`: focus target input
- `a`: AI runs screen (read-only list of recent AI runs)
- Escape: focus catalog
- `Ctrl+Q`: quit

## Desktop (whaxon gui)

PySide6 window hosting a `QWebEngineView` that loads the same UI served by `whaxon web`. Every web UI improvement appears automatically.

The GUI starts an embedded `whaxon serve --daemon` if one is not already running on `127.0.0.1:5001`. On close, it terminates only the server it started — an already-running daemon is left alone.

## Web (whaxon web / whaxon serve --daemon)

Flask app with SSE. Browser UI at `/ui`.

- `whaxon web` — foreground, reload on change, dev use.
- `whaxon serve --daemon` — waitress, double-fork, writes `data/whaxon.pid`. Production.

Auth: HTTP Basic with `WHAXON_AUTH_USER` / `WHAXON_AUTH_PASS` (or `WHAXON_AUTH_PASS_HASH` for a pre-hashed password). Skipped on loopback by default.

**UI (session 59).** The web UI is built to the ui-v4 canonical design system. The shell, sidebar, topbar, six-stage workflow bar, slide-over, command palette, and 14 page sections live in templates/base.html and templates/index.html. Styling is in static/style.css (the ui-v4 token system plus .stages and .load-more rules the mockup was missing). Interaction JS is in static/app.js. The design reference is mockups/ui-v4.html (outside the repo, on the Desktop).

**Status: partially wired.** The pages render the ui-v4 design exactly. As of session 60, Scope and Findings fetch real data from the API and are covered by behavioral tests. The remaining pages render ui-v4 placeholder content and have load-only test stubs; each graduates to behavioral tests as it is wired. A Playwright suite (tests/test_web_*.py, 56 tests) drives every page in a real browser: console cleanliness, Scope behavior, Findings behavior, navigation, and keyboard shortcuts. The prior web UI is recoverable at 4c48303.

**Page-wiring status (session 61).** Three of fourteen web UI pages fetch real API data: **Scope** (GET /api/scope, POST /api/scope/check), **Findings** (GET /api/report?format=json, with slide-over and sort), **Run** (GET /api/tools, POST /api/run, SSE via GET /api/jobs/<id>/stream, POST /api/jobs/<id>/cancel). The remaining eleven pages render ui-v4 mockup content and are covered by stub tests. Wiring pattern: strip mockup from the template, add id hooks, append a scoped IIFE to app.js, add tests/test_web_<page>.py.

Endpoints listed in [api.md](api.md).

Stopping a daemon:

    kill $(cat data/whaxon.pid)
    rm -f data/whaxon.pid
