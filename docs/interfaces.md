# Interfaces

WHAXON ships three interfaces on the same core, plus a CLI dispatcher.

## Terminal (whaxon tui)

Textual-based. Header with clock; left pane catalog; right pane target input and extra args; bottom pane live log; pivot chain viewer toggled with g.

Keys:

- Arrows / Tab: navigate catalog
- Enter: select tool
- r: run selected tool
- x: cancel running job
- g: show pivot chain for the current job
- s: save report for the current job
- i: focus target input
- Escape: focus catalog
- Ctrl+Q: quit

## Desktop (whaxon gui)

PySide6 window hosting a QWebEngineView that loads the same UI served by whaxon web. Every web UI improvement appears automatically.

The GUI starts an embedded whaxon serve --daemon if one is not already running on 127.0.0.1:5001. On close, it terminates only the server it started - an already-running daemon is left alone.

## Web (whaxon web / whaxon serve --daemon)

Flask app with SSE. Browser UI at /ui.

- whaxon web - foreground, reload on change, dev use.
- whaxon serve --daemon - waitress, double-fork, writes data/whaxon.pid. Production.

Auth: HTTP Basic with WHAXON_AUTH_USER / WHAXON_AUTH_PASS.

Endpoints listed in api.md.

Stopping a daemon:

    kill $(cat data/whaxon.pid)
    rm -f data/whaxon.pid

## CLI

Fifteen subcommands, dispatched by whaxon.cli.main:

- init          - create data/ with default scope
- up / down     - lifecycle helper (no docker-compose)
- serve         - production WSGI server
- web           - dev web server
- tui           - terminal UI (default if no subcommand)
- gui           - desktop UI
- report        - per-job report (md / html)
- evidence      - attach notes/files to a job
- scope         - scope management
- msf           - Metasploit RPC commands
- burp-import   - import a Burp XML scan
- install       - install a catalog tool package
- suggest       - next-step suggestions

whaxon --help prints the full list.