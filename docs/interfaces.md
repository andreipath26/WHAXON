# Interfaces

WHAXON ships three interfaces on the same core.

## Choosing an interface

    Remote server over SSH        Terminal (TUI)
    Local mouse-driven workflow   Desktop (GUI)
    Headless server, remote       Web
    Phone or tablet               Web

All three write to data/whaxon.db.

## Terminal interface

    whaxon tui

Key bindings:

    Up / Down    Move through catalog or history
    Enter        Select a tool
    r            Run selected tool
    c            Cancel running job
    i            Focus target input
    s            Save selected history job as Markdown
    Escape       Focus catalog
    Ctrl+Q       Quit

Reports go to ~/.local/share/whaxon/reports/<job_id>.md

## Desktop interface

    whaxon gui

Right-click a History item to save reports or add notes.

## Web interface

    whaxon web

Open http://127.0.0.1:5001/ui - default credentials whaxon / whaxon.

Environment variables:

    WHAXON_HOST            Bind address (default 127.0.0.1)
    WHAXON_PORT            Port (default 5001)
    WHAXON_DATA            Data directory (default data)
    WHAXON_AUTH_USER       Basic auth username
    WHAXON_AUTH_PASS       Basic auth password (bcrypt-hashed at startup)
    WHAXON_AUTH_PASS_HASH  Pre-computed hash, overrides WHAXON_AUTH_PASS

Only expose over HTTPS. HTTP Basic auth sends credentials in plaintext.

## Command-line interface

    whaxon --help
    whaxon report <job_id>
    whaxon report <job_id> --format html
    whaxon report <job_id> --out report.md
    whaxon evidence <job_id>
    whaxon evidence <job_id> --note "text"
    whaxon evidence <job_id> --add file.png
    whaxon evidence <job_id> --rm <seq>
