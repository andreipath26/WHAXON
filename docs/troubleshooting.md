# Troubleshooting

## Installation

### ModuleNotFoundError: No module named 'whaxon'

Virtualenv not active:

    source .venv/bin/activate
    pip install -e ".[tui]"

### error: externally-managed-environment

Use a virtualenv:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[tui]"

### PySide6 wheel download is slow

Try a mirror:

    pip install -e ".[gui]" --index-url https://mirrors.aliyun.com/pypi/simple/

Or skip the GUI and install just the TUI: pip install -e ".[tui]"

### Could not find a version that satisfies the requirement PySide6

PySide6 lags behind new Python releases. On Python 3.14, install 3.13:

    sudo apt install python3.13 python3.13-venv
    python3.13 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[tui,gui]"

## Running scans

### Couldn't open a raw socket

Use TCP connect mode - edit tools.json:

    "args": "-sT {target}"

Or grant capability (Linux only):

    sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)

### binary not found

Install the tool or update the binary field in tools.json.

### A scan hangs

Press c in TUI/GUI or click Cancel in web. Sends SIGTERM to the subprocess.

### No findings appear

Only these tools have parsers: nmap, nikto, gobuster, sqlmap, whois, dig,
nuclei, ffuf, wpscan. Others stream but produce zero findings.

## Interfaces

### TUI screen garbles after exit

Run reset in that terminal. If it persists, use tmux:

    tmux new -s whaxon "whaxon tui"

### Could not load the Qt platform plugin "xcb"

Install X11 libs:

    sudo apt install libxcb-cursor0 libxcb-xinerama0 libxcb-icccm4 \
                     libxcb-image0 libxcb-keysyms1 libxcb-render-util0 \
                     libxkbcommon-x11-0

On Wayland: QT_QPA_PLATFORM=xcb whaxon gui

### Web UI rejects credentials

Defaults are whaxon / whaxon. If changed via env, restart with new values.

Clear cached Basic auth in the browser: private window or clear site data.

### Web UI says "unknown job" for a recent job

Two gunicorn workers with separate in-memory state. WHAXON uses SQLite to
avoid this. Check:

    docker exec whaxon ls -la /data/

Verify /data/whaxon.db exists and is written.

## Docker

### Container starts then exits

Run in foreground to see the crash:

    docker run --rm --name whaxon \
      --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
      --cap-drop=ALL -p 127.0.0.1:5001:5001 \
      -v "$PWD/data:/data" -e HOME=/tmp \
      -e WHAXON_AUTH_USER=whaxon -e WHAXON_AUTH_PASS=whaxon \
      -e WHAXON_DATA=/data whaxon:secure

### Read-only file system: '/home/whaxon/.gunicorn'

Gunicorn writes a control socket to $HOME. Set HOME=/tmp in the container.

### unable to open database file

SQLite file is on a read-only mount, or container user can't write.

    ls -la data/whaxon.db
    chmod 664 data/whaxon.db

## Database

### Reset all history

    rm data/whaxon.db data/whaxon.db-wal data/whaxon.db-shm

### Inspect manually

    sqlite3 data/whaxon.db
    sqlite> .tables
    sqlite> SELECT id, tool, target, status FROM jobs ORDER BY started_at DESC LIMIT 10;
    sqlite> .quit

## Getting help

Open an issue at https://github.com/andreipath26/WHAXON/issues with OS,
Python version, and the exact command you ran.
