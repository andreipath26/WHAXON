# Getting Started

## Requirements

- Python 3.11+ (3.13 recommended)
- Linux, macOS, or Windows
- External tools on PATH (nmap, nikto, gobuster, etc.) - see tools.md

## Installation

    git clone https://github.com/andreipath26/WHAXON.git
    cd WHAXON
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[tui,gui,web]"

## Your first scan

WHAXON ships with a harmless test tool called Echo (test).

    whaxon tui

In the TUI:

1. Arrow keys to select Echo (test), press Enter
2. Type hello world in Target
3. Press r to run
4. Watch output pane

Press Ctrl+Q to exit.

## Your first real scan

scanme.nmap.org is a host Nmap runs for testing scanners.

1. Select Nmap
2. Target: scanme.nmap.org
3. Extra args: -sV -p 22,80,443
4. Press r

## Where things live

    data/tools.json              Tool catalog
    data/whaxon.db               Job history, findings, evidence
    data/evidence/<job_id>/      Attached files
    ~/.local/share/whaxon/reports/  Reports from TUI

## Web interface credentials

    username: whaxon
    password: whaxon

Change these before exposing on a network. See deployment.md.
