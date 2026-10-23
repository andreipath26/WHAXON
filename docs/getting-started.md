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

## Passive recon (Phase 1)

Before you run any active tools, WHAXON can run a passive recon pass against a
target. This is scope-gated exactly like a tool run: if the target is out of
scope, WHAXON emits a `recon_out_of_scope` finding and touches nothing.

Run recon from the CLI:

    whaxon recon example.com
    whaxon recon example.com --checks dns,ssl,headers,tech
    whaxon recon example.com --verbose

Or from Python:

```python
from whaxon.core import Core
core = Core(...)  # your existing Core construction
core.recon.run("example.com")
```

That call runs four checks — DNS, SSL certificate + SANs, security headers,
tech stack — writes findings to the store, and fires the correlator. A
`tech_detected` finding with a known version (e.g. `apache 2.4.25`) will
correlate with the CVE table and produce a `correlated` finding just like an
nmap run would.

Recon does not auto-scope discovered hosts. If the SSL SANs reveal related
hostnames, each appears as a `recon_discovered_host` finding — add them to
scope via the override log if they are authorised targets.

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
