# WHAXON

One platform. Every layer of security.

A modular, portable cybersecurity testing platform with terminal, desktop, and web interfaces powered by a shared Python core.

## Overview

WHAXON is a modular cybersecurity testing platform that unifies security tools, workflows, and assessment capabilities behind a single, extensible core.

The same core drives a Textual terminal UI, a PySide6 desktop app, and a browser-based web interface - so a tool added once runs everywhere.

WHAXON follows a hybrid open-source and commercial model.

## Status

v0.2 - adapter architecture, enriched findings, three working interfaces.

### Working now

| Feature | Status |
| --- | --- |
| Headless core (catalog + runner + event bus) | Working |
| Terminal interface (Textual) | Working |
| Desktop interface (PySide6) | Working |
| Web interface (Flask + SSE + auth) | Working |
| Tool catalog with argument templates | Working (10 tools) |
| Adapter layer | Working (nmap, nikto, burp) |
| Enriched findings (CVSS, CWE, impact, remediation) | Working |
| Burp XML import | Working |
| SQLite persistence across all interfaces | Working |
| Job history (all three UIs) | Working |
| Report generation (Markdown + HTML) | Working |
| Evidence attachments | Working |
| Docker (hardened, multi-worker) | Working |
| Test suite | 15 passing |

### Planned

| Feature | Priority |
| --- | --- |
| Web UI file upload for Burp XML | Near term |
| Send to tool actions on findings | Near term |
| Scope declaration + out-of-scope safety | Near term |
| SQLmap adapter with next-step logic | Medium term |
| Session tree (hosts, ports, findings) | Medium term |
| Multi-user auth + projects | Medium term |
| AI-assisted next-step suggestions | Longer term |

## Quick start

### Install

    git clone https://github.com/andreipath26/WHAXON.git
    cd WHAXON
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[tui,gui,web]"

Requires Python 3.11+.

### Run

    whaxon tui          # Terminal UI (Textual)
    whaxon gui          # Desktop app (PySide6)
    whaxon web          # Web interface at http://127.0.0.1:5001/ui

### Import a Burp Suite scan

    whaxon burp-import ~/burp-export.xml

### Generate a report

    whaxon report <job_id>
    whaxon report <job_id> --format html
    whaxon report <job_id> --out scan-report.md

### Web configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| WHAXON_HOST | 127.0.0.1 | Bind address |
| WHAXON_PORT | 5001 | Port |
| WHAXON_DATA | data | Data directory |
| WHAXON_AUTH_USER | whaxon | Basic auth username |
| WHAXON_AUTH_PASS | whaxon | Basic auth password (bcrypt) |

## Adapter architecture

Every tool can have an adapter - a Python class that parses that tool output and enriches it with remediation, impact, CWE, and CVSS.

Two modes are supported:

1. Subprocess adapters (nmap, nikto) - parse streaming output
2. File adapters (burp) - parse an imported XML file

Both produce the same Finding shape. The store persists enrichment as JSON. Every interface renders it. Reports include it.

### Built-in adapters

| Tool | Mode | Knowledge source |
| --- | --- | --- |
| nmap | subprocess | Service knowledge table (16 services) |
| nikto | subprocess | Issue pattern table (13 patterns) |
| burp | file import | Extracted from Burp XML |

## Architecture

    Terminal UI        Desktop UI         Web UI
    (Textual)          (PySide6)          (Flask + SSE)
         |                  |                  |
         +------------------+------------------+
                            |
                     Core Services
                            |
         +------------------+------------------+
         |                  |                  |
    Tool Catalog       Event Bus          Job Store
    (tools.json)     (pub/sub)            (SQLite)
                            |
                        Adapters
                            |
         +------------------+------------------+
         |                  |                  |
       nmap               nikto              burp
    (subprocess)      (subprocess)      (file import)
                            |
                    Enriched Findings

## Interfaces

### Terminal

whaxon tui

Catalog and history on the left, target/extra-args inputs on the right, live output below. Keys: arrows to navigate, Enter to select, r to run, c to cancel, s to save report, Ctrl+Q to quit.

### Desktop

whaxon gui

Same layout, native widgets, splash screen on launch. Right-click any history item to save a report or attach a note.

### Web

whaxon web

Flask server exposing a JSON API and a browser UI at /ui. Live output streams over Server-Sent Events. Findings render as a color-coded table with expandable rows.

### CLI

    whaxon tui                              # Terminal UI
    whaxon gui                              # Desktop UI
    whaxon web                              # Web server
    whaxon report <job_id>                  # Markdown report
    whaxon report <job_id> --format html    # HTML report
    whaxon evidence <job_id>                # List evidence
    whaxon evidence <job_id> --note "text"  # Add note
    whaxon evidence <job_id> --add file.png # Attach file
    whaxon burp-import scan.xml             # Import Burp XML

## Findings

Every adapter produces Finding objects with severity, CVSS, CWE, impact, and remediation. Findings are persisted in SQLite, rendered in the web UI as an expandable table, included in reports, and queryable via the API.

## Reports and evidence

Reports are Markdown or HTML summaries of a single job.

    whaxon report 5fae0b1b36f4 --format html --out report.html

Evidence attaches notes or files to any job.

    whaxon evidence 5fae0b1b36f4 --note "Confirmed weak ciphers"
    whaxon evidence 5fae0b1b36f4 --add screenshot.png

## Deployment

Docker, systemd, and HTTPS guidance live in docs/deployment.md.

    docker build -t whaxon:secure .
    docker run --rm -d --name whaxon \
      --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
      --cap-drop=ALL --security-opt=no-new-privileges:true \
      -p 127.0.0.1:5001:5001 \
      -v "$PWD/data:/data" \
      -e HOME=/tmp \
      -e WHAXON_AUTH_USER=whaxon -e WHAXON_AUTH_PASS=whaxon \
      -e WHAXON_DATA=/data \
      whaxon:secure

## Roadmap

### Near term

- Web UI file upload for Burp XML
- Send to tool actions on findings
- Scope declaration + out-of-scope safety warning

### Medium term

- SQLmap adapter with next-step logic
- Session tree (hosts, ports, findings, evidence)
- Multi-user auth, projects, audit logging

### Longer term

- AI-assisted next-step suggestions
- Autonomous pentest session orchestration
- Plugin marketplace

## Responsible use

WHAXON is intended for authorized security testing, defensive security operations, research, and education.

Only use WHAXON and its integrated tools on systems you own or have explicit permission to assess.

## Licensing

WHAXON Community is licensed under AGPL-3.0-or-later. See LICENSE-COMMERCIAL.md and LICENSE-ENTERPRISE.md.

## Documentation

- User guide: docs/
- Deployment: docs/deployment.md
- Architecture: docs/architecture.md

WHAXON - One platform. Every layer of security.
