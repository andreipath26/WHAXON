# WHAXON

**One platform. Every layer of security.**

[![CI](https://github.com/andreipath26/WHAXON/actions/workflows/ci.yml/badge.svg)](https://github.com/andreipath26/WHAXON/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/whaxon.svg)](https://pypi.org/project/whaxon/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/whaxon.svg)](https://pypi.org/project/whaxon/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

**WHAXON** turns your pentest tools into a pipeline. One catalog, three interfaces (terminal, desktop, web). Three things it does that most tools do not:

- **Deterministic auto-chaining.** When nmap finds an HTTP port on `127.0.0.1:8090`, WHAXON queues nikto against *that specific port* automatically. Rule-based, no LLM in the loop — just a rule that fires on findings. Turn it off with `WHAXON_AUTOCHAIN=false`.
- **Cross-tool correlation.** nmap says port 8090 is open. nikto says `/login.php` is on 8090. WHAXON emits a `web_login_surface` finding that says both, because that is what a pentester wants to know. Eight rules today, all deterministic, all testable offline.
- **AI with hard guardrails.** An optional AI layer proposes the next action. A deterministic executor validates every proposal before anything runs: catalog check, scope check, target lock, dedup guard, stagnation stop. The planner proposes; the executor disposes.

## Status

**v0.3** — adapter architecture, deterministic automation, cross-tool correlation, optional AI with executor guardrails, three working interfaces.

### Working now

| Feature | Status |
| --- | --- |
| Headless core (catalog + runner + event bus) | Working |
| Terminal interface (Textual) | Working |
| Desktop interface (PySide6 + QWebEngineView) | Working |
| Web interface (Flask + SSE + Basic auth) | Working |
| Production WSGI server (`whaxon serve --daemon`) | Working |
| Tool catalog with argument templates | Working (11 tools) |
| Adapter layer | Working (14 adapters) |
| Enriched findings (CVSS, CWE, impact, remediation) | Working |
| Fail-closed scope enforcement | Working |
| Deterministic auto-chain (nmap -> nikto per web port) | Working |
| Correlation engine | Working (8 rules) |
| Pivot chain graph + rendering | Working |
| Burp XML import | Working |
| SQLite persistence across all interfaces | Working |
| Reports (per-job MD/HTML/PDF + engagement MD/JSON/PDF) | Working |
| Evidence attachments | Working |
| Metasploit RPC integration | Working |
| AI layer (Ollama / OpenAI / Anthropic / Google) | Working, opt-in |
| Plugin API (entry-point adapters) | Working |
| Published to PyPI | [![PyPI](https://img.shields.io/pypi/v/whaxon.svg)](https://pypi.org/project/whaxon/) |
| Test suite | 519 passing |

### Planned

| Feature | Priority |
| --- | --- |
| Web UI file upload for Burp XML | Near term |
| Multi-user auth + projects | Medium term |
| Demo GIF + video walkthrough | Near term |

## Try WHAXON in 60 seconds

    pip install whaxon
    whaxon init --demo
    whaxon run nmap scanme.nmap.org --extra "-F -T4"

That last command scans  — a public host Nmap's authors
maintain specifically for people to test their scanners against. You get:

    [2 findings]
      [MEDIUM  ] open_port  22/tcp  open  ssh    OpenSSH 6.6.1p1
      [INFO    ] open_port  80/tcp  open  http   Apache httpd 2.4.7

    job: 9a52ab3c5b7b
    report: whaxon report 9a52ab3c5b7b

Then:

    whaxon findings scanme.nmap.org        # every finding against that target
    whaxon report 9a52ab3c5b7b --open      # view the report

The demo scope permits only , , and .
Try  and it will refuse — that is what fail-closed
scope looks like.

## Install

    pip install whaxon

Optional extras:

    pip install "whaxon[tui]"           # Terminal UI (Textual)
    pip install "whaxon[gui]"           # Desktop app (PySide6)
    pip install "whaxon[web]"           # Web interface (Flask)
    pip install "whaxon[metasploit]"    # Metasploit RPC client
    pip install "whaxon[tui,gui,web]"   # Everything

Then:

    whaxon init                # create data/ with strict default scope
    whaxon tui                 # Terminal UI (Textual)
    whaxon gui                 # Desktop app (PySide6)
    whaxon serve --daemon      # Production web server
    whaxon web                 # Web, foreground (dev)

## Quick start (from source)

    git clone https://github.com/andreipath26/WHAXON.git
    cd WHAXON
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[tui,gui,web]"

![DVWA findings parsed by the nikto adapter](https://raw.githubusercontent.com/andreipath26/WHAXON/main/docs/assets/dvwa-findings.png)

Requires Python 3.11+.

    whaxon init                # create data/ with strict default scope
    whaxon tui                 # Terminal UI (Textual)
    whaxon gui                 # Desktop app (PySide6)
    whaxon serve --daemon      # Production web server
    whaxon web                 # Web, foreground (dev)

Web UI: <http://127.0.0.1:5001/ui>

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `WHAXON_HOST` | `127.0.0.1` | Bind address |
| `WHAXON_PORT` | `5001` | Port |
| `WHAXON_DATA` | `data` | Data directory |
| `WHAXON_AUTH_USER` | `whaxon` | Basic auth username |
| `WHAXON_AUTH_PASS` | `whaxon` | Basic auth password (hashed at startup) |
| `WHAXON_AUTH_PASS_HASH` | (unset) | Pre-hashed password; takes priority over `WHAXON_AUTH_PASS` |
| `WHAXON_AUTOCHAIN` | `true` | nmap -> nikto auto-chain on web ports |
| `WHAXON_MSF_AUTOCHAIN` | `false` | Run post modules after a Metasploit exploit session opens |
| `WHAXON_MSF_TIMEOUT` | (unset) | Timeout for Metasploit RPC calls |
| `WHAXON_AI_SCOPE_EXPANSION` | `strict` | AI scope-expansion policy. v1 ships `strict` only. |
| `WHAXON_AI_ENABLED` | `false` | Master switch for the AI planner layer |
| `WHAXON_AI_PROVIDER` | `null` | `null` / `rules` / `ollama` / `openai` / `anthropic` / `google` |
| `WHAXON_AI_MODEL` | per-backend | Model name for the selected provider |
| `WHAXON_AI_MAX_STEPS` | `12` | Step budget per AI run |
| `WHAXON_AI_MIN_CONFIDENCE` | `0.55` | Actions below this confidence become ask_human |
| `WHAXON_OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama backend endpoint |
| `WHAXON_OPENAI_HOST` | (OpenAI default) | OpenAI-compatible endpoint override |
| `WHAXON_ANTHROPIC_HOST` | (Anthropic default) | Anthropic endpoint override |
| `WHAXON_GOOGLE_HOST` | (Google default) | Google/Gemini endpoint override |

**Change the auth credentials before exposing WHAXON on any network.**

## Adapters

Every tool can have an adapter — a Python class that parses its output and enriches findings.

![WHAXON web interface](https://raw.githubusercontent.com/andreipath26/WHAXON/main/docs/assets/screenshot-01.png)

Built-in: `nmap`, `nikto`, `sqlmap`, `burp`, `hashcat`, `impacket`, `msf`.

Catalog tools without an adapter still run; their output just isn't enriched.

See [docs/adapters.md](docs/adapters.md) for the built-in adapter layer.

For shipping an adapter as a separate pip package, see [docs/plugins.md](docs/plugins.md).

## Scope

Fail-closed. Missing `data/scope.json` gets a strict default on first load. Unreadable config raises.

    whaxon scope --show
    whaxon scope --check <target>
    whaxon scope --set scope.json
    whaxon scope --enable / --disable
    whaxon scope --clear

See [docs/scope.md](docs/scope.md).

## Interfaces

- **Terminal** (`whaxon tui`): `r` run, `x` cancel, `g` chain, `s` save report, `Ctrl+Q` quit.
- **Desktop** (`whaxon gui`): native window hosting the web UI in a `QWebEngineView`.
- **Web** (`whaxon serve --daemon`): Flask + SSE. API + browser UI at `/ui`.
- **CLI**: 21 subcommands — see [docs/interfaces.md](docs/interfaces.md).

## Reports

    whaxon report <job_id>                              # Per-job, Markdown
    whaxon report <job_id> --format html                # Per-job, HTML
    whaxon report <job_id> --format pdf --out scan.pdf  # Per-job, PDF
    whaxon report --engagement default --format md      # Engagement, Markdown
    whaxon report --all --format whaxon                 # Engagement, signed .whaxon
    curl -u whaxon:whaxon "http://127.0.0.1:5001/api/report?format=md"   # Engagement via HTTP

![Correlated findings in a WHAXON PDF report](https://raw.githubusercontent.com/andreipath26/WHAXON/main/docs/assets/engagement-nikto.png)

HTML output is escaped — a `raw_line` with `<script>` can't execute in a browser.

## Testing

    python -m pytest tests/ -q

519 tests passing.

## Documentation

[docs/](docs/) — getting started, architecture, adapters, plugins, tools, scope, interfaces, findings, reports, API, deployment, troubleshooting, changelog.

## Responsible use

Authorized testing only. Use on systems you own or have explicit permission to assess.

## Licensing

AGPL-3.0-or-later. See `LICENSE-COMMERCIAL.md` and `LICENSE-ENTERPRISE.md`.
