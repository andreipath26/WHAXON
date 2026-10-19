# WHAXON

**WHAXON is a deterministic, validated penetration testing platform.**

Point it at a target. It chains your tools, correlates what they find, and produces an accurate report. But unlike the current wave of AI-driven scanners, WHAXON is built on a **Trust Layer**: every finding can be reproduced with a raw proof payload, verified by the deterministic engine, and tracked through a retest lifecycle. 

No LLM decides what is real; the proof does.

![WHAXON web interface — Findings](https://raw.githubusercontent.com/andreipath26/WHAXON/main/docs/assets/screenshot-ui-v4-findings.png)

<p align=center>
  <img src=https://raw.githubusercontent.com/andreipath26/WHAXON/main/docs/assets/screenshot-ui-v4-scope.png alt=Scope width=32%>
  <img src=https://raw.githubusercontent.com/andreipath26/WHAXON/main/docs/assets/screenshot-ui-v4-intel.png alt=Threat-Intel width=32%>
  <img src=https://raw.githubusercontent.com/andreipath26/WHAXON/main/docs/assets/screenshot-ui-v4-compliance.png alt=Compliance width=32%>
</p>

[![CI](https://github.com/andreipath26/WHAXON/actions/workflows/ci.yml/badge.svg)](https://github.com/andreipath26/WHAXON/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/whaxon.svg)](https://pypi.org/project/whaxon/) [![PyPI - Python Version](https://img.shields.io/pypi/pyversions/whaxon.svg)](https://pypi.org/project/whaxon/) [![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)

## Why WHAXON?

The 2026 market is flooded with autonomous AI agents that run tools and spit out findings. They are fast, but they hallucinate. Studies show the best AI frameworks still carry a higher false-positive rate than human testers. WHAXON solves this by keeping the LLM on a leash (R71). 

- **Deterministic Validation:** Findings enter the store as `candidate` and move to `verified` or `refuted` only when a payload is replayed and the response matches a deterministic signature. `whaxon validate <job_id> <seq>` runs the check. Payloads are vendored from PayloadsAllTheThings at a pinned SHA (MIT) — no runtime dependency on GitHub.
- **Reproducible Proof (--reproduce):** Outputs the raw curl or Python script that triggered the finding. You do not just get a verdict; you get the evidence.
- **Coverage Disclosure:** Tells the client exactly what was not tested (e.g., Skipped /admin, requires auth).
- **The Retest Loop:** Re-runs the validation payload after a fix. Marks the finding  or .
- **AI with hard guardrails:** An optional AI layer proposes the next action. A deterministic executor validates every proposal before anything runs: catalog check, scope check, target lock, dedup guard, stagnation stop.

## Try WHAXON in 60 seconds

pip install whaxon
whaxon init --demo
whaxon run nmap scanme.nmap.org --extra -F -T4

That last command scans scanme.nmap.org — a public host Nmap authors maintain specifically for people to test their scanners against. You get:

[2 findings]
  [MEDIUM  ] open_port  22/tcp  open  ssh    OpenSSH 6.6.1p1
  [INFO    ] open_port  80/tcp  open  http   Apache httpd 2.4.7

job: 9a52ab3c5b7b
report: whaxon report 9a52ab3c5b7b

Then:

whaxon findings scanme.nmap.org        # every finding against that target
whaxon report 9a52ab3c5b7b --open      # view the report

The demo scope permits only 127.0.0.1, ::1, and scanme.nmap.org. Try google.com and it will refuse — that is what fail-closed scope looks like.

## Install

pip install whaxon

Optional extras:

pip install whaxon[tui]           # Terminal UI (Textual)
pip install whaxon[gui]           # Desktop app (PySide6)
pip install whaxon[web]           # Web interface (Flask)
pip install whaxon[metasploit]    # Metasploit RPC client
pip install whaxon[tui,gui,web]   # Everything

Then:

whaxon init                # create data/ with strict default scope
whaxon tui                 # Terminal UI (Textual)
whaxon gui                 # Desktop app (PySide6)
whaxon serve --daemon      # Production web server
whaxon web                 # Web, foreground (dev)

## Scope

Fail-closed. Missing data/scope.json gets a strict default on first load. Unreadable config raises.

whaxon scope --show
whaxon scope --check <target>
whaxon scope --set scope.json
whaxon scope --enable / --disable
whaxon scope --clear

See [docs/scope.md](docs/scope.md).

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| WHAXON_HOST | 127.0.0.1 | Bind address |
| WHAXON_PORT | 5001 | Port |
| WHAXON_DATA | data | Data directory |
| WHAXON_AUTH_USER | whaxon | Basic auth username |
| WHAXON_AUTH_PASS | whaxon | Basic auth password (hashed at startup) |
| WHAXON_AUTH_PASS_HASH | (unset) | Pre-hashed password; takes priority over WHAXON_AUTH_PASS |
| WHAXON_AUTOCHAIN | true | nmap -> nikto auto-chain on web ports |
| WHAXON_MSF_AUTOCHAIN | false | Run post modules after a Metasploit exploit session opens |
| WHAXON_MSF_TIMEOUT | (unset) | Timeout for Metasploit RPC calls |
| WHAXON_AI_SCOPE_EXPANSION | strict | AI scope-expansion policy. v1 ships strict only. |
| WHAXON_AI_ENABLED | false | Master switch for the AI planner layer |
| WHAXON_AI_PROVIDER | null | null / rules / ollama / openai / anthropic / google |
| WHAXON_AI_MODEL | per-backend | Model name for the selected provider |
| WHAXON_AI_MAX_STEPS | 12 | Step budget per AI run |
| WHAXON_AI_MIN_CONFIDENCE | 0.55 | Actions below this confidence become ask_human |
| WHAXON_AI_AUTO_ALLOW | (unset) | Master gate for --auto; must be 1 |
| WHAXON_AI_AUTO_PHASES | (empty) | Phase whitelist for unattended transitions |
| WHAXON_AI_AUTO_CONFIRM | (unset) | Force interactive confirm even in --auto |
| WHAXON_AI_AUTO_MAX_STEPS | 50 | Step budget per --auto run |
| WHAXON_OLLAMA_HOST | http://127.0.0.1:11434 | Ollama backend endpoint |
| WHAXON_OPENAI_HOST | (OpenAI default) | OpenAI-compatible endpoint override |
| WHAXON_ANTHROPIC_HOST | (Anthropic default) | Anthropic endpoint override |
| WHAXON_GOOGLE_HOST | (Google default) | Google/Gemini endpoint override |

**Change the auth credentials before exposing WHAXON on any network.**

## Adapters & Architecture

Every tool can have an adapter — a Python class that parses its output into typed Finding objects.

Built-in (25): arjun, burp, dig, dnsrecon, ffuf, gobuster, har, hashcat, impacket, msf, msf_getuid, msf_hashdump, msf_sysinfo, netexec, nikto, nmap, nuclei, smb_ls, smb_shares, sqlmap, theharvester, whatweb, whois, wmi_exec, wpscan.

Catalog tools without an adapter still run; their output just is not enriched.

See [docs/adapters.md](docs/adapters.md) for the built-in adapter layer.
For shipping an adapter as a separate pip package, see [docs/plugins.md](docs/plugins.md).

## Interfaces

- **Terminal** (whaxon tui): r run, x cancel, g chain, s save report, i target input, a AI runs, Ctrl+Q quit.
- **Desktop** (whaxon gui): native window hosting the web UI in a QWebEngineView.
- **Web** (whaxon serve --daemon): Flask + SSE. API + browser UI at /ui.
- **CLI**: 21 subcommands — see [docs/interfaces.md](docs/interfaces.md). Includes:
  - whaxon lookup — offline exploit search via searchsploit (search, --cve, --id, --save)
  - whaxon cve — online CVE lookup via NVD with a local SQLite cache (exact ID, --keyword)
  - whaxon vulndb — manage the local vulnerability database (update, status, lookup)

## Reports

WHAXON produces standalone, interactive HTML and PDF reports with KPI filtering, sortable findings, technical severity, business impact, and Cyentia IRIS cost ranges. 

whaxon validate <job_id> <seq>                       # Deterministic validation of one finding
whaxon report <job_id>                              # Per-job, Markdown
whaxon report <job_id> --format html                # Per-job, HTML
whaxon report <job_id> --format pdf --out scan.pdf  # Per-job, PDF
whaxon report --engagement default --format md      # Engagement, Markdown
whaxon report --engagement default --format html    # Engagement, HTML (standalone)
whaxon report --all --format whaxon                 # Engagement, signed .whaxon
curl -u whaxon:whaxon http://127.0.0.1:5001/api/report?format=md   # Engagement via HTTP

HTML and PDF output are both escaped — a raw_line with <script> cannot execute in a browser or corrupt the PDF.

## Status

**v0.10.0** — deterministic pipeline, cross-tool correlation, session transports, optional AI with executor guardrails, four working interfaces, interactive standalone HTML reports.

| Feature | Status |
| --- | --- |
| Headless core (catalog + runner + event bus) | Working |
| Terminal interface (Textual) | Working |
| Desktop interface (PySide6 + QWebEngineView) | Working |
| Web interface (Flask + SSE + Basic auth) | Working |
| Production WSGI server (whaxon serve --daemon) | Working |
| Tool catalog with argument templates | Working (22 tools + echo test fixture) |
| Adapter layer | Working (25 adapters) |
| Enriched findings (CVSS, CWE, impact, remediation) | Working |
| Fail-closed scope enforcement | Working |
| Deterministic auto-chain (nmap -> nikto per web port) | Working |
| Correlation engine | Working (8 rules) |
| Pivot chain graph + rendering | Working |
| Burp XML import | Working |
| SQLite persistence across all interfaces | Working |
| Reports (per-job MD/HTML/PDF + engagement MD/HTML/JSON/PDF, branded) | Working |
| Evidence attachments | Working |
| Metasploit RPC integration | Working |
| SSH transport | Working (live-verified) |
| SMB transport | Working (live-verified) |
| WMI transport | Untested, blocked (no Windows target on this host) |
| Phase-gated catalog | Working |
| Session-scoped tools | Working |
| AI layer (null / rules / Ollama / OpenAI / Anthropic / Google) | Working, opt-in |
| AI modes (interactive / --auto / --resume) | Working, opt-in |
| Approval queue (store + API + web UI + CLI) | Working |
| Plugin API (entry-point adapters) | Working |
| HAR ingestion (browser traffic capture) | Working (bounty add-on input layer) |
| Published to PyPI | Yes |
| Deterministic validation (whaxon validate) | Working — loader + CLI landed; re-execution engine next |
| Test suite | 775 passing |

## Roadmap

WHAXON is a solo-founder project. Scope is tracked in full on the founder Desktop roadmap; this section is the summary.

### In progress - The Trust Layer (v1.0)

The roadmap has a written v1.0 definition: one pentester runs recon through validated initial access, a coverage-disclosed report, and a retest lifecycle, end to end, with zero false positives and every finding reproducible.

**Landed so far:** PayloadsAllTheThings vendored at pinned SHA 3ac2790 (six chapters, MIT, attribution in data/payloads/), `verification_status` column with idempotent migration, `whaxon validate <job_id> <seq>` CLI, and a `PayloadLoader` that extracts 70 SQLi payloads from the vendored corpus.

**Next:** the re-execution engine (pick payload, run via runner, parse response, set verified or refuted), then coverage disclosure, the retest loop, and the three-tab UI. Full scope in roadmap §32 and §33.

### Shipped (v0.10.0)

- Deterministic pipeline, cross-tool correlation (8 rules)
- Four interfaces: CLI, TUI, Web, GUI
- Four transports: MSF, SSH, SMB (live-verified); WMI (untested)
- Six AI providers, three AI modes (interactive, --auto, --resume)
- Approval queue, phase-gated catalog, session-scoped tools
- CVE lookup (NVD) and offline exploit search (searchsploit)
- 22 tools + echo test fixture, 25 adapters
- HAR ingestion adapter
- Bug-bounty add-on design (§26)
- 774 tests passing

### Team-ready (~53-62h)

- **MCP server** - expose the catalog via Model Context Protocol so Claude Desktop, Cursor, and Codex can drive WHAXON. The keystone for team work.
- Verification layer - findings become candidates, then verified or refuted
- Persistent knowledge graph, multi-agent split, RAG for pentest knowledge
- Team-scale approvals with role gating

### Company-grade (~125-170h)

- Organization layer: orgs, teams, users, engagements
- RBAC: Owner, Admin, Pentester, Reviewer, Client-viewer, Auditor
- Client engagement lifecycle, compliance and audit (immutable log)
- Deployment: Docker, Kubernetes, air-gapped, cloud
- Commercial layer: licensing, billing, support tooling

### Market coverage (~185-235h)

- PTaaS delivery, remediation tracking, ASM / continuous monitoring
- Client reporting, compliance framework mapping
- Collaboration, threat intel, training mode, i18n, air-gapped
- Full CSPM / CIEM, BAS / AEV

### Explicitly out of scope (never built)

Wireless, SDR, forensics, reverse-engineering, malware analysis, social engineering, hardware, unstructured network attacks, mobile, honeypots, commercial scanners without CLI parity.

## Sister projects

WHAXON is one of three projects built to compose:

- **[KILN](https://github.com/andreipath26/KILN)** — the fastest local LLM runtime. One binary per platform, one model file, one API. No cloud, no GPU required.
- **[Aletheia Framework](https://github.com/andreipath26/aletheia-framework)** — the advisor framework. Local-first, modular, governed personal AI. Indexes everything, remembers with provenance, advises — never acts without authorization.

WHAXON is the deterministic domain expert in that stack: KILN provides local inference, Aletheia provides memory and governance, WHAXON provides the security testing pipeline.

Each project stands alone. None requires the others to run. Integration between them (MCP/ACP) is designed but not yet built.

## Testing

python -m pytest tests/ -q

774 tests passing.

## Documentation

[docs/](docs/) — getting started, architecture, adapters, plugins, tools, scope, interfaces, findings, reports, API, deployment, troubleshooting, changelog.

## Responsible use

Authorized testing only. Use on systems you own or have explicit permission to assess.

## Licensing

AGPL-3.0-or-later. See LICENSE-COMMERCIAL.md and LICENSE-ENTERPRISE.md.
