# Third-party components and licensing

WHAXON runtime dependencies, base package plus optional extras.

## Base package

- platformdirs >= 4.0 — MIT; see upstream LICENSE.
- dnspython >= 2.6 — ISC; see upstream LICENSE.
- defusedxml >= 0.7.1 — PSF License; see the upstream LICENSE and copyright notice.

## Extra: tui

- textual >= 0.80 — MIT.
- rich >= 13 — MIT.
- textual-image >= 0.8 — see upstream LICENSE.

## Extra: gui

- PySide6 >= 6.7 — LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only.
- qasync >= 0.27 — see upstream LICENSE.

## Extra: web

- flask >= 3.0 — see upstream LICENSE (BSD-3-Clause upstream).
- gunicorn >= 21 — see upstream LICENSE (MIT upstream).
- waitress >= 3.0 — ZPL 2.1.
- bcrypt >= 4.0 — Apache-2.0.
- flask-limiter >= 3.5 — see upstream LICENSE (MIT upstream).
- markdown >= 3.5 — see upstream LICENSE.

## Extra: metasploit

- pymetasploit3 >= 2.0 — GPL. Compatible with the project AGPL-3.0-or-later license; review on redistribution.

## External tools (not bundled)

WHAXON drives external security tools that the user installs independently. Named examples: Nmap, Nikto, sqlmap, Metasploit, Impacket, hashcat, WhatWeb, WPScan, Gobuster, ffuf, Nuclei, theHarvester, dnsrecon, dig, whois. They are not distributed with the package. Before redistributing any of them, obtain the exact upstream release, preserve its license and notices, and review each platform redistribution terms.

## Development-only dependencies (not in the runtime notice)

See pyproject.toml project.optional-dependencies.dev. Dev-only dependencies do not ship with the package.
