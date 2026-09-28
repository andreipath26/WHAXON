# Changelog

## 2026-09-28 (session 2)

### Added

- tests/test_server.py (27 tests): /api/health, /api/tools, /api/history, /api/jobs/<id> (detail, findings, per-job report md and fmt alias), /api/report (md, json, whaxon envelope, envelope integrity), /api/scope (get, check allowed, check denied), /api/loot, /api/tree, /api/pivot/graph, /api/settings, /ui, /, and the auth gate (required on non-loopback, accepted with correct Basic, rejected with wrong password, skipped on loopback).

### Found

- server.py defines two @app.get("/api/health") decorators. Flask keeps the first one (the readiness probe returning {status, checks}); the second ({ok, tools}) is unreachable. The shadowed route should be removed or renamed.

### Tests

- 177 passing (was 150).


### Added

- tests/test_attach_chains.py (5 tests): empty store, no edges, non-from_exploit ignored, single chain, descendant traversal.
- tests/test_report_cmd.py (10 tests): engagement mode, --all alias, envelope shape, envelope integrity matches payload hash, --jobs filter, single-job paths, exit codes.
- tests/test_adapters_parse.py (9 tests): nmap severities, nikto dedup, sqlmap injectable parameter, burp XML, hashcat _find_hashes.
- WHAXON_AI_MAX_STEPS and WHAXON_AI_MIN_CONFIDENCE are now read at import time (were documented but ignored).
- Legacy ?fmt= accepted as an alias for ?format= on both report routes.
- archive/README.md explains that flask-legacy is dead code kept for context.

### Fixed

- pyproject.toml description said BACKFORGE; now says WHAXON. Author email filled in.
- cli.py: whaxon tui --help and whaxon gui --help now print usage instead of launching the interface.
- cli.py: whaxon --help no longer advertises the nonexistent forward subcommand.
- report_cmd.py: --format whaxon without --engagement now exits 2 with a clear message, matching the engagement-wide contract.
- report_cmd.py: envelope shape now matches /api/report?format=whaxon (format, version, generated, tool, engagement, integrity, payload).
- README env var table was missing WHAXON_AUTH_PASS_HASH, WHAXON_MSF_AUTOCHAIN, WHAXON_MSF_TIMEOUT, and the three provider host overrides.
- README test count was 54; correct value is 146.

### Changed

- server.py: extracted attach_chains helper into core/report.py; web route now calls it.
- server.py: envelope generated field reuses data.generated, so integrity is reproducible and verifiable against the payload.
- whaxon/__init__.py: __version__ = 0.2.0 (was empty); server and CLI both read it.

### Removed

- enterprise/, tools/, third_party/ (empty directories).
- src/whaxon/{plugins,reporting,api,catalog}/ (empty packages, no importers).
- v0.impacket git tag (local and remote).

### Tests

- 146 passing (was 122).

## Unreleased


## 2026-09-27

### Added

- Impacket adapter: secretsdump / smbclient / wmiexec. Wired through the web API. 5 unit tests.
- tests/test_impacket_adapter.py.

### Fixed

- TUI: deduplicate c binding (was colliding between cancel_job and show_chain). Now x = cancel, g = chain. Added missing textual.binding.Binding import.
- Report: to_markdown now calls _md_chains, so pivot chains actually render.
- Report: render_html now HTML-escapes markdown before wrapping in pre. A raw_line containing script tag no longer reaches the browser unescaped.

### Changed

- Scope default expanded: 127.0.0.0/8 (was 127.0.0.1), plus IPv6 link-local fe80::/10 and ULA fc00::/7.
- .gitignore deduplicated; data/scope_overrides.log untracked.
- runner._publish_findings now receives argv and target, passing them into adapter ctx.
- catalog.load() filters unknown keys from tools.json, so entries can carry metadata the Tool dataclass does not model.

### Tests

- 54 passing.
- Stale tests realigned: tests/test_report.py rewritten to match the actual per-job vs engagement contract; test_scope.py::test_missing_file_means_disabled replaced with a fail-closed assertion.

## Earlier

- feat: pivot chain graph, /api/pivot/graph, TUI g binding.
- feat: unified theme, GUI as web host, settings backend.
- feat(cli): whaxon init / up / down - no compose dependency.