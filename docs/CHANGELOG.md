# Changelog

## Unreleased

- Bump version to 0.2.0.

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