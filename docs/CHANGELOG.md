# Changelog

## 2026-09-28 (session 9)

### Added

- **whaxon run <tool> <target>** — execute a catalog tool directly from the CLI. Streams stdout/stderr live, persists to the store, prints a findings summary and the report command on finish. Flags: --extra, --data, --timeout, --allow-out-of-scope, --quiet, --json. Exit codes: 0 OK, 1 tool error, 2 out of scope, 3 unknown tool, 64 usage error.
- tests/test_run_cmd.py (9 tests).

### Fixed

- run_cmd.py: added missing JobStarted import (caught by the first smoke test — the subscribe call raised NameError before any tool ran).

### Tests

- 275 passing (was 266).

## 2026-09-28 (session 8)

### Released

- **whaxon 0.3.0 published to PyPI** — https://pypi.org/project/whaxon/0.3.0/

### Added

- .github/workflows/release.yml — triggered on v* tags. Runs the full test suite, builds the wheel and sdist, publishes to PyPI via the PYPI_API_TOKEN repository secret.
- .gitignore now ignores dist/, build/, *.egg-info/ (Python build artifacts).

### Changed

- pyproject.toml: version 0.2.0 -> 0.3.0. License field switched to the PEP 639 string form (was the deprecated dict form). Added license-files = [LICENSE], 37 keywords, 11 classifiers, [project.urls] with Homepage/Repository/Issues/Changelog, and an explicit sdist allow-list that cuts the source distribution from 3.4 MB to 138 KB.
- whaxon/__init__.py: __version__ = 0.3.0.

### Fixed

- tools/state.py: build() now checks for pyproject.toml at REPO root and exits 1 with a clear message if missing. Previously, whaxon state crashed with FileNotFoundError when run from an installed wheel (where the source tree is not on disk). Found during the PyPI pre-flight smoke test.
- tests/test_state.py: no longer hardcodes the version string; reads whaxon.__version__.

### Tests

- 266 passing (unchanged from session 7).

## 2026-09-28 (session 7)

### Added

- tests/test_tui_report_format.py (6 tests): ReportFormatScreen composes all five format labels, keys 1/3/5 dismiss with md/pdf/whaxon respectively, escape dismisses with None, job_id is preserved on the screen.
- tests/test_tui_main.py (14 tests): MainScreen composes expected widget IDs (#catalog, #history, #target, #extra, #run, #cancel, #output, #search, #status), cancel button starts disabled, run button starts enabled, both tables have 3 columns, BINDINGS contains r/x/s/g/i/ctrl+q, focus actions move focus to the right widget, run-selected without tool/target sets status, cancel-with-nothing sets status, JobStartedMsg/JobFinishedMsg/JobFailedMsg toggle the cancel button and update the status line.

### Changed

- WhaxonApp.__init__ now accepts an optional data_dir parameter. Previously hardcoded to Path(__file__).parents[4] / "data". This lets tests, demos, and multi-profile runs point the TUI at a specific directory. No existing callers break (the parameter is optional).

### Tests

- 266 passing (was 246).

## 2026-09-28 (session 6)

### Added

- tests/test_msf_tracker.py (9 tests): _poll no-op when MSF is down, first sighting creates a session row and fires SessionStarted, second sighting does not refire, closing a session flips store status and fires SessionClosed, MSFUnavailableError mid-flight is swallowed, existing sessions get last_seen refreshed and info updated, start() spawns a daemon thread and stop() joins it, start() is idempotent, _loop swallows exceptions from a broken client.

### Tests

- 246 passing (was 237).

## 2026-09-28 (session 5)

### Added

- tests/test_runner.py (15 tests): ToolRunner.build_argv (no catalog, unknown tool, template substitution, default template, extra_args append, bad template), run_tool happy path (JobStarted/Output/Finished fire in order, stdout captured, stderr captured separately), scope enforcement (out-of-scope raises OutOfScopeError before spawn, allow_out_of_scope bypasses), missing binary (FileNotFoundError + JobFailed event), timeout (process killed + JobFailed with error=timeout), cancel (terminates running subprocess, unknown job is a no-op), and findings publication through the nmap adapter.

### Fixed

- core/events.py: JobFailed was missing the @dataclass(frozen=True, kw_only=True) decorator that every other Event subclass has. This made JobFailed(job_id=..., error=...) raise TypeError instead of instantiating. Affected the runner's tool-not-found and timeout paths, which had never been exercised by any prior test.

### Tests

- 237 passing (was 222).

## 2026-09-28 (session 4)

### Added

- tests/test_server_ai.py (18 tests): /api/ai/run (validation, 202 + store entry), /api/ai/runs (list), /api/ai/runs/<id> (found, not found, stream not found), evidence CRUD (list empty, add note, add missing body, delete, delete missing, download note returns 404), error paths (output.txt missing and present, findings.csv content type, findings.json shape, cancel unknown job returns ok=false).
- tests/test_server_portfwd.py (9 tests): GET list (empty, rows, error swallowed), POST add (missing fields, missing rhost, success with call-args assertion and pivot edge written, exception returns 500), DELETE (missing lport, success).

### Tests

- 222 passing (was 213).

### Server test coverage

- D2 complete. All Flask endpoints now have at least one test:
  - test_server.py       27 non-MSF, non-AI endpoints
  - test_server_msf.py   18 MSF endpoints
  - test_server_ai.py    18 AI + evidence + error paths
  - test_server_portfwd.py  9 portfwd endpoints
  - Total: 72 server tests covering ~46 HTTP routes.

## 2026-09-28 (session 3)

### Added

- tests/test_server_msf.py (18 tests): /api/msf/status (up/down), /api/msf/sessions (empty, live, msf-down), /api/msf/sessions/<id> (found, not found, msf-down), /api/msf/sessions/<id>/exec (missing command, msf-down, success with call-args assertion), /api/msf/modules/<type> (exploit, bad type, msf-down), /api/msf/run validation (missing module_path, bad module_type, out-of-scope target, in-scope acceptance).

### Deferred

- /api/msf/sessions/<id>/portfwd GET/POST/DELETE — deferred to session 4. Requires mocking client.connect().sessions.session(id) with .write()/.read() — deeper than FakeMSF covers.

### Tests

- 195 passing (was 177).

## 2026-09-28 (session 2)

### Added

- tests/test_server.py (27 tests): /api/health, /api/tools, /api/history, /api/jobs/<id> (detail, findings, per-job report md and fmt alias), /api/report (md, json, whaxon envelope, envelope integrity), /api/scope (get, check allowed, check denied), /api/loot, /api/tree, /api/pivot/graph, /api/settings, /ui, /, and the auth gate (required on non-loopback, accepted with correct Basic, rejected with wrong password, skipped on loopback).

### Found

- server.py defines two @app.get("/api/health") decorators. Flask keeps the first one (the readiness probe returning {status, checks}); the second ({ok, tools}) is unreachable. The shadowed route should be removed or renamed.

### Tests

- 177 passing (was 150).

## 2026-09-28 (session 1)

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