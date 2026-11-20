# WHAXON — V1 RELEASE AND ACCEPTANCE MASTER

> **Current release and sequencing status (2026-11-06):** `pyproject.toml` declares **0.11.16 Beta**, Python `>=3.11`; V1.0 acceptance remains OPEN. The live 75-row requirements ledger records 12 accepted bounded entries (four product-requirement rows plus G01–G05 and G07–G09); this is acceptance accounting, not code-completion percentage. The implementation baseline `0cef416` passed its recorded 20/20 CI run; current `main` `a05949a` is documentation-only. Complete all agreed V2 engine/UI and remaining solo-v1.0 implementation first, with internal testing throughout; only then begin deferred external qualification. Current HOLD reflects incomplete implementation and the lack of a qualified release candidate.

**Consolidated 2026-11-05.** This is the single V1 baseline, 75-requirement and release acceptance narrative. The product roadmap remains authoritative for priorities. Older checkpoint assertions have their original dates and SHAs, and must not be treated as live deployment approval. CSV ledgers and CI remain machine-checkable underlying evidence.

## Part I — V1 baseline and release acceptance register

# WHAXON v1.0 Baseline and Acceptance Register

> **Acceptance reconciliation — 2026-11-03:** At source commit `f0b25d3629d7`, 4 of 75 bounded requirement entries (P0-04, P1-01, P2-07, P4-01) are accepted with exact-commit CI evidence; 71 remain NOT_ACCEPTED. No E0–E9 phase or G01–G10 v1.0 release gate is closed. Prior claims that one-shot coverage/validate/retest/recon still drain unrelated pending jobs are historical and superseded by current source and `test_cli_initialization_isolation.py`. See [acceptance reconciliation](./V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md).

> **Integration update — 2026-11-02, supersedes affected baseline statements below:** Four one-shot CLI commands now use `initialize(drain=False)` with regression coverage. Desktop startup targets `/ui-v2`. Test catalog consumers use the packaged seed; the duplicate tracked root catalog and unused qasync requirement/manifest entry are removed, while operator catalogs and protected legacy designs remain preserved. See [UI control inventory](V2_UI_MANDATORY_CROSSWALK.md) for 793 source controls across 22 templates; static coverage does not establish complete runtime wiring, visual fidelity, accessibility or service parity. Local browser execution is blocked by unavailable Chromium downloads. Local Python 3.12 verification: **1,110 passed, 14 skipped**, excluding 34 browser-dependent modules because Chromium downloads fail. Ruff, mypy (142 source files), wheel/sdist build and metadata checks, and clean-wheel arbitrary-workspace catalog bootstrap passed. The earlier CI/source records below describe their stated baseline, not acceptance of this integration.


**Reviewed:** 2026-11-02
**Repository / branch:** `andreipath26/WHAXON-AI-Forensics` / `main`
**Inspected source baseline:** `6fa1fa5f9bcff9b7afffb87ca908b0f78562fa3b`
**Authority:** [Product trajectory](../WHAXON%20ROAD%20MAP%20-%20WHATS%20NEXT%20-%20FULL%20SCOPE.md), P0–P8 and §38 G01–G10; detailed Engine v2 specification remains subordinate to that trajectory.
**Status:** P0 is partial; v1.0 acceptance remains OPEN.

This register replaces the older `4019b655` snapshot as the current baseline. It records source inspection, tracked-file counts and exact-baseline remote CI evidence. No local application, external-tool or browser tests were run for this documentation review; the local environment lacks the project test dependencies. Principal paths below are traced, but this is not an exhaustive per-control inventory or a full security audit.

## 1. Repository and release identity

| Item | Observed baseline |
|---|---|
| Source commit | `6fa1fa5f9bcff9b7afffb87ca908b0f78562fa3b` — `test: restore complete MSF tracker coverage and fix lint` |
| Package metadata | `0.11.16`, Beta, Python `>=3.11` in `pyproject.toml`; matching runtime version in `src/whaxon/__init__.py` |
| Tracked files | 534, including 82 Markdown and 294 Python files |
| Test modules | 147 files matching `tests/test_*.py`; 23 matching `tests/test_web_ui_v2*.py` |
| Production supplied UI | 22 `ui_v2_*.html` templates and 22 page destinations; dashboard has a route alias |
| Supplied design package | 32 HTML and 32 PNG files; totals include ten byte-identical loose copies and distinct alternatives |
| Packaged catalog | 24 entries in `src/whaxon/data/tools.json` |
| Tracked SQLite databases | None |
| Remote branches | 56 including `main`; 10 other tips strictly behind baseline, 45 diverged |
| Open PR search | No open PRs at inspection |
| Release acceptance | OPEN; no v1.0 release/publication claim is made by this review |

Counts describe tracked baseline content, not delivered feature counts. Package-index/tag publication was not independently rechecked in this review; verify it at release gate G09 rather than copying an old publication assertion.

The catalog entries are `nmap`, `nikto`, `gobuster`, `echo`, `sqlmap`, `whois`, `dig`, `nuclei`, `commix`, `ffuf`, `wpscan`, `impacket`, `theharvester`, `dnsrecon`, `msf_sysinfo`, `msf_getuid`, `msf_hashdump`, `ssh_cmd`, `smb_shares`, `smb_ls`, `netexec`, `arjun`, `wmi_exec`, `hydra`. Catalog entries, registered adapters, import-only integrations, installed executables, capability providers and verified support are distinct inventories.

## 2. Exact-baseline CI evidence

[CI run #41488450899](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/41488450899) completed successfully for the inspected SHA. All nine jobs passed.

| Job | Evidence / scope |
|---|---|
| Python 3.11, job `125424852642` | Ruff, mypy, pytest and distribution build passed; pytest **1,408 passed, 14 skipped** |
| Python 3.12, job `125424852500` | Same checks and totals; sdist runtime-resource check and clean-wheel smoke also passed |
| Python 3.13, job `125424852900` | Ruff, mypy, pytest and distribution build passed; pytest **1,408 passed, 14 skipped** |
| Ubuntu setup smoke | Built-wheel install, setup preview and virtual-environment bootstrap |
| macOS setup smoke | Built-wheel install, setup preview and virtual-environment bootstrap |
| Windows setup smoke | Built-wheel install, setup preview and virtual-environment bootstrap |
| Headless Linux server | Built web wheel, no-display setup/doctor checks and Waitress startup |
| Curated apt installation | Explicit plan/consent flow, executable checks and loopback-only scanner smoke |
| Curated Homebrew installation | Explicit plan/consent flow, executable checks and loopback-only scanner smoke |

The sdist-resource and clean-wheel steps are intentionally selected on Python 3.12, not repeated on 3.11/3.13. Fourteen skips remain skips; this record does not classify them as tested support. Setup smoke and selected loopback tools do not certify every OS release, external tool, optional profile or deployment mode. A later documentation or code commit requires its own CI result.

### Superseded failure records

- The previous baseline's `Route(..., session_host=...)` collection failure is fixed in current source. `core/routes.py` now defines `session_host`; `resolve()` carries it and `live_resolver()` obtains session peer identity. `tests/test_smb_pivot.py` covers missing/drifted identity, scoped sessions and route authorization. `tests/test_msf_tracker.py` covers preservation of persisted session identity. The exact-baseline matrix passes.
- The older approvals Refresh-queue browser failure on `e9b2f02` is historical evidence for that commit, not a current red-CI blocker. It does not close broader UI acceptance.
- Do not weaken identity guards or repeat completed parser/lease work to resolve stale documentation. Security and full product acceptance remain separate gates.

## 3. Principal workflow and evidence crosswalk

Paths are relative to the repository. Named test files exist in the inspected tree and are covered by baseline CI where not skipped; this table does not assert real-target coverage for every test or capability.

| Workflow / boundary | Actual source path and persisted state | Existing test evidence | Still required |
|---|---|---|---|
| Scope → command run | `interfaces/cli/run_cmd.py` → `Core.initialize(drain=False)` → `core/runner.py`; scope in `core/scope.py`; job/output/findings in `core/store.py` | `test_run_cmd.py`, `test_scope_failclosed.py`, `test_runner.py`, `test_executor_target_lock.py` | Cross-entry-point authorization and supported environment acceptance |
| Findings → follow-up | `core/__init__.py` store subscriptions precede `core/automation.py`; Automator queues pending Nikto jobs; `core/worker.py` claims/leases them | `test_automation.py`, `test_autochain_durable.py`, `test_worker.py`, `test_run_cmd.py::test_run_automatically_drains_jobs_queued_by_automator` | Declarative migration/parity before old path retirement; startup side-effect issue below |
| Recon → evidence | `interfaces/cli/recon_cmd.py` → `core/recon.py`/`recon_checks.py` → shared events/store | `test_recon.py` | Scope/provenance and actual configured-check support; one-shot startup contract |
| Adapter → normalized findings | `adapters/registry.py`, tool/session adapter modules, `core/findings.py`; raw/data/request context stored by `append_finding()` | `test_adapters_parse.py`, `test_adapter_severity.py`, `test_request_context.py`, adapter-specific tests | Full catalog/adapter/provider reconciliation, live version/platform/parser acceptance |
| Finding → deterministic validation | `interfaces/cli/validate_cmd.py` and web `/api/validate/<job_id>/<seq>` → `core/validator.py`; `store.update_verification()` records status/reason | `test_validator_engine.py`, `test_validator_blind.py`, `test_validator_observation.py`, `test_validator_request_context_contract.py`, `test_validator_security_regressions.py` | Full evidence/secret/scope and false-positive/inconclusive acceptance; POST/state-changing replay is refused, not generally supported |
| Verified finding → retest | `interfaces/cli/retest_cmd.py` and web `/api/retest/<job_id>/<seq>` → `Validator.revalidate()` → persisted verification status/reason | `test_validator_retest.py`, `test_validate_cmd.py`, `test_web_trust_layer.py` | End-to-end lifecycle and conservative fixed/still-vulnerable/inconclusive proof; one-shot startup contract |
| Coverage → report | `CoverageSkipped` event → `store.record_coverage()`; `coverage_cmd.py`; report `core/report.py`, `report.html`, charts/print CSS; web `/api/report` | `test_coverage.py`, `test_report.py`, `test_report_business_impact.py`, `test_report_pdf.py`, `test_report_cmd.py` | Complete persisted negative coverage, proof reproduction/redaction, format-specific review; no universal recall/confidence guarantee |
| Mission → DAG → provider | `workflow_cmd.py` → Core mission/plan services → `workflow.py`, `scheduler.py`, `capabilities.py`, `providers.py` → existing ToolRunner; durable mission/plan/task/attempt/manifest tables in store | `test_workflow_cli.py`, `test_workflow.py`, `test_capabilities.py`, `test_providers.py`, `test_store.py` | Durable campaign-wide budgets/cancellation/audit/reconciliation and shared API/UI lifecycle |
| Session/pivot → dispatch | `core/msf.py`, `msf_tracker.py`, `routes.py`, `portfwd.py`, `runner.py`; stored session identity compared with live identity | `test_smb_pivot.py`, `test_msf_tracker.py`, `test_session_adapter.py`, `test_executor_session.py` | Real SSH/SMB/WMI/MSF support matrix and DNS/redirect/secondary-request limits |
| Diagnostics → approved installation | `dependencies.py`, `remediation.py`, `installer.py`, `dependency_jobs.py`, `dependency_history.py`, `setup_environment.py`, `setup_installers.py`; packaged `dependencies.json`; operation/history/audit records | `test_dependencies.py`, `test_dependency_jobs.py`, `test_dependency_history.py`, `test_dependency_installer.py`, `test_setup_cmd.py`, `test_setup_installers.py` | Offline/upgrade/partial-failure/restart/clean-platform acceptance; Windows native tool install stays manual |
| Web/desktop → service | `interfaces/web/server.py`, `serve.py`, 22 UI-v2 templates; `gui/app.py` loads URL from `gui/embed.py` | `test_web_ui_v2*.py`, `test_server.py`, auth/cancellation tests; headless CI smoke | Desktop still opens `/ui`, unlike web root `/ui-v2`; visual/accessibility/all-control/parity/external-asset gates remain open |

The AI proposal path remains `interfaces/cli/ai_cmd.py` or web AI routes → `core/ai_bridge.py` → `ai/executor.py` → guarded runner. Its approvals/phase/resume tests and `test_ai_boundary.py` protect existing behavior. It has not been wholly migrated to the mission DAG. Existing worker, Automator and AI paths are active, not dead modules removable by naming them legacy.

## 4. Resolved one-shot dispatch finding — current source reconciliation

**Status: fixed, with explicit regression coverage.** The previous section was a source snapshot before the correction. At the inspected 2026-11-05 code HEAD, `run_cmd.py`, `coverage_cmd.py`, `validate_cmd.py`, `retest_cmd.py` and `recon_cmd.py` explicitly use `Core.initialize(drain=False)`; workflow CLI initialization follows the same isolation policy. `tests/test_cli_initialization_isolation.py`, `tests/test_initialize_drain.py` and `tests/test_run_cmd.py` test unrelated pending jobs and intentional own-follow-up draining. The optional `drain=True` Core behavior remains intentional for long-lived execution. **P1-01 is the bounded accepted requirement in the source-linked ledger; G02 is still OPEN** because it includes many more security boundaries than this fix.

## 5. Implemented components versus outstanding acceptance

| Area | Implemented now | Acceptance or migration still open |
|---|---|---|
| E1 guards | One-shot isolation, leases/ownership/heartbeat, stale recovery, session/pivot identity and immediate pre-process scope checks | Cross-transport DNS/redirect/follow-up/pivot boundary, cancellation and adversarial race acceptance remain open; the one-shot defect itself is closed |
| E2 contracts | Immutable versioned WorkflowTask/WorkflowPlan and manifests, plan digests, exact ApprovalBinding, durable mission/task/attempt persistence | Common lifecycle and real-workflow recovery evidence |
| E3 scheduler | Atomic claims, retries, per-task deadlines, fencing and uncertain outcomes; durable mission cost/rate/deadline limits, cancellation intent and audit/outbox paths exist | Full external-effect recovery, real-provider side effects, transport parity and independent audit-anchor acceptance remain open |
| E4 providers | Constrained catalog-backed scanner bridge with default catalog inputs; registered manifests | Portfolio reconciliation, readiness/permission/impact truthfulness, separately authorized session/API transports |
| E5 services/headless | E5 bounded engineering-accepted shared V2 service, durable run requests, CLI/API/headless worker, Docker/systemd startup and offline restore smokes; PR #124 merged 2026-11-05 | Legacy direct-path migration, broad UI parity, real-target/production security, external audit anchors, full disaster recovery and V1 release gates remain open |
| E6 supplied UI | 22 V2 templates, browser routes and page-specific tests; web and desktop defaults already switched to `/ui-v2` | Every-control completion, D1–D6 visual/manual accessibility/security/parity, external assets and final production acceptance remain open |
| Setup and deployment | Profiles/doctor/plans/approval-bound installers and selected cross-platform smoke | Full clean-machine/upgrade/offline/partial-failure/restart, optional-extra and advertised service-mode matrix |

The provider bridge's allowlist and registered manifests are an initial slice. They do not establish every tool as independently verified, safe for every parameter set, installed or authorized. Current `core/remediation.py` plans dependency repairs; it is not the deferred vulnerability patch/application engine.

## 6. Repository cleanup and branch disposition (historical 2026-11-02 baseline)

The following counts and pre-cleanup code/catalog assertions are preserved as dated baseline evidence, **not current tracked-file counts or pending tasks**. The later documentation consolidation and migrated catalog consumers supersede those cleanup details.

[Due diligence](PROJECT_GOVERNANCE_MASTER.md) is the exact removal/retirement register. Cleanup removes Batches A/B (23 non-runtime files); no runtime code or branches are deleted. Byte-identical loose UI copies and unconsumed imports/exports differ from live compatibility paths, unique historical rationale, legal notices or retained evidence. Root `data/tools.json` still has test/runtime consumers; migration must precede removal. Distinct supplied designs and the legacy UI design remain preserved.

Remote comparison of all 55 non-main tips against the baseline found **10 strictly behind** and **45 diverged**. Strict ancestry containment proves no unique commits beyond main at that tip; it does not check external references or authorize deletion. Divergence can reflect squashed integration; it neither proves missing work nor safe deletion. Match PR contents and final files before retiring those tips. Do not merge old branches over current main merely because they are ahead. No pending PR merge was identified.

## 7. Remaining work and order

Finish implementation before external qualification, while continuing internal testing throughout:

1. **P0–P2:** complete the execution-path/capability inventory; close authorization, validation, evidence, shared-lifecycle, legacy migration, provider-effect recovery, and cross-client parity gaps.
2. **P3:** complete setup, packaging, headless worker, installation, upgrade, and recovery implementation; use internal tests and staging fixtures to find and fix defects during development.
3. **P4:** finish all agreed V2 UI workflows and control wiring against real services; complete internal browser/API and accessibility automation. The UI is active implementation work.
4. **P5:** integrate the complete solo-v1.0 scope and establish a green exact-source internal test/CI baseline.
5. **Post-completion qualification:** only after P0–P5 implementation is complete and internal checks pass, run authorized real-target validation, independent evidence/security review, manual accessibility review, production-like install/upgrade/rollback/restore, then record the final release identity and decision.
6. **P6–P8:** broader bounty autonomy, multi-target/competitive measurement, full Metasploit, expanded candidate onboarding/upstream monitoring, remediation application, enterprise and platform expansion remain gated/deferred.

A current green matrix is substantial engineering evidence. It does not close the open product gates or justify a global completion percentage. Refresh this register when source/CI evidence changes, rather than carrying forward old failure tables or forecasts.


---

## Part II — Bounded acceptance reconciliation (2026-11-03 evidence)

# WHAXON v1.0 — bounded requirement acceptance reconciliation (2026-11-03)

**Decision:** accept four *bounded* source-level requirements, not four entire phases or any release gate.
**Source baseline:** [main at `f0b25d3629d776b433f72c83db679bb41313c812`](https://github.com/andreipath26/WHAXON-AI-Forensics/commit/f0b25d3629d776b433f72c83db679bb41313c812).
**Exact-SHA CI:** [run #41642767222](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/41642767222): all 10 checks successful (Python 3.11, 3.12, 3.13; E1 regression job; Linux headless; Windows/macOS/Ubuntu setup; curated apt and Homebrew smokes).
**Evidence provenance:** GitHub source review, named test assertions and exact-source CI. No independent local execution, real-host service recovery, live scanner, visual/accessibility or end-to-end lab acceptance was performed in this reconciliation.
**Decision authority:** user-requested acceptance of already-proven behavior, with conservative boundaries.
**Ledger:** `ENGINE_V2_ROADMAP_REQUIREMENTS.csv`.

## Accepted requirements

| ID | Exact demonstrated behavior | Assertion/evidence | Limit |
|---|---|---|---|
| P0-04 | Only packaged catalog seed remains tracked; fresh workspace seeds from package and existing operator catalogs are preserved | `src/whaxon/data/tools.json`; missing `data/tools.json`; `tests/test_catalog_bootstrap.py::test_new_workspace_bootstraps_packaged_catalog_outside_checkout`; `::test_existing_operator_catalog_survives_startup_unchanged` | Tool *catalog presence* is not tool authorization or compatibility |
| P1-01 | `coverage`, `validate`, `retest`, `recon` and `run` initialize with `drain=False`, while `run` retains its own follow-up drain | `src/whaxon/interfaces/cli/{coverage_cmd,validate_cmd,retest_cmd,recon_cmd,run_cmd}.py`; `tests/test_cli_initialization_isolation.py::test_one_shot_preserves_unrelated_pending_jobs` (11 parameterized outcomes); `tests/test_run_cmd.py::test_run_automatically_drains_jobs_queued_by_automator` | Does not close other authorization, DNS, pivot or audit requirements |
| P2-07 | V2 catalog adapter provider is deliberately restricted to catalog defaults and registered readiness; unsupported providers are reported without enabling them | `src/whaxon/core/providers.py`; `tests/test_providers.py::test_catalog_adapter_provider_rejects_dynamic_cli_arguments`; `::test_provider_does_not_register_exploit_or_credential_tools`; `::test_catalog_portfolio_reconciles_unsupported_tools_without_registering` | No claim that providers are lab-validated or all E4 migration complete |
| P4-01 | The 22 production template/routes and preserved supplied reference design inventory have corresponding code/tests | 22 `ui_v2_*.html`, 27 `code.html` plus 27 `screen.png`; `tests/test_web_ui_v2_route_matrix.py::test_every_canonical_ui_route_renders`; `tests/test_web_ui_v2_control_inventory.py` | Does not accept all UI controls, backend wiring, visual fidelity, accessibility or offline assets |

All assertions are anchored to the source baseline and its successful CI; relevant test bodies were reviewed. This is a **bounded acceptance** decision. Any material later changes must be revalidated on the release candidate.

## Count and scope

- **4/75 ACCEPTED** (5.33%) as narrowly defined above.
- **71/75 NOT_ACCEPTED** remain in the ledger.
- **54 solo-v1-applicable** entries (P0–P5, E0–E6, G01–G10): **4 accepted, 50 open**.
- **21 deferred** entries (P6–P8, E7–E9) remain NOT_ACCEPTED; they are outside the solo-v1 release gate, not failed release requirements.
- **G01–G10: 0/10 closed.** G08 has exact-main CI success but still requires full exact-candidate browser, supported-platform acceptance and documented skips; current `0.11.16` Beta is not the approved v1 candidate.
- **E0–E9: 0/10 whole-engine gates formally closed**; no whole phase is inferred from bounded acceptance.

## Stale statement correction

The old baseline narrative in `STATE.md` and `V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md` describing default `drain=True` for four one-shot commands is historical, overridden by checked source and tests. Old E1 branch-only acceptance notes and older check-run totals are not the current main status. The preexisting 25/40 sampled-source-checkpoint figure is a different metric; it is not the 75-row acceptance figure.

## Still open before G01–G10 closure

Exhaustive cross-surface capability mapping; adversarial scope/external egress and audit-failure checks; validation/evidence ground truth; real worker/service restart and full backup/restore; 793-control runtime/visual/accessibility check; controlled solo-lab chain; supported installation modes; candidate-only CI; version/tag/index publication and explicit release decision.

**No product source code, visual assets or legacy designs were changed in this reconciliation.**

