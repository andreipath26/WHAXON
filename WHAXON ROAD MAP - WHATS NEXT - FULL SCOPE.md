# WHAXON — PRODUCT ROADMAP MASTER

> **Historical source reconciliation (2026-11-05; inspected main `9bd4dfe`):** E5 [PR #124](https://github.com/andreipath26/WHAXON-AI-Forensics/pull/124) **merged November 5** with exact PR-head 12/12 CI. This establishes bounded E5 engineering acceptance, NOT production sign-off. UI PRs #126 (Dashboard) and #127 (Scope & Targets) are merged; their merges do not close D1–D6 or authorize deployment. The final pre-merge #127 head `bf89063` passed focused Scope acceptance and Dashboard visual CI, but its Full CI run [42063514323](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/42063514323) failed when the Python 3.13 lane's Ubuntu mirror download exceeded the 17-minute pandoc-install timeout; its tests did not run, while Python 3.11/3.12 and the other reported jobs passed. This branch increases the bounded timeout without skipping report/PDF tests. Legacy dispatch migration, E6, independent evidence anchoring, real authorized targets and V1 G01–G10 release gates remain OPEN. Engine V2 UI implementation continues; external E6 qualification is deferred until the full agreed UI and engine scope is internally complete. Older assertions that E5 or #127 merge is pending are superseded.

> **Current source and delivery-sequence reconciliation (2026-11-06; implementation baseline at main `0cef416155623199d8cb551b809dd469d62b4778`):** Exact-head CI run [42253317306](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/42253317306) passed all 20/20 jobs. Bounded G01–G05 and G07–G09 evidence remains useful engineering evidence, not full release approval. The current tree includes the G01 CLI inventory and AST guard, the PR #144 report overhaul, and the PR #143 upgrade smoke. Remaining implementation includes exhaustive legacy caller coverage, V2 lifecycle parity, full UI behavior/control wiring, and integration/recovery work. UI implementation is active. Run internal tests throughout implementation. Defer further real-target validation, independent external review, manual accessibility sign-off, and production-like rollout/rollback exercises until the agreed V2 engine, V2 UI, and remaining v1.0 implementation scope are complete and internal checks pass. G10 remains **HOLD — NOT READY TO DEPLOY** until that sequence and final candidate qualification are complete.

> **Current implementation status — 2026-11-20.** Main is at `dfe6a38` after PR #221 merged; the merge-head README-freeze and CI workflows passed. A local, unpublished continuation branch at `f997fc8` adds strict typed request validation for V2 budget, approval, and recovery endpoints while preserving existing routes and JSON shapes. The selected Engine V2/backend regression set passes (275/275); repository Ruff and mypy pass. The full local suite reported 1,908 passed, 17 skipped, and 376 browser setup errors because Chromium cannot create Unix sockets in this container; therefore it is not a passing full-suite result. G10 remains **HOLD — NOT READY TO DEPLOY**: exhaustive legacy execution-path coverage, remaining shared V2 lifecycle and transport parity, provider-effect recovery, complete UI behavior/control wiring, clean exact-candidate CI, and deferred external qualification are still open.

**Canonical product scope, priorities, delivery sequence and release gates. Consolidated 2026-11-05.**

The original product roadmap below is the governing source. The competitor-capability analysis is subordinate strategic input, not a parallel work order. The dated state snapshot is retained solely as historical evidence; exact-head code, tests and acceptance determine current state.

## Part I — Authoritative product roadmap

# WHAXON — Product trajectory and release gates

> **E5 engineering review (2026-11-04):** E5's supported durable V2 service has [bounded engineering acceptance evidence](docs/ENGINE_V2_MASTER.md) on source SHA `557311dfa125`, [12/12 CI](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/41815823360), and passing supervised Ubuntu systemd plus Docker worker/restore smokes. **Historical status at the time of this 2026-11-04 review:** final documentation-head CI and PR #124 phase-review/merge were still pending then; PR #124 subsequently merged on 2026-11-05. See the current-head reconciliation above. **This is not production acceptance:** legacy direct dispatch remains a recorded P2/E4 migration obligation, and G01–G10, real-target, external audit-anchor and full deployment gates remain OPEN. Earlier pre-E5 status notes below are historical.

## Engine V2 implementation-first sequence

Complete the agreed V2 engine, V2 UI, and remaining solo-v1.0 implementation scope before beginning final external validation. Keep internal unit, integration, static, adversarial, and browser testing active throughout development; fix defects as they are found. These checks support implementation and do not substitute for final external qualification.

After implementation scope is complete and internal checks pass, run the deferred qualification: controlled real-target testing with explicit authorization, independent evidence/audit review, manual accessibility and security review, production-like multi-worker operation, and install/upgrade/rollback/restore exercises. Production rollout follows a passing exact-candidate qualification; it is not a development test or a prerequisite to finishing features.

Existing bounded lab and CI results remain historical engineering evidence. Do not repeat or expand external validation while implementation is incomplete. P6–P8 / E7–E9 expansion remains deferred and is not part of the agreed solo-v1.0 completion denominator.

> **Engine V2 current-head evidence note (2026-11-03):** At main `f0b25d3629d776b433f72c83db679bb41313c812`, the [dated source audit](docs/ENGINE_V2_MASTER.md) and [checkpoint ledger](docs/ENGINE_V2_AUDIT_CHECKPOINTS_2026-11-03.csv) reconcile 33 source-backed of 48 *selected unweighted checkpoints* (68.75% sampled presence), including newer E2–E5 changes and merged E5 service-unit work. This is **not** a whole-engine completeness or v1.0 release percentage. The roadmap's priority/acceptance requirements below remain authoritative and no E0–E6 phase has formal full-gate sign-off. The earlier 25/40 audit is historical.

> **Integration update — 2026-11-02, supersedes affected baseline statements below:** Four one-shot CLI commands now use `initialize(drain=False)` with regression coverage. Desktop startup targets `/ui-v2`. Test catalog consumers use the packaged seed; the duplicate tracked root catalog and unused qasync requirement/manifest entry are removed, while operator catalogs and protected legacy designs remain preserved. See [UI control inventory](docs/V2_UI_MANDATORY_CROSSWALK.md) for 793 source controls across 22 templates; static coverage does not establish complete runtime wiring, visual fidelity, accessibility or service parity. Local browser execution is blocked by unavailable Chromium downloads. The earlier CI/source records below describe their stated baseline, not acceptance of this integration.


**Reviewed:** 2026-11-02 · **Repository:** `andreipath26/WHAXON-AI-Forensics`
**Inspected baseline:** `6fa1fa5f9bcff9b7afffb87ca908b0f78562fa3b` · **Package:** `0.11.16`, Beta
**Decision:** finish and accept one reliable solo assessment product before expanding the platform. **v1.0 acceptance is OPEN.**

This is the single active work order. It replaces the accumulated schedules, session diaries, tool-count targets and contradictory status snapshots in the previous roadmap. It does not erase approved deferred scope or turn implemented components into accepted product workflows. Current source/tests establish behavior; this file establishes priorities and acceptance; operator guides explain use. [Due diligence](docs/PROJECT_GOVERNANCE_MASTER.md) records removal and retirement decisions; [baseline register](docs/V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md) records source/test/CI evidence.

## 0. How to use this trajectory

Read the current baseline, follow P0–P5 in dependency order, and close §38 with evidence. A mapped critical correctness/security defect may move immediately into P1 while independent P0 inventory continues; P0 is not a serial waiting gate for a known bounded repair. P6–P8 are gated expansion. Work on independent tasks concurrently only when contracts, ownership, integration order and tests are agreed; follow [the engineering execution model](docs/PROJECT_GOVERNANCE_MASTER.md). Do not spawn work merely to increase concurrency.

Status meanings:

| Status | Meaning |
|---|---|
| Implemented | Source and regression coverage exist for the named behavior; acceptance may remain open |
| Partial | Some required behavior exists; specific gaps remain |
| Accepted | Named workflow passed its full gate on an exact revision/environment with retained evidence |
| Open | Required work or acceptance evidence is missing |
| Deferred | Approved direction outside the current release critical path |
| Retire after migration | Consumers/contracts must be migrated before removal |
| Remove after checks | No required behavior is lost; follow the due-diligence removal conditions |
| Excluded | Outside WHAXON's product boundary |

Do not derive a project-completion percentage from test counts, page counts, old DONE labels or merged PRs. There is no validated remaining-hours estimate. An accepted milestone needs commit, environment, commands/checks, result, limitations and evidence links. A failed, skipped or unavailable check is never a pass.

### Non-negotiable product rules

1. Deterministic plans and policy checks; AI proposes or explains, never grants authority or sets verification status.
2. Explicit consent bound to scope, exact plan/parameters, impact and expiry. An activated campaign may authorize routine in-envelope work; material changes and consequential actions need separate approval.
3. Bounded, allowlisted execution with least privilege, time/output/resource/rate ceilings, cancellation and fail-closed scope checks at dispatch and follow-up boundaries.
4. Independent verification. Tool output, exit zero, an installer result, a model assertion or a rendered page is not proof of success.
5. Attributable, timestamped, durable and tamper-evident evidence linking proposal, approval, action, observation, verification and recovery with stable operation/event IDs, plan/policy versions and digests, actor/approval identity and evidence hashes. Provide export and integrity checking through a verifiable hash chain or equivalent with an explicit trust anchor and stated limitations. Record denial, cancellation, timeout, crash, audit failure and uncertain effects. Hash chaining without an independent trust anchor is not immutability.
6. ZERO REDESIGN. Use the supplied `web ui files and rendering/` design inputs; preserve layout, typography, colors, spacing, components, icons, navigation and animations on supported desktop targets. Keep unsupported features hidden/disabled without deleting distinct supplied reference designs or inventing backend success. Preserve legacy design source unchanged.
7. CLI/API/headless services own behavior; clients do not own durable jobs or implement independent authorization rules. Preserve tested parsers, scope checks and data compatibility during migration.
8. No universal zero-false-positive, unlimited-scale, fully air-gapped or production-ready claims without evidence for the stated scope.

## 1. Where the project stands

The product has substantial implementation. The remaining release work is correctness, consolidation, durable shared lifecycle and integrated acceptance—not rebuilding the existing Trust Layer or replacing the supplied UI.

| Workstream | Current evidence | Remaining boundary |
|---|---|---|
| Package and quality | `0.11.16` Beta, Python `>=3.11`; [13/13 CI jobs passed at `fc056d0`](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/42033360849), including Python 3.11–3.13, systemd, Docker, SearchSploit and installation lanes | Exact-SHA engineering checks, not v1.0 or the next HEAD's acceptance; standard test matrix still records environment-dependent skips |
| Runner, adapters, persistence | Shared `Core`, ToolRunner, SQLite store, 24 packaged catalog entries, registered parsers and session integrations | Reconcile catalog/adapter/provider/readiness distinctions and each advertised support combination |
| Existing correctness fixes | CLI `run` drains its own follow-ups while preserving older pending jobs; Nikto current-format parser; worker leases and session/pivot identity guards | Do not reopen fixed bugs from historical notes; audit other entry points and boundary races |
| Trust Layer | Request-context replay, deterministic validation, observation/blind checks, retest, reproduction helpers, coverage persistence/reporting | Prove evidence completeness, conservative outcomes, meaningful coverage and report reproducibility end to end |
| Supplied UI | 22 production templates/routes; 23 UI-v2 test modules; web root redirects to `/ui-v2` | All-control inventory, visual fidelity, accessibility, service parity, external assets and desktop entry-point acceptance |
| Setup/readiness | Packaged manifest, doctor, profiles, approval-bound Python install, curated apt/Homebrew plans, operation/history APIs | Platform/upgrade/offline/partial-failure/restart acceptance; native Windows tool install remains manual |
| Engine v2 | Versioned DAG/approvals; persisted missions, plans, tasks and attempts; mission cost/rate/deadline limits, durable run-request queue, provider routing, lease fencing, cancellation/audit and guarded reconciliation; **E5 bounded engineering acceptance merged in PR #124** | Legacy direct CLI/web/AI/Metasploit migration, whole-portfolio/transport parity and production, real-target and independent audit-anchor acceptance remain OPEN |
| Headless | Waitress local service plus separate Gunicorn web and durable worker systemd units; paired Docker E5 staging with CI-backed startup/restart and offline-state snapshot/restore | Bounded staging engineering smoke passed; production host/TLS/secrets, independent audit anchoring, external-effect crash, real-target and disaster-recovery acceptance remain OPEN |
| Expansion | Bounty ingestion/policy primitives and detailed approved designs exist | Full bounty autonomy, multi-target, broad Metasploit/provider coverage, patch application and enterprise are not delivered merely because designed |

The old Route/session-host collection failure is **closed at this baseline**: `routes.py` carries `session_host`, the live resolver supplies peer identity, regression tests cover drift/missing identity and the exact-baseline matrix passes. The historical approvals-browser failure is not a current red-CI blocker either. Keep security acceptance open without pretending these earlier failures still occur.

### Resolved correctness dependency — one-shot initialization

**Fixed and retained as regression coverage.** Current `coverage_cmd.py`, `validate_cmd.py`, `retest_cmd.py`, `recon_cmd.py` and `run_cmd.py` explicitly call `Core.initialize(drain=False)`; `tests/test_cli_initialization_isolation.py`, `tests/test_initialize_drain.py` and `tests/test_run_cmd.py` cover unwanted historical draining and intended own-follow-up behavior. The `Core.initialize(drain=True)` path still intentionally drains when selected by a long-lived worker. Earlier sections/dated snapshots describing default draining by those five one-shot commands are historical, not a current P1 bug.

## 2. Critical path and active workstreams

| ID | Outcome | Status at baseline | Depends on | Acceptance / owner boundary |
|---|---|---|---|---|
| P0 | One trustworthy baseline and cleanup decisions | Partial; this review refreshes evidence and dispositions | Current main/CI | Full advertised-capability/control inventory remains open; docs/inventory integration owner |
| P1 | Correct execution, scope and Trust Layer semantics | Partial | Affected P0 boundary mapped; remaining inventory may continue | No unrelated startup dispatch; adversarial authorization/evidence checks; core/CLI/security owner |
| P2 | Shared durable lifecycle and compatibility seams | Partial | Stable P1 contracts | CLI/API/UI parity, bounded cancellation/recovery, no unsafe replay; core/service integration owner |
| P3 | Truthful first run and headless deployment | Partial | P2 lifecycle for affected operations | Clean supported environments, failure/recovery and resource/secret handling; setup/deployment owner |
| P4 | Supplied UI accepted against real services | Partial | P2 contracts; relevant P3 readiness | Every exposed control accounted for, zero redesign, visual/accessibility/parity evidence; page owner + one UI integrator |
| P5 | Solo end-to-end v1.0 and release | Open | P1–P4 integrated | All §38 gates; one release integrator |
| P6 | Programme policy and bounded autonomy | Deferred full subsystem; primitives present | P5 and policy/authorization gates | Isolated customer/bounty policies and audited in-envelope operations |
| P7 | Multi-target and competitive measurement | Deferred | P4 and P5 accepted | Per-target policy, bounded fan-out, seeded lab comparison |
| P8 | Selective platform/business expansion | Deferred | Accepted need and prerequisite contracts | Per-capability business case, unique value, license/support/test evidence |

**Implementation queue:** (1) finish the exhaustive execution-path, capability, and UI-control inventories; (2) migrate remaining legacy direct execution clients onto shared V2 services and close cross-client policy parity; (3) complete provider-effect recovery, evidence/report behavior, and all agreed engine/UI workflows; (4) finish supported installation, headless operation, and internal regression/security/browser coverage. Run internal checks continuously and fix issues before declaring implementation complete.

**Deferred qualification queue:** Only after all agreed V2 engine, V2 UI, and remaining solo-v1.0 implementation work is complete and internal checks pass, run controlled real-target validation, independent evidence/security review, manual accessibility review, production-like deployment, and rollback/restore exercises. These are post-implementation qualification gates. Earlier bounded test evidence remains historical and does not need to be repeated during feature implementation.

### P0 — Baseline and repository simplification

- Maintain the exact source/CI baseline and capability states: implemented, integrated, partial, planned, unverified, unsupported, blocked.
- Inventory every advertised tool/adapter/provider, CLI verb, API route, UI control, worker, transport and deployment mode; record source, authorization, persistence, tests and limitations. This review maps principal paths; it does not close an exhaustive security or per-control audit.
- Execute only independently reviewable cleanup batches from the [disposition register](docs/PROJECT_GOVERNANCE_MASTER.md). Preserve Git history; no history rewrite or automatic branch deletion.
- Keep one maintained tool-catalog seed after migrating root-catalog consumers. Research inventories must not masquerade as runtime support.
- Retire historical implementation plans as active instructions. Keep unique rationale/evidence where necessary, with corrected links. Do not create another competing roadmap or a new archive full of duplicate files.
- Recheck `main` and exact branch tips before any later deletion. An ancestry-contained branch can be retired after reference checks; a diverged/squashed branch needs content/PR reconciliation.

**Exit:** one current baseline, disposition/retirement list, complete capability inventory, dependency map, work ownership and acceptance plan. This review does not mark the entire P0 exit accepted.

### P1 — Existing execution correctness and Trust Layer

- Preserve and extend the already-tested one-shot `initialize(drain=False)` isolation and `run` own-follow-up handling. Any new CLI entry point must demonstrate that it does not dispatch unrelated queued jobs.
- Verify fail-closed scope for original/redirected/resolved/replayed/follow-up/pivot/session targets, and recheck immediately before consequential dispatch. Cover ownership races, closed/drifted sessions, cancellation and descendants. Document external-tool DNS/secondary-request and egress limitations.
- Enforce approved action identity, permissions, scope, expiry and impact independently of AI/UI. Host/programme authorization and external RPC/TLS transport checks must not weaken during refactoring.
- Retain deterministic request-context replay for supported methods/headers/bodies and authenticated contexts without leaking secrets. Current security guards refuse POST and other state-changing replay until a separately authorized safe-replay contract exists; request-context storage is not proof that every method is replayable. Validate SQL/error markers, reflected XSS, blind timing, observation probes, malformed inputs and changed scope; state timing limitations.
- Retest only eligible previously verified findings; keep `fixed`, `still_vulnerable`, `inconclusive` and reasons distinct. Network failure or changed evidence alone is not proof of a fix. This is narrower than the future remediation lifecycle.
- Preserve raw request/response or timing/baseline evidence, target identity, artifact/reproduction provenance and state transitions. AI may triage/summarize only; human review does not turn ambiguity into deterministic proof.
- Coverage discloses skipped, failed, unrequested, inaccessible and unsupported work from persisted records. A heuristic confidence number must not imply measured recall, endpoint completeness or certainty.
- Prove audit/evidence behavior on success, refusal, cancellation, timeout, interruption, recovery and audit-write failure. Document remaining integrity/trust-anchor limits.

**Exit:** controlled workflows do not silently dispatch unrelated work, bypass authorization, fabricate success/verification or omit material coverage/evidence gaps.

### P2 — Shared services and Engine v2 migration

- Use one versioned domain/service boundary for missions, plans, tasks/attempts, approvals, progress, findings, evidence, coverage, verification, reports and errors; CLI/API/web/headless are clients.
- Preserve existing ToolRunner, parsers, store compatibility and safe transport behavior behind façades. The worker/Automator/sequential AI executor are still live; remove them only after caller and persisted-state migration, parity, no-bypass and rollback evidence.
- Preserve existing mission-wide rate, cost, deadline and concurrency controls and durable plan cancellation/stop intent, already represented in `workflow_cmd.py`, `Core`, storage and the V2 HTTP API. Verify unaccepted resource-accounting, provider-effect recovery and multi-client cases against exact requirements; never describe the entire category as absent or replay uncertain effects.
- Retain tested atomic claims, worker leases, conservative crash/restart reconciliation, durable progress and audit/outbox behavior in the bounded E5 V2 service. Complete still-open production chaos, independent audit/witness, real-provider external effects, legacy execution migration and operator recovery cases. Do not promise exactly-once external side effects.
- Replace fixed Automator branches with evidence/capability-driven follow-ups only after equivalent behavior is tested. Feed AI proposals through the same plan/policy/approval services. Use a versioned structured proposal contract that cites persisted source records, distinguishes observation from inference, states uncertainty and requests a typed action; reject and audit malformed, stale or out-of-scope proposals. Provider/model routing may consider task capability, complexity and configured resource policy, but never grants permission or bypasses approval. No second scheduler or execution authority.
- Define common versioned provenance, capability-report and onboarding/readiness-state models for existing-portfolio reconciliation before adding candidate automation. Reconcile catalog-only, adapter-only, import-only and session integrations; use bounded read-only discovery/extraction and deterministic gap/compatibility analysis in P0/P2, rather than deferring migration prerequisites to P8. Manifests describe actual target/protocol/platform/auth/input/output, dependency, impact/permission, timeout/cancellation, readiness, parser/evidence and reconciliation support. Registration never authorizes execution.
- The initial provider bridge is constrained to an allowlist and catalog defaults, with no dynamic task inputs; its manifest readiness is `registered`. Do not advertise all providers as generally safe or fully verified.

**Exit:** a supported job can be created, authorized, observed, cancelled and recovered through shared services independently of a browser, with audit and coverage intact.

### P3 — Setup, readiness and headless deployment

- Maintain the schema-validated dependency manifest and deterministic environment/readiness evaluator. Missing optional dependencies degrade only dependent capabilities. Distinguish presence, version verification, functional smoke-test evidence and actual runtime readiness.
- Keep Core/Standard/Full/Custom preview read-only. Use exact-plan approvals and separate system/elevation consent for curated OS tools. No commands copied from AI/tool output, silent elevation or arbitrary installer execution.
- Verify clean and partial installs, optional extras, wheel/sdist resources, venv/no-admin behavior, upgrade, offline/manual fallback, PATH conflicts, missing assets, wrong versions, partial changes, cancellation, interruption, restart and audit failures. Disclose that completed package changes are not generally rolled back.
- Curated apt support is restricted to recognized Debian/Ubuntu/Kali combinations; Homebrew is the supported curated macOS path. Treat native Windows and WSL as distinct environments with separate support/test records. Native Windows package-manager installation stays manual until separately implemented/accepted. Setup-preview smoke is not full platform acceptance.
- Make first-run, doctor, administration, job/campaign/status and approval workflows usable without desktop/TUI/browser. Test foreground first, then advertised daemon/systemd/Docker modes, health/readiness, secrets/auth/TLS/reverse proxy, restricted permissions, persistent volumes, resource limits and backup/restore.
- Consolidate installation/readiness operations onto the durable lifecycle rather than assuming operation files/process-local workers guarantee every restart/multi-process case.

**Exit:** a clean supported host installs a truthful profile, runs headlessly and retains/reconciles supported jobs/approvals/evidence across disconnects and restarts; unsupported combinations are explicit.

### P4 — Supplied UI integration and acceptance

- Use the 22 current production routes/templates and named supplied designs. The baseline package contained 32 HTML and 32 PNG files. Cleanup removes five exact loose copies of each type, leaving 27 HTML and 27 PNG named inputs including distinct alternatives; counts are not accepted product workflows.
- Complete one page/workflow at a time against real service contracts. Every visible control must be recorded as real, hidden or disabled with its endpoint, permission, loading/empty/error/progress/cancel/reconnect behavior and test. A passing route is not acceptance of all its controls.
- In the supplied Run & Orchestration and AI Gate workflows, present only state persisted by shared services: plan/task/attempt status and dependencies where available, ready or blocked work and its recorded reason, approval/recovery holds, and AI proposal rationale linked to its cited source records. Keep suggestions distinct from tool observations, validated findings and completed work. Do not infer state from agent prose or add a second graph/store; preserve the supplied designs and map every exposed control to an accepted service contract.
- Account for dashboard, scope, run, findings, report, reports, history, diagnostics, evidence, AI, retest, chains, adapters, settings, audit, monitoring, BAS, bounty, compliance, PTaaS, threat intelligence and approvals. Pages may present supported subsets; future capabilities stay inaccessible.
- Run visual regression against approved supplied references on supported desktop targets, keyboard/focus/non-color/screen-reader acceptance, and CLI/API/UI service parity or documented deliberate differences.
- Resolve external Tailwind/font/icon/image dependencies and verify the supported deployment/offline policy without altering the supplied design. Current CDN-dependent pages do not prove air-gap readiness.
- Keep the **already corrected** desktop `embed.URL` pointing to `/ui-v2` (`src/whaxon/interfaces/gui/embed.py`) and preserve regression tests; complete independent desktop deployment/visual acceptance. Preserve old UI templates/CSS/JS/screenshots and the legacy audit unchanged; reference-only retirement and public route deprecation need compatibility evidence.
- Distinct `_forensics_hardened` and `_v0.11.16` source variants require a canonical mapping/difference review. Do not delete them because their names look old. Exact loose duplicates are a different disposition.

**Exit:** every exposed page/control has real authorized behavior; unsupported features remain inaccessible; design, accessibility, parity and deployment acceptance pass on the candidate.

### P5 — Solo v1.0 proof and release

One operator must complete an authorized controlled-lab chain: scope/recon → enumeration → discovery → supported initial access where in scope → independent validation → findings/evidence → honest coverage/report → remediation retest. Declare which stages/targets/transports were exercised and which were not. Demonstrate reproducibility and false-positive handling against known ground truth; never generalize a clean lab result to all targets.

Use existing hydra/session/validator/report/retest primitives where supported; a fixed six-new-tool list is not an unconditional release gate. Add a provider only when a measured gap blocks the agreed proof. Business-logic/browser inference and AI-system testing are conditional workstreams, not assumed existing capabilities; explicitly scope/defer them when the proof target has no such surface.

Close all §38 gates. Capture current reports, inspect HTML/PDF/Markdown/JSON behavior and evidence/redaction differences, then refresh state/operator docs and version/tag/build/publication evidence. Launch activity and commercial claims follow acceptance. Deferred team/enterprise/bounty/platform breadth is not a hidden v1.0 prerequisite.

## 3. Expansion after the solo foundation

### P6 — Programme policy, bounty and bounded campaigns

Retain the detailed [bounty design](docs/bounty-addon.md) and original §§26, 45–46 as requirement sources, subordinate to this order:

1. Source-backed programme ingestion and policy versioning, uncertainty, review/activation, dual programme+host gates, staleness/change suspension and audit. Import or URL availability never authorizes testing.
2. Controlled-lab plan/execution with separate customer/bounty policy/state, exact permission envelope, expiry, rate/concurrency/request/cost limits and emergency stop.
3. Provenance-preserving asset graph and monitoring; proposals never expand scope automatically.
4. Independent verification, evidence vault/reproduction, correlation and attack-path analysis.
5. Programme knowledge, measured prioritization and differential sessions/invariant/workflow inference. Managed-browser capture and identities use explicit authorization and deterministic boundaries.
6. Platform-specific report drafts, redaction, integrations and isolated multi-programme orchestration. Disclosure/submission requires separate explicit approval.

Manual/guided/supervised/autonomous modes share one controller. Routine activated in-envelope actions need no repetitive confirmation; scope ambiguity/expansion, increased limits, intrusive/destructive tests, sensitive-data access, identities/accounts, third-party testing, disclosure and paid actions pause for approval. Defend ingestion against prompt injection, SSRF, unsafe redirects/DNS, size/time/content limits and untrusted downloads. Do not assume third-party API/terms access.

### P7 — Multi-target, subnets and measurement

After P4/P5 acceptance, support domain/IP/URL/CIDR/mixed inputs with canonical assets, explicit authorization/provenance and exclusions; no discovery-driven scope expansion. Bound fan-out/per-target budgets and concurrency, isolate failures, preserve cancellation/recovery, deduplicate without losing per-asset evidence, and report partial/non-tested outcomes. Network discovery and transport/pivot behavior require separate accepted lab coverage.

Build a sourced competitor capability matrix and reproducible seeded-lab benchmark: ground truth, false positives/negatives, coverage, time/resource/cost, evidence quality, installability, usability and retest outcomes. Retain version/date/environment and uncertainty. Feature counts and vendor claims are not superiority evidence. Keep this work after the supplied UI/solo gate.

### P8 — Selective tools, Metasploit, remediation and business platform

| Direction | Retained scope and admission rule |
|---|---|
| Tool intelligence/onboarding | [Detailed design](docs/APPLICATION_ARCHITECTURE_MASTER.md): source-backed capability/gap/risk report, bounded read-only introspection, overlap/license/maintenance/platform assessment, proposed→researched→assessed→approved→integrated→validated→enabled/deprecated lifecycle; no auto-install/enable/plugin execution; monitoring reports deltas only |
| Tool portfolio | Evaluate unique capability and measurable value; reconcile catalog/adapters/providers before adding breadth. Keep CLI-native tools native; adopt structured harness/verification/discovery methodology on touch; GUI/Burp control is a separate integration. No 120-tool quota or old hour estimates |
| Recon/API/cloud/code | Preserve provenance/scope for recon; design authenticated API/OpenAPI contracts and typed cloud-SDK/account/region/IAM scope; distinguish source/SARIF, container/dependency/SBOM, Kubernetes and secrets inputs. Prefer supported unique providers over overlapping frameworks; maintenance substitutions require current evidence |
| Metasploit/Armitage | [Detailed design](docs/APPLICATION_ARCHITECTURE_MASTER.md): full module metadata/search/options/payload/compatibility/job/session/route/pivot coverage and collaborative-workbench patterns inside the supplied UI, through the same Engine v2 services; individual operations require scope, impact/privilege, approval, timeout, cleanup and lab acceptance. Existing RPC support is not full integration |
| Remediation | [Approved detailed addendum](./WHAXON%20ROAD%20MAP%20-%20WHATS%20NEXT%20-%20FULL%20SCOPE.md): native/imported finding normalization → root cause/context → reviewable patch → isolated validation → separately authorized application → rollback/recovery → original-check retest and before/after evidence. Current `core/remediation.py` is dependency remediation planning, not this vulnerability patch engine |
| AI/business-logic/AIRT | Provider-neutral proposal interface; budgets/backoff/resume/escalation/dry-run and confidential-data policy; differential sessions, workflow/invariant checks and AI-surface adapters only with evidence and demand. No fixed free-tier/pricing/privacy assumptions from historical notes |
| Small teams/MCP | Shared workspaces, delegated roles/approvals, graph, retrieval and separate multi-agent roles after stable services and demonstrated demand. MCP metadata never grants permission; no mandatory new runtime dependency |
| Company/platform | Tenant/RBAC/SSO isolation, engagement lifecycle, collaboration, HA/observability, deployment/secrets/upgrade, billing/support only after validated customer need; preserve actor/tenant seams without pretending enterprise exists |
| Business capabilities | PTaaS, broader remediation lifecycle, ASM, report versioning/templates/redaction, compliance mapping, threat intelligence, training, CSPM/CIEM, SIEM/ticketing/CI/CD/webhooks/SDK, internationalization, offline bundles and responsive/PWA client remain deferred. BAS/AEV needs its own bounded scope and evidence. Mobile client support does not mean mobile application pentesting |
| Research | Fact-Intent Graph, hints/RAG/governed replanning, app-to-backend chains and full proof-driven remediation are post-foundation hypotheses. KILN, Aletheia, SYBIL and other portfolio projects are separate products, not WHAXON dependencies or release tasks |

Each addition needs source/license/version/platform, overlap/replacement, permissions/impact, parser/evidence, install/readiness, timeout/cancellation/recovery and test/rollback decisions. Discovery/research is not approval to install or execute. Credential access, poisoning, C2 and post-exploitation are separate high-impact capability classes, never ordinary unattended scanners.

## 4. Exclusions and retirement boundaries

The repository name does not expand scope into forensic tooling. Preserve original exclusions: wireless/SDR/hardware, digital forensics, reverse engineering, malware analysis, social engineering, mobile-app pentesting, honeypots, unsupported commercial scanners without CLI parity, and unstructured protocol-attack tooling. No unapproved/non-consenting activity, automatic scope expansion or bypass of the deterministic executor. Retain existing explicitly approved session/transport scope; this list is not permission to broaden it.

Safe removal is distinct from product retirement. The [disposition register](docs/PROJECT_GOVERNANCE_MASTER.md) identifies exact duplicate/no-consumer candidates, dependency-bound removals, retained evidence/design/legal resources and migration gates. Cleanup removes only verified loose copies and superseded non-runtime artifacts; named design originals, runtime code, evidence and branch refs remain intact.

## 38. Solo v1.0 release acceptance — OPEN

This section retains the established release-gate number so references to §38 remain meaningful. Every item requires exact-candidate evidence; prior implementation markers or green CI alone do not close it.

| Gate | Required evidence | Baseline state |
|---|---|---|

> **G10 implementation checkpoint (2026-11-06):** The [release decision record](docs/ENGINE_V2_G10_RELEASE_DECISION.md) remains **HOLD — NOT READY TO DEPLOY** because agreed V2 implementation and integration work is incomplete. External qualification is intentionally deferred until the V2 engine, V2 UI, and remaining solo-v1.0 implementation scope are complete and internal checks pass.


| G01 Capability/workflow crosswalk | All advertised CLI/API/UI/tool/transport/deployment surfaces, source/tests, supported limits and complete controlled-lab chain | Bounded V2 crosswalk/lab acceptance is recorded at exact head `90e099f` / CI #2194 (14/14). Current main additionally contains `docs/ENGINE_V2_G01_CLI_MODE_INVENTORY.csv` and its AST guard; exhaustive V1 caller inventory and real authorized-target evidence remain OPEN |
| G02 Authorization/execution | No unrelated initialization dispatch; fail-closed target/scope/auth/approval, session/pivot/DNS/redirect/follow-up boundaries, ownership races and cancellation/descendants | Bounded V2 authorization/execution acceptance is recorded at `7c166e7`; exact head `ca8d98a` / CI #2204 passed 14/14, including `/api/run` bypass and redirect authorization regressions; remaining G03–G10/release gates OPEN |
| G03 Independent validation/retest | Supported replay/SQL/XSS/timing/observation paths; candidate/inconclusive never promoted by AI/UI; eligible retest and conservative outcomes with reasons | Bounded acceptance is recorded at PR #137 merge `fd8e2db`; exact head `c98b99d` / CI #2214 passed 14/14; unsupported methods/kinds stay candidate, timing alone is not proof, and missing replay does not prove a fix |
| G04 Evidence, coverage and reports | Reproducible raw proof/provenance, honest skipped/failed/unrequested disclosures, redaction/format review, timestamped audit IDs/digests, export/integrity verification, explicit trust anchor/limits and audit failure/crash/recovery behavior | Bounded report/coverage acceptance is recorded at PR #138. PR #142 established the client-facing engagement HTML/PDF baseline; PR #144 then expanded the engagement and per-job reports at `edb427b` / exact head `28543e3`; CI run `42249696631` passed 20/20. Markdown, HTML and PDF regression coverage includes evidence, remediation, coverage, provenance, empty states and escaping. Unsigned digests, external audit anchoring, production custody and broader recovery remain OPEN |
| G05 Shared durable lifecycle | CLI/API/web/headless service parity; persisted jobs/approvals/progress; budgets, cancellation, restart/reconciliation and no unsafe replay | Bounded acceptance is recorded at exact head `53d3535` / CI #2227 passed 14/14; shared CLI/API persistence, approvals, budgets, cancellation, reconciliation and uncertain-attempt no-replay covered; legacy migration, provider-effect and production recovery remain OPEN |
| G06 Supplied UI | Complete all agreed UI workflows and wire visible controls to real V2 services; keep unsupported actions truthful and inaccessible | Implementation remains in progress. The 22 routes and browser suites are present, but per-control behavior and integration are not complete. Continue implementation and internal browser/API checks. Defer external visual approval, manual accessibility/security review, and deployment/rollback qualification until the entire agreed V2 implementation is complete |
| G07 Installation/deployment | Clean wheel/sdist/core/extras install and upgrade; catalog/payload resources; safe doctor/setup; supported platform/service modes, offline/partial failure, secrets, backup/restore and restart tests | Bounded setup/staging acceptance is recorded at exact head `53d3535` / CI #2227 passed 14/14, including approved installer behavior, platform setup and staging/restart/offline-restore lanes. PR #141 added the initial same-version upgrade preservation smoke (`d8ed413`, head `8132269`, CI #2266 passed 14/14). PR #143 expanded this to 0.11.14 → candidate 0.11.16 and same-version 0.11.16 reinstall on Python 3.11–3.13; exact head `b54957a` / CI #2283 (`42232819920`) passed 22/22, merge `78470c8`. It preserves catalog, scope, legacy jobs and V2 mission storage. Snapshot restore now detects mutation during copy; injected snapshot/restore interruptions leave no partial destination. Broader release-history compatibility, package-install rollback, production security and whole-system disaster recovery remain OPEN |
| G08 Candidate CI | Required Python 3.11–3.13 tests/static/build, browser and supported-platform checks green on exact release candidate; skips/limitations recorded | Bounded acceptance is recorded at PR #139 / exact head `35cf928` / CI #2239 (14/14). Current `main` exact-head CI run `42253317306` also passed; no V2 release-candidate identity exists |
| G09 Release identity | Matching intended version/tag/commit, successful release workflow and verified expected index publication | Release-safety acceptance is bounded at PR #140 / CI #2249 (14/14). No V2 release tag, publication or GitHub Release exists; full G09 remains OPEN |
| G10 Documentation and decision | Keep implementation state, capability/control/UI records, known limits, candidate evidence, and final release decision accurate | **HOLD / NOT READY TO DEPLOY** while agreed implementation remains incomplete. Once implementation and internal checks are complete, perform deferred external qualification, establish V2 release identity/publication, then record the final go/no-go decision. No unverified “operator direction” is assumed |

Any unmet correctness, safety, user-visible workflow, report-honesty or installability requirement blocks a readiness claim. Deferred expansion does not. Change release scope explicitly with rationale and evidence; never hide a blocker by changing a status label. After acceptance: controlled dogfooding and reproducible report examples, then launch material and publication. Patch/minor versions reflect actual change scope; bumping to 1.0 is a release decision, not a document revision.

## 49. Engine architecture authority and specification boundaries

Keep [Engine v2 architecture/crosswalk](docs/ENGINE_V2_MASTER.md) as the detailed architecture source, subordinate to this trajectory. E0 inventory is historical; E1 guards, E2 contracts, E3 scheduler primitives and initial E4 providers exist. E1 acceptance, durable mission-wide guarantees, broad E4 reconciliation, E5 shared lifecycle and E6 product/UI acceptance remain open. E7 autonomy, E8 multi-target and E9 expansion follow P6–P8.

Required contracts remain Mission/AuthorizationContext/Plan/Task/TaskAttempt/CapabilityManifest/ProviderRegistration/PolicyDecision/Approval/BudgetLedger/ExecutionContext/Observation/Finding/VerificationRun/EvidenceArtifact/AuditEvent/ReadinessSnapshot, delivered only where implemented and tested. Local process, session, API, browser, cloud SDK and local analysis are separate execution kinds—not automatically supported transports. No manifest, AI agent, plugin or browser becomes a second authority.

## 50. Previous-roadmap reconciliation and retained scope

The complete pre-rewrite text is retained in [Git at the inspected baseline](https://github.com/andreipath26/WHAXON-AI-Forensics/blob/6fa1fa5f9bcff9b7afffb87ca908b0f78562fa3b/WHAXON%20ROAD%20MAP%20-%20WHATS%20NEXT%20-%20FULL%20SCOPE.md). No duplicate 296 KB archive is added to the working tree. Its detailed requirements remain reference material where not superseded below; its priorities, estimates, current-state assertions and implementation instructions are superseded by this file. Detailed future scope is retained without enabling it or turning it into a v1.0 prerequisite.

| Previous section(s) | Disposition and destination |
|---|---|
| Foundations, §0, engineering rule | Consolidated into §0 and P0–P8; five principles and dependency-driven work retained |
| §§1–4 | Completed phase/migration/small-fix history → baseline/changelog; no rebuild queue |
| §§5–6, 10 | Revalidate medium/large/AI gaps against source; correctness/durable bounds → P1/P2, broader AI/objectives/streaming → P8 |
| §§7, 39 | Tool candidates/substitutions and harness requirements → P2 portfolio reconciliation/P8 admission; quotas, old totals and fixed estimates retired |
| §§8–9 | Cloud and platform scope → P3 supported-platform acceptance/P8 typed expansion; old Kali-only assumptions superseded |
| §§11–12 | Obsolete time/version schedules retired; evidence-based gates replace session forecasts |
| §§13–16 | Exclusions/invariants → §0/§4; companion index → docs index; MCP/competitor/vendor references are research, not dependencies or facts to repeat without rechecking |
| §§17–18 | Solo validation → P1; team/MCP/enterprise → P8. Old “solo complete” and MCP-first priorities superseded |
| §19 | Supplied UI integration → P4. Old redesign alternatives/effort proposals retired; legacy designs preserved |
| §20 and remediation addendum | Narrow existing retest/report correctness → P1/P5; full business/remediation platform → P8; old PTaaS-urgent priority retired |
| §§21–22, 25 | Report fixes/session diaries/PR plans → historical Git/changelog; current report acceptance → P1/P5/G04 |
| §§23–24 | Adversarial evidence/scope/prompt-injection concerns → P1/P2/P6; speculative triage/research → P8, not new implemented capabilities |
| §26 | Programme policy/ingestion/browser/differential analysis/reporting → P6 and detailed bounty design; partial primitives remain implemented, full subsystem deferred |
| §§27–31 | No numbered sections existed in the baseline; no scope inferred |
| §32 | Solo chain → P5; validation/coverage/retest → P1; business logic/browser/AIRT conditional/deferred → P6/P8. Three-tab/UI restructure and fixed six-tool quota superseded by supplied-design/no-expansion gates |
| §33 | Trust Layer → P1; reproduction/evidence/coverage → G03/G04; local/privacy constraints → P3/P8. No simplistic response-change=fixed or universal confidence claim |
| §34 | Solo foundation/launch/versioning → P5/§38; stale remaining-session estimates and earlier sequencing retired |
| §35 | Portfolio R&D remains separate/post-foundation; do not restore excluded adversary archive or add portfolio products as WHAXON modules |
| §36 | Existing passive recon → baseline/P5; bounded enrichment and new data providers → P8 |
| §37 | Graph/hints/governance/A2B/full remediation hypotheses → P8 |
| §38 | Preserved and consolidated as G01–G10 above |
| §§40–41, 47 | Dependency manifest/doctor/setup/readiness/four existing UI states → P3/P4; old provisional module layouts and branch-only status snapshots superseded by actual source |
| §§42–44 | Multi-target and measured competition → P7; existing UI and solo release prerequisite retained |
| §§45–46 | Bounty phases/campaign autonomy/transport and evidence requirements → P6; older unconditional approval or no-autonomy statements superseded by exact activated envelope |
| §48 | Full capability inventory → P0/G01; shared headless/deployment/transport acceptance → P2/P3/§38 |
| §§49–50 | Engine specification → §49/P2; E0 findings are historical and must not reopen already-fixed defects |
| §51 | Full Metasploit/Armitage integration → P8 and its detailed design; current RPC/session primitives retained |
| §52 | Existing-portfolio audit, provenance/report/readiness contracts and bounded discovery/gap analysis → P0/P2; broader candidate onboarding/upstream monitoring → P8 and its detailed design. No competing manifest/scheduler or automatic upstream changes |

When a historical requirement is ambiguous or conflicts with a later approved decision, record a decision at the affected gate before implementation. Do not silently drop scope, treat historical prose as current evidence, or restart obsolete plans.


---

## Part II — Competitor capability and remediation research (subordinate)

# WHAXON Competitor Capability and Vulnerability Remediation Roadmap Addendum

**Status:** QUEUED — approved product direction; not yet implemented.
**Applies to:** `andreipath26/WHAXON-AI-Forensics`.
**Relationship to the master roadmap:** This addendum expands the remediation lifecycle already described in §20.2 of `WHAXON ROAD MAP - WHATS NEXT - FULL SCOPE.md`. Read it alongside the master roadmap; it does not replace the roadmap, change release gates, or mark any capability DONE.
**Execution constraint:** Respect the master roadmap's UI-first execution gate. Complete and verify the agreed existing UI work before beginning this larger capability implementation. Preserve the approved UI assets/design; do not redesign the UI as part of remediation work.

## 1. Product objective

Make remediation a core WHAXON capability, not merely a report containing generic advice. For vulnerabilities WHAXON discovers—and, by design, supported findings imported from other scanners—WHAXON should be able to:

1. Explain the finding, likely root cause, evidence, affected asset/component, and security/business impact.
2. Recommend a mitigation or corrective action appropriate to the finding and its context.
3. Generate a concrete, reviewable patch whenever sufficient evidence, source/configuration context, and a defensible fix are available.
4. Test the proposed patch in an isolated or otherwise controlled environment.
5. Offer a user-controlled path to apply an approved patch through an authorized workflow.
6. Retest the original finding and record whether the vulnerability is fixed, partially fixed, unresolved, or not verifiable.
7. Preserve a traceable before/after evidence record and an auditable history of proposed, approved, applied, rolled-back, and verified changes.

The goal is broad coverage across vulnerability types and remediation surfaces. This is a product objective, **not a claim that every vulnerability can always be fixed automatically**. If context is missing, a fix is ambiguous, or a patch cannot be validated with sufficient confidence, WHAXON must state the limitation and provide the safest useful next step rather than fabricate certainty.

## 2. Scope: broad vulnerability and remediation coverage

Design the remediation engine to support these classes and allow future categories to be added through adapters/strategies rather than hard-coded into one narrow patcher:

- Injection vulnerabilities, XSS, unsafe parsing, insecure input handling, and output encoding.
- Authentication, authorization, access-control, session-management, and identity flaws.
- Vulnerable or unsupported dependencies, including compatible upgrades, replacement options, and lockfile changes.
- TLS, HTTP security headers, insecure service settings, and application/server configuration.
- Exposed credentials and secrets, including safe removal/rotation guidance and prevention of recurrence. A patch alone cannot invalidate a leaked credential; rotation/revocation must be represented separately.
- Insecure file permissions and operating-system/service configuration.
- Container images, Dockerfiles, Kubernetes manifests, deployment definitions, and infrastructure-as-code.
- Cloud policies, identities, network exposure, and resource configuration.
- Business-logic vulnerabilities requiring domain-specific context and regression tests.
- Vulnerabilities reported by external tools where a safe fix can be derived from normalized finding data and additional repository/asset context.
- Novel, complex, or poorly understood findings where automated patching is not yet reliable; provide structured investigation, compensating controls, and manual remediation guidance.

Remediation targets can include source code, dependencies, application/server configuration, operating-system/service configuration, containers, Kubernetes, infrastructure-as-code, and cloud configuration/resources. Actual application to a live target must depend on explicit authorization, supported integrations, and the risk policy; a finding's presence never grants permission to modify a system.

## 3. Finding intake and context normalization

Create a normalized remediation request that can originate from:
- WHAXON-native findings; and
- imported findings from other scanners or security tools.

Retain source/provenance and original identifiers. Normalize severity, confidence, affected asset/component, location, evidence, reproduction/validation status, references, and remediation context without discarding tool-specific data. Correlate duplicates while preserving links to every source.

Before patch generation, determine whether the finding has enough actionable context. Retrieve source/configuration/dependency context only from authorized workspaces and connections. Do not infer missing source code, business rules, cloud permissions, or deployment details. Imported findings with insufficient evidence should be enriched or returned for clarification before a patch is proposed.

## 4. End-to-end remediation lifecycle

### Stage A — Triage and root-cause analysis
- Review finding evidence and validation status; distinguish confirmed, probable, unverified, and informational findings.
- Identify the likely root cause, affected component, attack path, and impact.
- Explain uncertainty and identify missing context.
- Recommend the appropriate remediation strategy, including a compensating mitigation when a permanent fix is not immediately feasible.

### Stage B — Patch generation
- Generate a concrete diff or equivalent reviewable change when justified by available context.
- Explain the root cause, why each material change is needed, expected security benefit, compatibility/performance implications, and residual risk.
- Include relevant tests or test changes, migration notes, dependency constraints, and operational steps.
- Keep the patch minimal and scoped; avoid unrelated refactoring.
- Never treat hiding a finding, disabling a feature, suppressing a scanner rule, or weakening a control as a successful fix.
- If no defensible patch can be generated, say why and give actionable manual steps or a mitigation plan.

### Stage C — Pre-application validation
Use an isolated worktree, sandbox, test environment, or equivalent controlled mechanism appropriate to the target. Where relevant, run:
- syntax/build checks and static analysis;
- unit and integration tests;
- regression tests for the affected functionality;
- security-specific tests and negative/bypass cases;
- dependency, configuration, container, or infrastructure validation;
- the original finding's reproduction/validation procedure.

Record commands/checks actually run, their environment, exit status, output/evidence, and checks not run. Never claim a test passed when it was skipped, unavailable, or not executed. A successful build alone does not prove the vulnerability is fixed.

### Stage D — User-controlled application
Support these workflow modes:
1. **Advisory:** explain the fix and provide a patch artifact; the user applies it.
2. **Approval-based (recommended default):** generate, test, and present the patch; apply only after explicit approval.
3. **Explicitly authorized bounded automation:** permit automatic application only within user-defined target, scope, and risk constraints, with audit trail and rollback/recovery planning.

Keep patch generation and patch application as separate permissions. Never silently change production or other live systems. Require explicit approval for high-impact, destructive, externally visible, credential/identity, cloud-permission, or production changes. Respect least privilege and authorization boundaries. Provide dry-run/review mode, diff preview, backup/snapshot where appropriate, and rollback guidance or mechanism where feasible. If rollback is not feasible, disclose this before application.

### Stage E — Post-application verification and evidence
- Re-run the relevant original validation/reproduction check and regression tests.
- Classify the outcome as **fixed**, **partially fixed**, **unresolved**, or **unable to verify**, with a reason and supporting evidence.
- Check that the finding was not merely suppressed and that the fix did not introduce obvious regressions or an alternate bypass.
- Preserve before/after evidence, patch/diff, test results, timestamps, target identity, approval and actor, application outcome, and rollback details.
- Link the remediation record to the original finding and subsequent retest history/report.

## 5. Confidence, safety, and trust requirements

These are non-negotiable design requirements:

- **Do not conflate patch creation with a verified fix.** Report patch status, application status, and verification status separately.
- **No fabricated certainty.** Label assumptions, missing context, unsupported checks, and uncertainty.
- **No live modification by default.** Testing a target and changing it are separate actions requiring separate authorization.
- **Least privilege and scope enforcement.** Imported findings or AI-generated plans cannot expand the authorized target/scope or bypass WHAXON scope checks.
- **Preserve functionality.** Evaluate regressions, compatibility, performance, and security side effects; do not "fix" a finding by breaking intended behavior.
- **Secrets safety.** Never echo secret values into reports or patch descriptions unnecessarily. Credential rotation/revocation is a distinct operation and needs authorization.
- **Auditable provenance.** Store the origin of the finding, evidence used, patch generation method/version, reviewer/approval, checks performed, and final outcome.
- **Safe failure.** If scope, target identity, patch context, or authorization cannot be confirmed, stop before application and explain what is needed.
- **Rollback and recovery.** Plan for reversal where feasible; disclose when recovery is not straightforward.
- **No unverified blanket support claims.** Coverage grows by vulnerability/target adapters with acceptance tests; unsupported cases remain visible as unsupported or manual.

## 6. Architecture direction

Implement remediation as a modular lifecycle/orchestration layer rather than embedding patching logic into one scanner or UI page.

Expected conceptual components (names are provisional):
- Finding normalizer/provenance layer for WHAXON and imported findings.
- Root-cause/context resolver with explicit evidence and confidence.
- Remediation strategy registry/adapters keyed by vulnerability class and target type.
- Patch generator that emits a diff plus structured rationale and assumptions.
- Isolated validation runner with bounded commands, resource/time limits, and recorded results.
- Approval/policy gate separating generation, validation, and application.
- Target-specific application adapters with least-privilege credentials and dry-run support.
- Retest/evidence recorder connected to the existing finding and retest lifecycle.
- Audit/event history and report/API/UI surfaces.
- Extensible capability matrix documenting what each adapter can generate, apply, and verify.

Reuse existing finding, request-context, validation, retest, reporting, scope enforcement, and evidence mechanisms where appropriate. Inspect actual code and contracts before deciding implementation details; do not duplicate existing functionality or assume an interface is complete just because its module exists.

## 7. UI and user workflow

After the UI-first gate is satisfied, integrate remediation into the approved existing UI without redesigning it. The user should be able to:
- inspect the original finding and evidence;
- view the proposed remediation and a readable patch diff;
- understand impact, confidence, assumptions, risk, and tests;
- select advisory, approval-based, or explicitly authorized bounded automation where supported;
- approve/reject a patch and see what permissions are required;
- inspect application/test progress and logs;
- review before/after evidence and verification outcome;
- retry, roll back, or follow manual recovery instructions where supported.

Controls must be wired to real backend behavior and safe authorization checks. Hide or disable unsupported actions; never present mock buttons or imply that an action succeeded before the backend confirms it.

## 8. Delivery sequence and dependencies

1. **Respect the current UI-first gate:** finish and verify the already-approved UI work before implementation of the broader remediation engine. Do not use this roadmap item as permission to redesign the UI.
2. **Inventory existing lifecycle primitives:** inspect finding schemas, validation/retest, report/evidence, scope/authorization, storage, and API contracts. Record what can be reused and gaps with file/test evidence.
3. **Define normalized remediation and audit contracts:** include source provenance, target identity, permissions, confidence, patch artifact, validation results, approvals, and outcome states.
4. **Build read-only/advisory remediation first:** guidance, context checks, structured patch proposal, diff output, and explicit unsupported/uncertain outcomes.
5. **Add isolated patch validation:** reproducible tests, recorded results, regression checks, and security-specific verification.
6. **Add approval-gated application adapters:** start with a small, well-defined set of target types where safe end-to-end testing is feasible; expand through adapter contracts rather than weakening safeguards.
7. **Support imported findings:** normalize/import, preserve provenance, correlate, enrich context, and reject unsafe or context-free patch attempts.
8. **Expand vulnerability/target coverage incrementally:** maintain a published capability matrix and prioritize by customer value, exploitability, frequency, safe testability, and implementation confidence.
9. **Integrate the approved UI and reports:** only after the UI-first gate; maintain truthful state transitions and complete evidence.
10. **Acceptance and release gate:** require automated tests, controlled lab demonstrations, failure-path tests, authorization/scope tests, rollback/recovery checks, and end-to-end proof before calling each capability verified or shipped.

Do not invent time estimates until the code inventory and test plan establish the actual remaining work.

## 9. Required acceptance criteria

A remediation capability is not complete until tests demonstrate, at minimum:

- A WHAXON-native finding can produce an evidence-linked recommendation and, when context supports it, a reviewable patch.
- An imported finding retains its source/provenance and can be remediated when sufficient context is available.
- Missing/ambiguous context results in a safe, explicit refusal to generate or apply an unreliable patch.
- Generated patches are isolated from the original working tree until an approved application step.
- The user can inspect a diff and understand the expected change and risks before approval.
- Application cannot bypass target scope, authorization, or least-privilege policy.
- Production/high-impact changes are not applied without explicit approval.
- Validation distinguishes passed, failed, skipped, and unavailable checks.
- A test can prove the original vulnerability is fixed, or the system accurately reports that it cannot verify the result.
- Regression tests detect representative cases where a patch breaks intended behavior or only suppresses the finding.
- The audit record links finding, patch, approvals, applied change, checks, and retest outcome.
- Failure, cancellation, partial application, and rollback/recovery paths are tested where supported.
- UI controls map to real backend routes and show truthful status; unsupported controls are disabled/hidden.
- Documentation and capability matrix distinguish **generated**, **tested**, **applied**, and **verified** states.

## 10. Success measures

Track measurable indicators rather than marketing claims:
- percentage of findings with actionable guidance;
- patch-generation coverage by vulnerability class and target type;
- patch acceptance rate and human edit rate;
- validation pass/failure rate and false-fix rate from controlled tests;
- regression rate;
- percentage of applied fixes independently retested;
- time from validated finding to verified remediation;
- rate of safe refusal when evidence/context is insufficient;
- imported-finding coverage and provenance retention.

Do not optimize for raw patch volume at the expense of correctness, safety, or evidence quality.

## 11. Relationship to existing roadmap and status discipline

This addendum expands existing remediation lifecycle scope in §20.2 and complements the roadmap's validation, retest, reporting, evidence-reproduction, and scope-safety work. When the master roadmap is next edited, add a short cross-reference from §20.2 to this addendum so the relationship is visible from the canonical section.

Until implementation and acceptance tests are completed, all capabilities described here remain **QUEUED**. Planning approval does not mean code exists, tests pass, a patch is safe, or a vulnerability has been remediated.


---

## Part III — Dated engineering state snapshot (historical; not live status)

# WHAXON — Project state

> **Acceptance reconciliation — 2026-11-03:** At source commit `f0b25d3629d7`, 4 of 75 bounded requirement entries (P0-04, P1-01, P2-07, P4-01) are accepted with exact-commit CI evidence; 71 remain NOT_ACCEPTED. No E0–E9 phase or G01–G10 v1.0 release gate is closed. Prior claims that one-shot coverage/validate/retest/recon still drain unrelated pending jobs are historical and superseded by current source and `test_cli_initialization_isolation.py`. See [acceptance reconciliation](docs/V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md).

> **Current-head Engine V2 reconciliation (2026-11-03):** `main` at `f0b25d3629d776b433f72c83db679bb41313c812` includes E2 strict JSON contracts, E3 uncertain-request audit events and a synthetic child-process-kill/no-replay regression, E4 live adapter/binding checks, and merged E5 systemd worker-unit packaging, SQLite-only backup/restore regressions and Core health checks. [Updated bounded checkpoint audit](docs/ENGINE_V2_MASTER.md): **33/48 = 68.75%** source-backed *selected checkpoints*, **not** full-engine completion. **Formal E0–E6 and v1.0 release acceptance remain open.** Earlier baseline sections below are historical where superseded.

> **Integration update — 2026-11-02, supersedes affected baseline statements below:** Four one-shot CLI commands now use `initialize(drain=False)` with regression coverage. Desktop startup targets `/ui-v2`. Test catalog consumers use the packaged seed; the duplicate tracked root catalog and unused qasync requirement/manifest entry are removed, while operator catalogs and protected legacy designs remain preserved. See [UI control inventory](docs/V2_UI_MANDATORY_CROSSWALK.md) for 793 source controls across 22 templates; static coverage does not establish complete runtime wiring, visual fidelity, accessibility or service parity. Local browser execution is blocked by unavailable Chromium downloads. Local Python 3.12 verification: **1,110 passed, 14 skipped**, excluding 34 browser-dependent modules because Chromium downloads fail. Ruff, mypy (142 source files), wheel/sdist build and metadata checks, and clean-wheel arbitrary-workspace catalog bootstrap passed. The earlier CI/source records below describe their stated baseline, not acceptance of this integration.


**Reviewed:** 2026-11-02
**Repository / inspected branch:** `andreipath26/WHAXON-AI-Forensics` / `main`
**Source baseline:** `6fa1fa5f9bcff9b7afffb87ca908b0f78562fa3b`
**Authority:** [Product trajectory](#part-i--authoritative-product-roadmap), especially P0–P5 and §38. This is a dated summary; [the baseline register](docs/V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md) holds detailed evidence.

## Release and verification

The package is **0.11.16, Beta** in source and metadata. **v1.0 acceptance is OPEN.** Package-index/tag publication was not independently rechecked for this review; do not repeat an old publication claim as a current verification.

Exact-baseline [CI #41488450899](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/41488450899) passed all nine jobs. Python 3.11, 3.12 and 3.13 each reported **1,408 passed, 14 skipped**, with Ruff, mypy and distribution builds passing. Python 3.12 also passed sdist-resource and clean-wheel checks. Ubuntu/macOS/Windows setup smoke, headless Linux Waitress startup and curated apt/Homebrew installation/scanner smoke passed.

This certifies those checks on that SHA. It does not certify every external tool, platform, transport, deployment mode, UI control or v1.0 release criterion. No local runtime/browser tests were executed for this documentation review; future commits require their own CI evidence.

The old `Route.session_host` collection failure is fixed in current source and covered by the passing matrix. The earlier approvals Refresh-queue failure is historical, not the current CI state. Preserve the session identity guards; do not reopen resolved defects because an old document still lists them.

## What exists

- Shared Core/runner, SQLite job/finding/session persistence, adapter registry, 24 packaged catalog entries and guarded command/session execution.
- Reconnaissance, normalized findings, request-context handling, deterministic supported validation/observation/blind checks, retest and coverage/report paths. POST/state-changing context replay is refused; do not imply arbitrary authenticated replay support.
- Engine v2 immutable contracts/digests/manifests, persisted missions/tasks/attempts, scheduler leases/retries/deadlines/fencing, bounded per-run concurrency/task limits and an initial constrained provider bridge.
- Doctor/setup profiles, deterministic plans, explicit approval-bound Python installation, curated apt/Homebrew tools and diagnostics/operation/history UI/API paths. Native Windows external-tool installation remains manual.
- Supplied UI with 22 production page templates/destinations and 23 UI-v2 test modules. Web root redirects to `/ui-v2`; desktop `gui/embed.py` still loads legacy `/ui` and needs migration. Legacy design source remains preserved unchanged.

Code and tests demonstrate substantial implementation. Registered/installed/verified/authorized are separate states; component presence does not equal full product acceptance.

## Immediate correctness issue and remaining gates

**P1 priority:** `coverage`, `validate`, `retest` and `recon` call `Core.initialize()` with its default queue draining enabled. They can dispatch unrelated older pending jobs before their own action; `run` and `workflow` explicitly use `drain=False`. This is a source-confirmed startup side-effect risk, not an executed exploit demonstration. Add per-command no-unrelated-dispatch tests and repair the contract while preserving intentional worker/follow-up behavior.

Remaining trajectory:

| Gate | Current position |
|---|---|
| P0 baseline/cleanup | Evidence and principal paths refreshed; exhaustive capability/control inventory remains open |
| P1 correctness/Trust Layer | Substantial guards and validators exist; startup issue and integrated authorization/evidence/retest/coverage acceptance remain open |
| P2 shared durable lifecycle | Scheduler primitives exist; durable mission-wide budgets/cancellation/audit/reconciliation and CLI/API/UI parity remain open |
| P3 install/headless | CI smoke passes; clean-platform/upgrade/offline/partial-failure/restart, backup/restore and advertised service-mode acceptance remain open |
| P4 supplied UI | Integration exists; complete control inventory, desktop visual/accessibility/parity, external assets and desktop default remain open |
| P5 release | Controlled-lab end-to-end proof and §38 G01–G10 acceptance remain open |
| P6–P8 expansion | Full bounty autonomy, multi-target/competition, broad providers, vulnerability patch application and enterprise remain gated/deferred |

## Repository simplification

The tracked baseline has **534 files, including 82 Markdown files**. The old 102-file count and claims that an experiment archive remains in the current tree are stale. [Due diligence](docs/PROJECT_GOVERNANCE_MASTER.md) distinguishes exact duplicate/no-consumer removals from dependency-bound retirement and retained design/evidence/legal resources. Cleanup now removes the 23 verified non-runtime superseded files; runtime and branch retirements remain gated.

The 56 remote branches include main, ten other tips strictly behind it and 45 diverged tips. Retire only after exact-tip/reference checks; divergence needs content/PR reconciliation. Old branch tips are not merge instructions.

Scope remains application-level preflight, not a network firewall or connection-time DNS pin. External tool requests/redirects require deployment-specific egress controls. Installation changes are not generally rolled back; hash chains without an independent trust anchor are not immutable. AI proposes and explains; it neither authorizes operations nor determines verification.

Resume from current main/CI and the trajectory's next unmet gate. Do not restart completed implementation from historical notes or infer a global completion percentage from tests/pages.

