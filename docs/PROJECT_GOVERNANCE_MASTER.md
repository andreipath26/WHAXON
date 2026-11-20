# WHAXON — REPOSITORY GOVERNANCE, EXECUTION RULES AND RETIREMENT MASTER

> **Current repository audit boundary — 2026-11-06; implementation baseline at main `0cef416155623199d8cb551b809dd469d62b4778`.** The tree contains nine subject masters and two live acceptance CSV ledgers. `tests/test_documentation_integrity.py` checks 75 unique requirement entries and source/test file-path references. The acceptance register's 4 bounded ACCEPTED / 71 NOT_ACCEPTED requirement entries are not G01–G10 product-release approval. Exact-head main CI run [42253317306](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/42253317306) passed all 20/20 jobs. Historical branch/file counts and retirement candidates remain tied to their stated snapshots.

**Consolidated 2026-11-05.** Records engineering execution ownership, documented AI-use audit limitations and prior repository due diligence. Legal licenses, SECURITY.md, CONTRIBUTING.md, CLA.md, AGENTS.md and third-party notices remain separate binding documents. The [documentation index](README.md) and [documentation ownership policy](DOCUMENTATION_OWNERSHIP.md) determine which subject master to edit. Historical retention/deletion candidates in the register are *not* automatically approved changes; review runtime consumers and present HEAD.

## Part I — Repository due diligence and retirement audit (historical)

# WHAXON repository disposition and retirement register

> **Integration update — 2026-11-02, supersedes affected baseline statements below:** Four one-shot CLI commands now use `initialize(drain=False)` with regression coverage. Desktop startup targets `/ui-v2`. Test catalog consumers use the packaged seed; the duplicate tracked root catalog and unused qasync requirement/manifest entry are removed, while operator catalogs and protected legacy designs remain preserved. See [UI control inventory](V2_UI_MANDATORY_CROSSWALK.md) for 793 source controls across 22 templates; static coverage does not establish complete runtime wiring, visual fidelity, accessibility or service parity. Local browser execution is blocked by unavailable Chromium downloads. The earlier CI/source records below describe their stated baseline, not acceptance of this integration.


**Review date:** 2026-11-02
**Repository:** `andreipath26/WHAXON-AI-Forensics` · **Inspected main:** `6fa1fa5f9bcff9b7afffb87ca908b0f78562fa3b`
**Scope:** removal due diligence and retirement prerequisites, subordinate to the master roadmap P0–P8 and §38. **Execution update:** Batches A and B (23 non-runtime files) have now been removed after hash/reference checks. Runtime behavior, protected designs, Git history and branch refs are unchanged; Batch C and migration retirements remain pending.

## 1. Decision and evidence boundary

The baseline identified **26 specific file candidates**: 23 non-runtime artifacts and three no-consumer runtime/research files. These are candidates for bounded cleanup, not evidence that all obsolete material has been found or that every candidate is interchangeable with its replacement. Ten of the 26 are exact loose UI duplicates; they alone occupy **3,594,129 bytes**. The root tool catalog, legacy interface, old execution paths, distinct UI variants, legal notices and proof records are **not safe unconditional deletions**.

The inspected tree contains **534 tracked files, 82 Markdown files, 294 Python files, 147 `tests/test_*.py` modules, 23 UI-v2 test modules, 32 supplied HTML files and 32 PNG files**. The HTML count includes five loose duplicate copies. No tracked `.db` file is present. Counts describe this baseline, not future HEADs.

Evidence used: tracked-file inventory; SHA-256/byte comparisons; source, test, script, configuration and documentation reference searches; Python/Flask entry points and template/resource loading; packaging configuration; current branch comparisons; exact-baseline CI. CI [#41488450899](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/41488450899) passed all nine jobs; each Python 3.11/3.12/3.13 job reported **1,408 passed, 14 skipped**. This review did not rerun the runtime suite locally; its dependencies were absent. Existing green CI does not test a future deletion.

“No consumer found” means no reference was identified in this repository's inspected callers, scripts, packaging entry points and tests. It does not prove that an external user never imports a shipped module or requests a template through custom code. Recheck dynamic/plugin/external contracts before removing shipped resources. A filename, old version suffix, historical label or passing route is not removal proof.

Source of truth: current source/tests establish behavior; the master roadmap establishes sequence and acceptance; operator guides explain use. Historical captures, screenshots and designs do not establish implementation. This register replaces the older 102-file classification snapshot, which incorrectly described an experiment archive absent from current main.

## 2. Batch A — exact duplicate UI files

All paths in this table are relative to `web ui files and rendering/`. Remove only the loose copy in the first column, retaining the named original unchanged. Each row's two files have the full SHA-256 shown. No runtime/test/script/build consumer of the loose-copy names or this reference directory was found. These reference assets are outside the configured wheel package and sdist include set.

| Removal candidate | Named original to retain | Bytes | SHA-256 (both files) |
|---|---|---:|---|
| `code (copy 1).html` | `scope_targets/code.html` | 43,686 | `6c9fba82500e833f13f05e9087d4b9398642fdc80cb6dbdbb4b7ad553a6c168d` |
| `code (copy 2).html` | `run_tool_orchestration/code.html` | 40,358 | `54ace752fc75383dbd3b6b742af6b5481a43e04351902ebda3f5602abe3da3ba` |
| `code (copy 3).html` | `ptes_coverage_reports/code.html` | 45,975 | `bbc764431bcc752db65ee93ec478e630d567b801d1eaecf6865a4ce3604f2321` |
| `code (copy 4).html` | `ptes_coverage_reports/code.html` | 45,975 | `bbc764431bcc752db65ee93ec478e630d567b801d1eaecf6865a4ce3604f2321` |
| `code.html` | `trust_layer_verified_findings/code.html` | 42,120 | `756ecac819afbe482a24e177746b335ff8900c7efccc3a6d502542cb9249202b` |
| `screen (copy 1).png` | `scope_targets/screen.png` | 503,099 | `b10ed7fe5a0371004a173a019d4919dbf05ec5e78319c86500dbc2434c5f714e` |
| `screen (copy 2).png` | `run_tool_orchestration/screen.png` | 706,696 | `39c560c4c4ea538419c32fcb0dc8ae2eee7de3a7624be4784fc93a4de8c28b7f` |
| `screen (copy 3).png` | `ptes_coverage_reports/screen.png` | 717,113 | `b5ee04b15262de992cf83831571e3be76b21983212b48b48c9f9063fe187f14f` |
| `screen (copy 4).png` | `ptes_coverage_reports/screen.png` | 717,113 | `b5ee04b15262de992cf83831571e3be76b21983212b48b48c9f9063fe187f14f` |
| `screen.png` | `trust_layer_verified_findings/screen.png` | 731,994 | `df2cd7e0210a692c4735f69f1572cb9d34c7727d5b848ad2bda0c974989d6904` |

**Deletion condition:** refresh both hashes at the candidate revision, repair any documentation/bookmark references, and verify every named original remains. Keep supplied design and visual-baseline choices unchanged. Confirm the wheel/sdist resource set is unchanged. This removes ten copies, not ten product screens or ten distinct designs.

## 3. Batch B — non-runtime stale artifacts

These files have no operational/build/test consumer found. Documentation references are real dependencies and must be repaired in the same cleanup. Retain the inspected baseline in Git; do not add a second bulky archive to the working tree.

| Exact candidate or set | Evidence and disposition | Deletion condition |
|---|---|---|
| `commit_history.txt` | Static history export starts with old development commits; Git is the maintained history. No runtime/script/build consumer found | Remove stale links; history remains available through Git |
| `source_files.txt` | Static source listing includes the old GUI module and duplicates `git ls-files`; no runtime/script/build consumer found | Replace any inventory instructions with generated commands |
| `web ui files and rendering/whaxon_road_map_whats_next_full_scope.md` | Explicitly superseded copied roadmap, not the root authority | Repair the UI reference README and docs index; retain only the active root trajectory |
| `web ui files and rendering/whaxon_v1.0.0_deployment_release_notes.md` | Current file is a disclaimer for an unissued, misleading release draft—not a release artifact | Keep the “v1.0 not accepted/released” statement in current state/release records; repair links before removal |
| Nine imported captures listed below | Raw GitHub-page snapshots; explicitly archival, not implementation inputs. `whaxon.md` and `whaxon_2.md` are themselves exact duplicates | Remove capture links/classification rows rather than presenting dead links; keep unique product/design requirements in maintained sources |

The nine capture candidates, all under `web ui files and rendering/`, are:

- `extracted_text_from_https_github.com_andreipath26_whaxon.md`
- `extracted_text_from_https_github.com_andreipath26_whaxon_1.md`
- `extracted_text_from_https_github.com_andreipath26_whaxon_2.md`
- `extracted_text_from_https_github.com_andreipath26_whaxon_ai_forensics.md`
- `extracted_text_from_https_github.com_andreipath26_whaxon_ai_forensics_commits.md`
- `extracted_text_from_https_github.com_andreipath26_whaxon_ai_forensics_tree_main.md`
- `extracted_text_from_https_github.com_andreipath26_whaxon_blob_main_docs.md`
- `extracted_text_from_https_github.com_andreipath26_whaxon_commit.md`
- `extracted_text_from_https_github.com_andreipath26_whaxon_commits_main.md`

These nine captures have been removed; their provenance remains in Git. Do not treat removal of imported page text as permission to remove supplied `code.html`, PNG or `obsidian_kinetic/DESIGN.md` inputs.

## 4. Batch C — no-consumer code/template/research candidates

| Candidate | Evidence | Packaging/compatibility risk and required check |
|---|---|---|
| `src/whaxon/interfaces/gui/main_window.py` | Old native Qt `MainWindow`; current `whaxon-gui` entry point is `interfaces.gui.app:main`, whose own `MainWindow` embeds the web view. No import of `gui.main_window` found in source/tests/scripts/entry points | Shipped Python module. Check documented/public imports and downstream use; remove only with GUI import/startup/navigation regression and clean-wheel install. Keep `gui/app.py` and `gui/embed.py` |
| `src/whaxon/interfaces/web/templates/report.html` | No template rendering/inheritance/include reference found. Actual standalone report reads `core/report.html`; UI report uses `ui_v2_report.html` | Shipped template. Check dynamic/custom consumers; run report API/export and legacy/new web template regressions plus wheel resource checks. Keep `core/report.html`, print CSS, chart helpers and UI-v2 report templates |
| `data/tool_registry.json` | Separate 55-entry research list; no source/test/script/config consumer found. Packaged runtime catalog has 24 entries | Not an executable runtime registry. Reconcile unique candidate/license/source notes into controlled onboarding decisions before discarding research; do not enable the listed tools or alter the maintained catalog |

Exact baseline identities for these candidates:

| Path | Bytes | SHA-256 |
|---|---:|---|
| `src/whaxon/interfaces/gui/main_window.py` | 13,858 | `34b9e41c339238e9285d0210afe2428076782712cb2994146ece81a62598e390` |
| `src/whaxon/interfaces/web/templates/report.html` | 3,193 | `7eabe0b090ba64eafccd1b9771523a653cdbc8724d701efaade596c5bc9737dc` |
| `data/tool_registry.json` | 17,223 | `649ad1ad946e8adafcbc29575e257ba91e99aaf9fd07365783c2fa26157a159f` |

These are strong removal candidates after their checks, not permission to delete active GUI/report functionality. The three Batch C files remain present; no runtime test was performed locally. Batches A/B remove only non-runtime artifacts.

## 5. Batch D — migrate consumers before removing anything

| Material | Why immediate removal is unsafe | Retirement/migration gate |
|---|---|---|
| Root `data/tools.json` | Exact duplicate of packaged `src/whaxon/data/tools.json` (6,581 bytes; SHA-256 `84a97b7c21137685e75c5a5ff50d8029f107cc4fe04a28c8c9c8204a0f6dc2c7`). `tests/conftest.py`, `test_autochain_durable.py`, `test_smb_ls_template.py` directly read it; run/findings/TUI/report fixtures also copy it. TUI defaults to checkout-root `data`, so its runtime catalog is at this path | Make the packaged catalog the sole maintained seed; migrate all tests/default data-path handling; test fresh and existing workspaces, TUI/CLI/API, wheel/sdist and custom catalog preservation. Delete the tracked seed only after compatibility is proved. Never delete an operator's runtime catalog |
| Legacy web route/assets: `/ui`, `templates/base.html`, `templates/index.html`, `static/app.js`, `static/style.css` | `/ui` still renders `index.html`; desktop `gui/embed.py` still sets `URL` to `/ui`. New web root uses `/ui-v2`. User/roadmap explicitly require legacy design source unchanged | P4: migrate/test desktop entry point first; inventory existing consumers and define route compatibility. Source preservation remains mandatory; a route/package retirement decision does not authorize erasing reference source |
| Existing `core/worker.py`, `automation.py`, AI agent/executor/bridge, old job state | Live callers remain. Core attaches Automator; CLI run drains worker jobs; CLI/web AI use `build_executor`. Engine v2 is a partial migration, not a replacement of every caller/state path | P2: shared lifecycle, persisted-state upgrade, follow-up equivalence, approvals/scope, cancellation/recovery/parity/no-bypass tests and rollback. Migrate caller by caller; no wholesale deletion |
| Distinct supplied `_forensics_hardened`, `_v0.11.16` and other named UI alternatives | Names overlap but file contents are distinct; current production mapping and visual-acceptance choice must be established. They are protected design inputs | P4: canonical screen/variant mapping, difference review, unique-content preservation and visual acceptance. Do not infer supersession from suffix or date |
| Historical design/implementation documents | Several still carry useful rationale, schemas, assumptions or links from maintained source/guides | Consolidate active requirements/rationale and repair incoming references first; preserve unique history, then remove obsolete execution instructions or relocate only where useful |

Historical document candidates are `docs/agent-architecture.md`, `autonomous-loop.md`, `session-execution.md`, `report-redesign.md`, `report-visual-design.md`, `business-impact.md`, `ENGINE_V2_BASELINE_INVENTORY.md`, plus `WEB_UI_INTERACTION_AUDIT.md` as an explicitly preserved legacy audit. They are not a blanket deletion list. Examples of live references: scope guide and AI modules cite agent architecture; route/session tests cite session design; severity/core cite report redesign; print CSS cites visual design; `reports-and-evidence.md` points to business-impact cost sources. Preserve required source attribution and any unique decision rationale. The legacy audit/source must remain unchanged under the current user constraint.

### Dependency footprint and dormant helpers — conditional retirement

| Item | Actual usage found | Decision / coordinated retirement condition |
|---|---|---|
| `qasync` | Declared in GUI extra and dependency manifest/profile; no application/test import found. Current GUI uses Qt signals/timers and the embedded web server | Candidate to remove from GUI requirements only after clean GUI startup/navigation tests and synchronized extra, readiness/profile and notice updates. Metadata is still a consumer; not an isolated one-line deletion |
| `textual-image` | Declared in TUI extra/manifest/profile. Only code import is inside `tui/screens/splash.py`, behind `HAVE_IMAGE = False`; the TUI app does not mount that splash | Retire the disabled image path/requirement together after confirming intended TUI behavior, clean TUI tests and synchronized manifest/profile/notices. Preserve required legacy design/reference source; do not re-enable a known-disabled path just to justify a dependency |
| `interfaces/gui/splash.py` | `make_splash` has no source/test caller found; current desktop shell starts without it | Dormant helper retirement candidate, subject to shipped/public-module compatibility and GUI smoke checks; not counted among the 26 primary file candidates above |
| `gunicorn` | Actual production consumers in `Dockerfile` and `whaxon.service`; deployment guide documents it. `whaxon serve` separately uses Waitress | **Retain.** Multiple WSGI options are not proof of obsolescence. Removal requires a deliberate tested migration of Docker/systemd commands and documentation; Waitress presence alone does not supersede Gunicorn |

Removing an optional dependency changes install/readiness contracts and legal inventories; update those records as applicable without erasing historical attribution. No dependency declarations or helpers are changed in this documentation batch.

## 6. Retain — evidence, legal records and active resources

- Keep `src/whaxon/data/tools.json`, `dependencies.json`, payloads and attribution, `ai/prompts/planner_v1.md`, active report renderer/CSS/charts, parsers and tests. Prompt and payload Markdown files are runtime resources, not stale operator docs.
- Keep legal/license/CLA/trademark/third-party notices. Overlapping subject matter is not proof that a notice can be discarded; preserve attribution and applicable license obligations.
- Keep `data/proof-dvwa/` generated reports and their provenance pending an explicit evidence-retention decision. They are historical examples, not current acceptance. The identical `data/proof-cloud/tools.json` and `data/proof-testphp/tools.json` are separate snapshot contexts; deduplicating evidence is not the same as removing loose UI copies.
- Keep named supplied UI HTML/PNG originals and `obsidian_kinetic/DESIGN.md`. Historical screenshots may be excluded from active marketing without erasing protected reference assets.
- Keep TUI and current desktop shell unless a product retirement is explicitly decided. Optional extras and entry points still advertise these surfaces; old appearance alone is not dead-code evidence.
- Keep first-run/Engine v2/Metasploit/onboarding/bounty designs where they contain approved future contracts; their deferred state must be explicit. A proposed subsystem is not an obsolete subsystem merely because it has not shipped.

**Absent material:** `whaxon-experiment-2026-10-25/` and `docs/WHAXON_EXPERIMENT_AUDIT_2026-10-25.md` are absent from this baseline. Earlier documentation described them as present; repair those claims and links. Do not create placeholder files or count a nonexistent archive as a removal saving. No tracked proof database exists, so the old “remove committed proof databases” task is already satisfied in the current tree.

## 7. Branch retirement due diligence

There are **56 branch refs including main** at inspection. Comparing every other tip against the exact main baseline yields **10 strictly behind and 45 diverged**. No branch is deleted here. Ancestry containment proves reachable commit history, not that a historical effect is still enabled; it is sufficient to rule out unique commits on a contained tip but not external workflow/bookmark dependencies. Refresh tip SHA and compare before retirement; retain the table's SHA as the recovery identity.

### Ancestry-contained tips — eligible after reference checks

| Branch | Inspected tip SHA | Commits ahead / behind main |
|---|---|---|
| `docs/installation-diagnostics-guide` | `a6990952e1cd5ffe752a1935e6a2f6642cf6b820` | 0 / 263 |
| `feat/campaign-autonomy-foundation` | `31a09b524b330ec546b581338d4d179c205867bc` | 0 / 86 |
| `fix/ui-settings-no-mock-success-2026-10-29` | `8f94e18044d2c286e45a73d924766d02d61871da` | 0 / 273 |
| `fix/ui-v2-scope-acceptance-2026-10-30` | `c589caf0c67864c93d82518f6b7c6818fcf4839d` | 0 / 111 |
| `publish/whaxon-experiment-2026-10-25` | `889e9c0e30c82198d481de1993a9a3a599583be1` | 0 / 448 |
| `ui/ai-strategy-actions-2026-10-29` | `e6a83ad16f20223a37ea85d918053cc615cb5e1c` | 0 / 297 |
| `ui/approvals-actions-2026-10-29` | `7535748996f5786c470d049dc31d279f65c85547` | 0 / 290 |
| `ui/dashboard-actions-2026-10-29` | `8606cd3ce779f8832d035494d8dc5d187bd9b2a8` | 0 / 295 |
| `ui/dashboard-live-actions-2026-10-29` | `883d57ec507bda25d54778fc2e334b5e688c39b5` | 0 / 288 |
| `ui/threat-intel-live-actions-2026-10-29` | `883d57ec507bda25d54778fc2e334b5e688c39b5` | 0 / 288 |

Check open PRs, automation/default-branch references and owner intent before deleting a ref; do not merge these tips back into main. Preserve a recoverable ref/SHA record. A branch naming an old experiment is not proof that the experiment directory remains in current main.

### Diverged tips — not certified safe to delete

These 45 tips need content-level reconciliation against merged PRs/current source, including squash/cherry-pick effects. Ahead counts do not mean their work is missing from main; merged PR metadata alone does not prove every branch-only change is superseded. The review has **not** claimed patch equivalence or zero unique work for these branches.

| Branch | Inspected tip SHA | Ahead / behind |
|---|---|---|
| `docs/competitor-capability-remediation-roadmap` | `4015df14e7a7dc72c32da2a25ecfa401ab83cc76` | 2 / 270 |
| `docs/engineering-execution-rule` | `844bd30beda56d16bfe8e272ee699c7c08f21caa` | 3 / 267 |
| `docs/link-remediation-roadmap-addendum` | `be9a4fd73d40bc740ac1db94b60e78b6dd39d2e2` | 1 / 269 |
| `docs/readme-current-project-state` | `066e61dd218e312bd175da46aaedba1b1228112b` | 2 / 266 |
| `feat/first-run-install-manager` | `6001a2460027fa7d62c74edc8f71b357d053fd40` | 3 / 88 |
| `feature/bug-bounty-ingestion-stage1` | `b221ad781912da5152323e93ff94a215901ac7ba` | 36 / 268 |
| `feature/dependency-readiness-guided-install` | `f9149a77060bbd30bbc9f0d28e3e097a563359f0` | 188 / 267 |
| `roadmap/dependency-readiness-bounty-ingestion` | `5212b768e2ec21ed3ae3e894ed648c8c8bdbf403` | 2 / 272 |
| `roadmap/multi-target-subnet-orchestration` | `964b31b3aa3ae0e7849648e600146d4553db13b4` | 3 / 271 |
| `ui/adapters-actions-2026-10-29` | `a42e8a7f4870796ea148599ed999dd79fcf6200f` | 2 / 296 |
| `ui/adapters-live-actions-2026-10-29` | `c9942268026778ae5235bd4f0253c08dcef90903` | 3 / 288 |
| `ui/ai-scope-claim-truthfulness-2026-10-29` | `306797d803d20bbaaaec68c8328dd1c2a1819145` | 2 / 273 |
| `ui/ai-strategy-live-actions-2026-10-29` | `cb9c741e8f25ae0097f8836c11111837e6bae377` | 3 / 288 |
| `ui/approvals-header-actions-2026-10-29` | `96b91d376c42d95045096e02c949d50e93513623` | 2 / 289 |
| `ui/attack-chains-actions-2026-10-29` | `a652de34b0825ca864d1e2614429f6d3898bf825` | 3 / 297 |
| `ui/attack-chains-live-actions-2026-10-29` | `545374e54d478838c68d68ae06cdbc1160607c85` | 2 / 286 |
| `ui/audit-header-actions-2026-10-29` | `5b3eda07600e067371bbdfdbe10de603ffef25f7` | 3 / 301 |
| `ui/audit-live-scope-2026-10-29` | `1930fd1551fd0212ab04d75c7df5d365afb3b256` | 2 / 278 |
| `ui/bas-actions-2026-10-29` | `2f9eb3bae794a839293b47c79c4eb03af2377722` | 4 / 294 |
| `ui/bug-bounty-actions-2026-10-29` | `e09bf6da9774ef6bc819538cd435908f7066ea9e` | 4 / 294 |
| `ui/compliance-header-actions-2026-10-29` | `f32a2f68d3da5d58963f62a5a49ccddd817233fb` | 3 / 299 |
| `ui/dashboard-live-state-2026-10-29` | `457f5f4d496814f4f89aea6577232143a4dba330` | 5 / 286 |
| `ui/dashboard-wiring-2026-10-28` | `5b5faadb6f99eea705302ab21968022f62605df5` | 249 / 304 |
| `ui/diagnostics-live-action-audit-2026-10-29` | `d60f4b30bba08eae74b4fb496eb06b9981495f9b` | 3 / 303 |
| `ui/diagnostics-live-actions-2026-10-29` | `95a5d1a46f7ffab4c48c1a209d5dd6dfa495b65c` | 9 / 290 |
| `ui/evidence-header-actions-2026-10-29` | `e61d5de1faad1ce2230ce80978ac326b9df93e75` | 2 / 300 |
| `ui/findings-complete-2026-10-30` | `932e2a8f6fa920210ace25269f7cf5902b5d8e15` | 1 / 87 |
| `ui/findings-live-actions-2026-10-29` | `2ad22dbbe30530c869c16cf60a01f785a5770e64` | 1 / 288 |
| `ui/findings-live-kpis-and-scope-2026-10-29` | `966802e16147463bb068f40febf9dd059db2e1a9` | 7 / 274 |
| `ui/history-live-filters-2026-10-29` | `fc19edde78ce0ef718a52c53dd9c05fde45ec5a9` | 3 / 283 |
| `ui/monitoring-actions-2026-10-29` | `bc064f1b932d7bdf4819076c8a812b73527eb87d` | 6 / 295 |
| `ui/ptaas-actions-2026-10-29` | `d36290b7ee8667492597ac3a82146a224529038c` | 2 / 292 |
| `ui/report-scope-status-2026-10-29` | `672cd8fe42cb14f2b77e1688a33e41cf99381c46` | 2 / 281 |
| `ui/reports-controls-2026-10-29` | `0279e4b6956c124c1f0d1af95df6f9dfd026216e` | 2 / 288 |
| `ui/retest-actions-2026-10-29` | `c5e95022b95bd8ab5fd23d5bdda126ad12f977d0` | 2 / 291 |
| `ui/run-live-scope-header-2026-10-29` | `e4ccedf2b7649c62138e794c782ccba0c9e18619` | 4 / 279 |
| `ui/run-orchestration-complete-2026-10-30` | `9e2f103ab351fb8c723148ce34275576ef3e2a43` | 4 / 89 |
| `ui/run-planner-toggle-safety-2026-10-29` | `a6b1338137dffc05a0b931825b8b4d0b34be7191` | 4 / 283 |
| `ui/scope-enforcement-label-truth-2026-10-29` | `4532d1930c95b843d45ef375956bff5d52e51a9c` | 2 / 281 |
| `ui/scope-targets-complete-2026-10-30` | `73645de58ed4d5cbf2e0d3689c264fc7551c0604` | 3 / 90 |
| `ui/scope-workflow-verification-2026-10-29` | `746f13be1672789579d81d2acf6a7e6a82728705` | 1 / 285 |
| `ui/settings-header-actions-2026-10-29` | `f0587586fdbaf9fe145487793931005bb87b4426` | 2 / 302 |
| `ui/settings-live-scope-2026-10-29` | `009734711aef718fc8fe30d8684b2f862ffe8fd2` | 3 / 278 |
| `ui/threat-intel-browser-verification-2026-10-29` | `55e2e2ae6836407b4f4de3aefe2d07ad122185e8` | 2 / 277 |
| `ui/threat-intel-header-actions-2026-10-29` | `fc5df7ff959d25f835bdd61ca4f7325db5435522` | 4 / 298 |

For each diverged ref: identify associated PRs and merged/superseded decisions; compare branch-only changed paths/hunks against current main; classify retained, replaced, deliberately rejected or still unique work; preserve required work in a targeted change; record the decision and recovery SHA. Never remerge an entire stale UI branch to recover one useful hunk. This content review is a remaining retirement task, not silently completed due diligence.

## 8. Implementation batches, validation and rollback

| Batch | Scope | Required validation before merge |
|---|---|---|
| A — removed | Ten exact loose UI copies | Fresh hashes, named-original inventory, links, no design/template change, distribution resource comparison |
| B — removed | Thirteen stale non-runtime artifacts (nine captures, copied roadmap, release disclaimer, two exports) | Incoming-link repair, maintained authority/release statement retained, no runtime/package/resource delta |
| C | Three no-consumer files | Public/dynamic-consumer review, GUI/report regressions for affected resources, catalog/research reconciliation, clean wheel/sdist inspection |
| D1 | Root catalog consolidation | Migrate every consumer, preserve existing/custom runtime data, fresh CLI/TUI/API startup and relevant fixture/packaging regressions |
| D2 | UI route/desktop retirement | Accepted `/ui-v2` desktop default, compatibility contract, route/navigation/browser tests; protected legacy source unchanged |
| D3 | Execution-path consolidation | State migration, equivalent authorization/follow-ups, cancellation/crash/restart and parity/no-bypass tests; keep rollback until accepted |
| D4 | Historical documentation | Unique requirements/rationale/attribution preserved, all incoming links updated, removed schedules no longer presented as live work |
| R | Branch retirement | Fresh SHA/ancestry, workflow/PR references, full divergent-content disposition where needed, recoverable SHA/ref record |

Use isolated reviewable commits; apply dependent migrations before their removals. Record exact candidate, checks/results and any untested external-compatibility assumptions. After runtime or packaging deletions run affected tests, build/inspect wheel and sdist, install a clean wheel, then required CI once at the integration boundary. Documentation-only changes need link/content/diff checks; they do not justify claiming runtime acceptance.

Rollback: revert the bounded cleanup commit to restore tracked files; restore a branch from its recorded SHA while the object remains reachable, using a retained archival ref when required. Do not rewrite Git history. This register authorizes no live data removal and is not an automatic deletion script. Revalidate every candidate after main moves.


---

## Part II — Engineering execution model

# WHAXON Engineering Execution Model

**Status:** Main engineering rule — non-negotiable  
**Applies to:** Every WHAXON phase, subsystem, interface, and release.

## Main rule

**NON-NEGOTIABLE. Applies to every WHAXON phase, subsystem, interface, and release.**

Develop WHAXON through coordinated parallel workstreams wherever work can safely proceed independently. Roadmap phases define scope, dependencies, and acceptance criteria; they do not require needless serial execution. Optimise for the shortest verified end-to-end delivery time without sacrificing architecture, security, evidence, or release quality.

### Required rules

1. **One source of truth:** the roadmap, repository state, dependency graph, decisions, PRs, and acceptance evidence must stay aligned.
2. **Map dependencies first:** identify prerequisites and stable interfaces. Parallelise independent work; sequence only genuine dependencies and safety gates.
3. **Prioritise the critical path:** work first on blockers that prevent the most downstream progress. Recalculate when conditions change.
4. **Agree contracts before parallel work:** define shared schemas, APIs, state machines, error semantics, security boundaries, evidence formats, and compatibility requirements.
5. **Bounded ownership:** assign each workstream explicit scope, owner, files/interfaces, dependencies, deliverables, and tests. Avoid concurrent edits to the same files; coordinate shared-file changes through one integration owner.
6. **Integrate continuously:** merge small increments against shared contracts; run focused tests immediately and broader regression at integration boundaries. Do not wait for an entire phase.
7. **Independent adversarial review:** security, authorization, scope enforcement, evidence integrity, and recovery require review separate from implementation wherever practical.
8. **Verification is part of the task:** code presence or an agent's assertion is not completion. Require relevant unit, integration, security, browser/E2E, packaging, and compatibility checks; record actual results.
9. **Preserve the five principles:** know the environment; understand impact; recommend before acting; act only with consent; leave durable, attributable, tamper-evident evidence. Parallelism never bypasses them.
10. **Bound concurrency:** use isolated branches/worktrees where available, sensible worker limits, small changesets, explicit merge order, and one integration authority. Avoid duplicated effort and uncontrolled agent spawning.
11. **Record failure and recovery:** blocked work, failed checks, partial effects, cancellation, uncertain outcomes, conflicts, and recovery must be visible. Never claim success when outcome or evidence is unknown.
12. **Release on integrated evidence:** phase/release completion requires all components to work together and acceptance gates to pass. Individually completed components do not equal a working platform.

### Standard workstream lifecycle

Define outcome and acceptance tests → map dependencies and interfaces → assign bounded ownership → implement independent tasks concurrently → test against contracts → integrate continuously → conduct independent review → run cross-component regression → record evidence and update status.

### Required coordination records

Maintain an active dependency graph and critical path; a workstream register (scope, ownership, status, blockers, affected paths, acceptance); shared contract/version decisions; integration queue and merge order; and verification records linking completion claims to commands, CI runs, reviews, and limitations.

### Concurrency decision

Parallelise only when interfaces are stable, ownership is isolated, and outcomes are independently testable. Sequence work when another task changes its contract, data model, security boundary, migration, or precondition. If safe ownership is unclear, resolve or split the work first. Do not parallelise merely to increase agent count.

### Success measures

Optimise verified end-to-end lead time, early blocker discovery, low integration conflict, reduced rework, and reliable release acceptance—not agent count, branch count, lines of code, or reported completion percentages.

**This rule supersedes older roadmap wording that implies unnecessary serial execution.** Existing phase order remains binding wherever a real dependency, safety gate, or acceptance prerequisite requires it.

---



---

## Part III — AI usage audit

> **Historical disclosure (2026-10-02):** This statement records the author's described AI-tool usage through the date shown. It is not a continuously maintained provenance log, a guarantee that no other tooling was used later, or a substitute for reviewing commit history and the actual contribution process for a specific financing, licensing or legal representation.

# AI Usage Audit

**Date:** 2026-10-02
**Author:** Vasile-Andrei ([GitHub: andreipath26](https://github.com/andreipath26))

## Statement of Human Authorship

WHAXON was designed, architected, and developed by a human author. AI tools (Claude, Copilot, ChatGPT) were used as development aids for:
- Autocomplete suggestions on code the author was actively writing
- Boilerplate scaffolding (imports, class skeletons, error message templates)
- Documentation formatting
- Test case expansion from author-written test logic

## Human Creative Contributions

The following elements represent original human creative choices:
- **Architecture:** The adapter/catalog/runner/event-bus separation
- **Deterministic guardrails design:** The "planner proposes, executor disposes" pattern (ai/executor.py, ai/scope_policy.py)
- **Correlation rules:** The 8 rule definitions in core/correlator.py
- **Auto-chaining logic:** core/automation.py, core/autopivot.py
- **Scope enforcement:** core/scope.py (fail-closed model)
- **Pivot chain graph:** core/pivot.py, core/routes.py
- **CLI command structure:** interfaces/cli/*
- **Data model:** core/findings.py, core/store.py

## Iteration Evidence

221 commits to `main` over the project lifetime demonstrate iterative human development, not bulk AI generation. Code was written, tested, refactored, and debugged by the author across multiple sessions.

## Remediation

Files identified as potentially high-AI-content (GUI/TUI scaffolding, provider wrappers) have been reviewed and manually modified to ensure human creative contribution. Detailed per-file audit available on request.

