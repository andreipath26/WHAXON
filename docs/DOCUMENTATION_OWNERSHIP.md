# WHAXON — documentation ownership and retirement policy

The Engine V2 requirement and checkpoint ledgers are live CSV navigation indexes. Keep their `implementation_candidate`, `test_candidate`, `source_paths` and `related_test_definition` columns pointing to existing files after every consolidation. `tests/test_documentation_integrity.py` enforces this condition and the 75-entry cardinality in CI. Dated narrative history remains intact.

**Active inventory after consolidation; status checked 2026-11-06 at `main` `0cef416155623199d8cb551b809dd469d62b4778`.** This document specifies canonical owners; [docs/README](README.md) is the reader-facing index.

## Authoritative subject ownership

| Subject | Owner file |
|---|---|
| Product roadmap, competitor priorities, status | [WHAXON ROAD MAP - WHATS NEXT - FULL SCOPE.md](../WHAXON%20ROAD%20MAP%20-%20WHATS%20NEXT%20-%20FULL%20SCOPE.md) |
| Engine V2 | [ENGINE_V2_MASTER.md](ENGINE_V2_MASTER.md) |
| V1 acceptance | [V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md](V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md) |
| UI V2 | [V2_UI_MANDATORY_CROSSWALK.md](V2_UI_MANDATORY_CROSSWALK.md) |
| App architecture, AI and API | [APPLICATION_ARCHITECTURE_MASTER.md](APPLICATION_ARCHITECTURE_MASTER.md) |
| Installation, deployment, operator instructions | [OPERATIONS_MASTER.md](OPERATIONS_MASTER.md) |
| Findings, reporting, evidence, retention | [EVIDENCE_AND_REPORTING_MASTER.md](EVIDENCE_AND_REPORTING_MASTER.md) |
| Commercial planning, CBC, funding, editions | [CBC_2026_WHAXON_PARTNERSHIP_AND_INVESTOR_PLAYBOOK.md](CBC_2026_WHAXON_PARTNERSHIP_AND_INVESTOR_PLAYBOOK.md) |
| Bug bounty authorization, programmes and differential workflows | [bounty-addon.md](bounty-addon.md) |
| Business-impact severity methodology | [business-impact.md](business-impact.md) |
| Engineering governance, previous retirement records | [PROJECT_GOVERNANCE_MASTER.md](PROJECT_GOVERNANCE_MASTER.md) |
| Release history | [CHANGELOG.md](CHANGELOG.md) |

## Permanently distinct files

The bug bounty module and business-impact calculator are independent technical specifications, not chapters of the CBC commercial playbook. The original `web ui files and rendering/obsidian_kinetic/DESIGN.md` remains at its canonical design-source path and must not be deleted or silently replaced by a consolidated copy.


The root `README.md`, `AGENTS.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CLA.md`, `LICENSE*`, `TRADEMARK.md`, `THIRD_PARTY_NOTICES.md` and third-party license inventory have distinct operational or legal roles; do not absorb/delete these. Retain asset readmes and data-provenance files adjacent to assets, plus CSV evidence registers and historical Git commits.

## Rules for new and obsolete documents

1. Write current advice into the existing owner; do not create another `*_STATUS`, `*_AUDIT`, `*_ROADMAP`, `*_ACCEPTANCE`, or `*_PLAN` Markdown narrative for the same topic.
2. A dated technical record may be appended to the master under a clear evidence boundary. Keep machine-readable verification results in test artifacts or CSVs.
3. Before deleting a standalone narrative, incorporate all unique content into its subject master, replace internal references, and verify no source/test/license consumer requires the old path.
4. Do not delete binding policy or data files on the assumption they are obsolete; their ownership is distinct.
5. Treat source and CI on exact HEAD as behavioral truth; historical text embedded in masters is evidence, not an updated deployment verdict.

## Consolidation record

**2026-11-05:** 56 redundant narrative Markdown paths were removed after their full text was absorbed into nine subject masters. The UI-supplied DESIGN.md text was absorbed into UI master; immutable design images and source HTML remain. Legal/functional files stay at their stable paths. Individual historical changes remain accessible by Git commit. The removal transaction is captured in the consolidation commit and remains reversible through Git history.
