# Development handoff — 2026-10-30

## Immediate resume point

**Repository:** `andreipath26/WHAXON`  
**Workstream:** ui-v4, page-by-page functional completion  
**Current PR:** [#70 — ui: wire Attack Surface graph to persisted pivot data](https://github.com/andreipath26/WHAXON/pull/70)  
**Working branch:** `feature/observation-probes`  
**Base branch:** `main`  
**Rule:** keep the existing UI shell and styling; finish one page end-to-end before moving to another. Do not create another branch.

At the time this handoff was written, PR #70 had been updated with the implementation, the keyboard-test correction, the interaction-audit update, and this handoff. The latest CI result must be checked on the PR before merging. Earlier run `41073288000` showed Python 3.11 and 3.12 passing; Python 3.13 was still installing/running. Do not treat the PR as merged until GitHub reports `merged: true`.

## Completed in PR #70

- Replaced the hardcoded Attack Surface SVG with graph data from `GET /api/pivot/graph`.
- Graph renders persisted exploit, session, and forwarding relationships.
- Added click and keyboard node inspection, refresh, and explicit empty/error states.
- Removed duplicate Retest, Sessions, and Catalog loader blocks while preserving live and stored Metasploit session response handling.
- Added API and Playwright regression tests.
- Updated `docs/WEB_UI_INTERACTION_AUDIT.md` and `docs/CHANGELOG.md`.
- Fixed a flaky/incorrect keyboard-shortcut test: it now blurs the focused target input before asserting the global `/` command-palette shortcut. The UI intentionally ignores global shortcuts while a text input is focused.

## Merge gate

1. Read PR #70 head SHA and latest check-runs.
2. Confirm all required checks succeed on the current PR head for Python 3.11, 3.12, and 3.13, including lint/type/boundary/browser tests.
3. If any check fails, inspect its exact failure, fix it on `feature/observation-probes`, and rerun CI. Do not bypass required branch protection.
4. Merge PR #70 (squash is acceptable) only after all required checks pass.
5. Verify GitHub reports merged and record the merge commit SHA.

## Next UI work after merge

Continue the page-by-page audit from `docs/WEB_UI_INTERACTION_AUDIT.md`. Attack Surface is now marked WIRED. Do not redesign the shell or replace working pages with mockups. Select the next highest-priority page with unfinished real interactions, inspect its API/backend contract first, then wire UI controls to real persisted/backend behavior and add API + browser regression tests. Hide controls that have no supported backend rather than presenting fake functionality.

The audit currently identifies CVE/Threat Intel search as deferred (no web-backed service), and other Settings/Compliance/Notifications/Workspaces features as hidden or deferred. Re-evaluate against current code before starting; the repository is the source of truth.

## Separate repository context — WHAXON-AI-Forensics

**Repository:** `andreipath26/WHAXON-AI-Forensics`  
**Branch:** `main`  
There were no open PRs when checked on 2026-10-30. Scope & Targets work was committed directly to main. The latest relevant changes made the scope page report only data actually exposed by the scope API, removed misleading/demo information, added truthful labels and empty/filter states, and added edit/remove persistence plus CLI copy behavior tests. A CI failure was traced to a test assertion comparing transformed text against raw script/template source; the assertion was corrected to inspect rendered page text and uppercase CSS-transformed labels. Check the latest Actions run before assuming the branch is green.

Keep the two repositories separate. The current PR #70 belongs to `WHAXON`, not `WHAXON-AI-Forensics`.
