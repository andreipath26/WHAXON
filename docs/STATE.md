# WHAXON — Project State

Read this first. Updated at the end of every session.
Last updated: 2026-10-21, session 81.

## 1. Where we are

- Version 0.11.12. Branch main.
- Tests: 797 passing. ruff 0, mypy 0, both gated in CI on 3.11/3.12/3.13.
- Pre-beta repository audit closed in session 81. Remaining audit items: W-01 (11 of 14 web pages are mockups — product decision), L-02 (legal review of dual licensing — non-AI), S-05 partial (scope change audit event), C-01b-2 slide-over verification view. Deferred to a post-beta session.
- Roadmap still has §32 (solo-first v1.0). Full session record: docs/CHANGELOG.md.
- Not v1.0. The definition now exists (§32.0); ~71h / ~8-10 sessions at measured pace, excluding the two AI-dependent units.

## 2. Built this session (committed 71121c6)

- findings_by_target groups by host
- whaxon jobs reconcile
- Rules ladder enumeration runs gobuster
- whaxon ai --verbose streams tool output
- Success check reads ok
- Executor ok from exit_code
- ai_bridge drains queue after each tool run
- nuclei templates installed (environmental, unmanaged)

## 3. Written this session (roadmap §32.0-§32.13)

Stopping condition, eleven-bug pattern, hydra initial access, validation, business-logic inference, coverage, remediation/retest, AIRT, six-tool chain, prerequisite fixes, adapter harness contract, §26 consumption, AI provider strategy, three-tab UI with parity rule, effort/sequence.

## 4. Verified against live targets

- bWAPP (itsecgames.com): full ladder, verbose exposed nuclei fatal.
- Google Gruyere: full ladder, nuclei 24 findings after templates fix, no orphaned jobs.
- DVWA: Proof A (PR #30), four tools, 45 findings.

## 5. Known unverified or broken

- WMI transport: wired, never run against a Windows target.
- Report job-history finding counts show 0 for jobs that have findings.
- initialize() drains pending jobs; one-shot whaxon run executes queued jobs. Blocks coverage disclosure. Decision required.
- Raw job output not persisted (no job_lines table).
- msf_tracker timing flake under xdist.
- UP031 printf formatting: 32 sites.
- .db files committed in data/proof-dvwa/; proof-bwapp, proof-gruyere, proof-juice untracked.
- nuclei templates unmanaged (~/.local).
- hydra installed, not in catalog.

## 6. Next steps

1. Service layer + parity test (unblocks three tabs).
2. Schema fields: verification_status, coverage_ref, retest_state, actor, nullable org_id.
3. Three tabs (Discover / Operate / Report).
4. hydra initial access.
5. Validation.
6. Coverage (needs the initialize() drain decision).
7. Retest lifecycle.
8. Six-tool chain.
9. AI provider spike when business-logic code exists.
10. Proof C: full chain on a lab target.

## 7. Session log

57 lint+correlator. 61 severity+report 1a/1b. 62 report restructure. 63 business impact. 64 standalone report. 65 quality gates. 66 §21 closed. 67 §4 closed. 68 §26.1 policy layer. 70 durable auto-chain, adapters, Proof A. 71 findings grouping, reconcile, enumeration, verbose, ok-from-exit-code, drain. 72 solo-first v1.0 defined, §32 written, 763 tests. 81 pre-beta audit fixes: C-02, S-01, S-02, S-03, S-04, S-05 partial, SC-01, SC-02, SC-03, SC-04, W-03/C-04, W-06, W-08, C-01a, C-01b, D-01, D-02, D-06; median-of-3 timing; 4 tests added; 797 tests; v0.11.12.
