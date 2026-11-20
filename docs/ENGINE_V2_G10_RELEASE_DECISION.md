# Engine V2 G10 Delivery Status and Release Decision

**Assessment date:** 2026-11-20

**Decision:** **HOLD — NOT READY TO DEPLOY**
**Current main code head:** `5aecbc8`. PRs #222–#224 are merged. PRs #222 and #223 passed 20/20 exact-head CI checks each; PR #224 passed 22/22 after retrying a transient Docker installation failure in the controlled-lab job. The merged work hardens typed V2 request contracts, tracks worker readiness per instance, and reconciles stale run requests before readiness. Current continuation `codex/v2-effect-recovery-20261120` adds a default-deny gate to the dormant legacy Qt direct-dispatch path. Its 11 focused tests pass; repository Ruff and mypy pass. Hosted exact-head CI for this continuation is pending. A previous full local pytest run was blocked at browser startup by the container's Chromium socket restriction (1,908 passed, 17 skipped, 376 browser setup errors); this is not a current hosted-CI result. No V2 release tag, package publication, or production deployment exists.

## Delivery sequence

Complete the agreed V2 engine, V2 UI, and remaining solo-v1.0 implementation scope first. Continue internal unit, integration, security, static, and browser testing throughout development. Do not hold implementation work waiting for real-target, independent-review, manual-accessibility, or production-like deployment evidence.

After the full agreed implementation is complete and internal checks pass, perform final external qualification: authorized real-target testing, independent evidence/security review, manual accessibility review, and production-like multi-worker, installation, upgrade, rollback, backup, and recovery exercises. Production rollout follows a passing exact-candidate qualification. Deferred P6–P8 / E7–E9 expansion is not part of this completion gate.

Previously recorded bounded CI and lab runs remain evidence for their stated scope. They do not prove the complete product is finished, and they do not need to be repeated during implementation unless an internal regression requires it.

## Current decision basis

The decision remains **HOLD** because the implementation is not complete. The open implementation work includes exhaustive V1 execution-path coverage, migration of remaining legacy clients to shared V2 lifecycle services, full transport/client parity, provider-effect recovery, and completion of all agreed UI controls and workflows. The repository has route-level browser suites, but route coverage alone does not prove every UI action is implemented and wired to real services.

The release checklist also contains post-implementation external qualification items. Those items remain pending by sequence; they are not prerequisites for continuing implementation.

## Gate record

| Gate | Implemented or recorded now | Remaining work and sequence |
|---|---|---|
| G01 | Bounded V2 crosswalk and exact-tree isolated lab evidence; top-level CLI inventory and AST guard. Candidate `75880425cdaf4857989f229638e59c5b65de099f` passed CI run #43624338670; G01 chain artifact #14125401711 is retained. PR #224 also passed the current controlled-lab chain. The dormant Qt direct-dispatch path is now default-denied by an explicit environment gate. | Complete exhaustive V1 caller and dispatch-path inventory during implementation. Defer additional real-target qualification until the full scope and internal checks are complete |
| G02 | Bounded authorization/execution regressions, including legacy `/api/run` bypass and redirect cases | Close remaining caller, session, pivot, cancellation, and cross-transport authorization gaps with internal tests |
| G03 | Bounded independent-validation/retest behavior; unsupported methods and kinds remain conservative | Complete supported-method and finding-state behavior and internal regression coverage |
| G04 | Report overhaul and bounded evidence/coverage checks | Complete implementation of evidence and report requirements. Defer independent audit anchoring, external custody review, and final evidence qualification until implementation is complete |
| G05 | Bounded shared lifecycle and durable service work | Complete legacy-client migration, provider-effect reconciliation, client parity, and internal crash/recovery handling |
| G06 | 22 production routes and page-level browser suites exist | Complete all agreed UI workflows, control wiring, service behavior, and internal browser/API tests. Final visual, manual accessibility/security, and deployment qualification happen after implementation; there is no UI implementation freeze |
| G07 | Bounded setup/staging and upgrade-smoke evidence | Complete implementation and internal install/recovery checks. Defer production-like upgrade, rollback, and disaster-recovery qualification until the whole product scope is ready |
| G08 | Bounded candidate-CI acceptance is recorded | Run required exact-candidate CI after implementation is complete |
| G09 | Release-safety code and tests exist; no V2 release identity/publication exists | Create and verify the release identity and artifacts after the candidate passes qualification |
| G10 | This HOLD record | Reassess only after implementation, internal checks, external qualification, and release-artifact verification are complete |

## Deferred external qualification checklist

After implementation is complete, record evidence for:

- A controlled target WHAXON is explicitly authorized to assess, with scope, constraints, and retained run evidence.
- Independent review of evidence integrity and audit anchoring.
- Manual UI review against the agreed desktop design and accessibility criteria.
- Security review of the completed candidate.
- Production-like install, upgrade, rollback, backup/restore, worker recovery, and preservation of queued or uncertain work.
- Exact candidate SHA, CI/lab outcomes, limitations, verified publication artifacts, and the final release decision.

These items are deliberately sequenced after feature completion. This record does not authorize testing a target or deploying to production.

## Reopen condition

Keep this decision at **HOLD** while implementation or internal checks remain incomplete. Once they pass, proceed to the deferred external qualification checklist. Record a new G10 decision after the exact release candidate and its qualification evidence are reviewed.
