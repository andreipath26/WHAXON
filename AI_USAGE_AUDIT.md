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
