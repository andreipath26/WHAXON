# Report redesign

**Status:** DRAFT — active.
**Owner:** andreipath
**Depends on:** docs/reports-and-evidence.md
**Non-goals:** does not change the finding model, does not add new adapters.

---

## Why

The current report is not a client deliverable. Four concrete failures:

1. **Duplication.** The same finding appears once per job that produced it. A single vsftpd 2.3.4 finding appears 10 times in one engagement. `finding_count: 570` is raw rows, not unique findings.

2. **Severity inflation.** Every nikto finding whose raw line contains a CVE reference URL is classified Critical with CVSS 9.0. Nikto appends CVE URLs to almost every finding. Result: 34 Critical findings, of which roughly 8 are genuinely critical.

3. **Test-job noise.** `echo` jobs, `persist-test`, `kioo`, and other fixture targets appear in the client-facing job history.

4. **No business framing.** The executive summary is five severity counts. Findings are one-line bullets. There is no remediation roadmap, no attack narrative, no time-to-fix estimate.

## Non-negotiable constraints

- Deterministic. No LLM in the parsing, classification, dedup, or reporting path (R71).
- The report is derived from the store. No new state.
- Every change is testable offline.

---

## PR 1 — Correctness

### 1a. Adapter severity audit (all 24 adapters)

The bug pattern: a severity pattern matches a substring of the raw line rather than the semantic content of the finding.

Concrete example: `nikto.py` has a pattern matching `cve-\d{4}-\d+|vulnerable|remote code execution|command injection` classified as Critical, CVSS 9.0. Nikto appends `See: https://nvd.nist.gov/vuln/detail/CVE-1999-0678` to the directory-browsable finding. The regex matches `CVE-1999-0678`. The finding is now Critical. It is a directory listing.

The rule: severity patterns match the subject of the finding, not any string that appears anywhere in the raw line. A CVE in a reference URL is a reference, not a claim.

Scope: every adapter in `src/whaxon/adapters/` that has a severity table. 24 adapters. For each: read the severity patterns, identify patterns that match substrings not intrinsic to the finding, tighten them, and add a regression test with known-safe raw lines that must not be elevated.

### 1b. Dedup in `_load`

`store.findings_by_target` already dedups by `(target, kind, signature)` and accumulates a `count`. `report._load` does not. It iterates `jobs[].findings[]` and counts every row.

Fix: `_load` uses `store._signature_for(kind, data)`. Key is `(target, kind, signature)`. Duplicates increment a count and accumulate the list of jobs. `severity_counts` and `finding_count` are computed over unique findings.

Signature per adapter: nikto `(path, message_lower)`, nmap `(port, protocol, service)`, sqlmap `(parameter, technique)`. Adapters without a declared signature fall back to a hash of `(kind, raw_line_lower)`.

### 1c. Test-job filter

Jobs whose target is a known test string, or whose tool is `echo`, are excluded from client reports by default. Add `?include_test_jobs=1` to `/api/report` and `--include-test-jobs` to `whaxon report`.

Test target list: `evil.com`, `hi`, `hello`, `persist-test`, `kioo`, `ww.google.com`.

### 1d. Executive summary

Replace severity counts with a short narrative: one paragraph on overall risk, top 3 findings in plain language, one recommendation. Generated deterministically from the deduplicated findings. No LLM.

### 1e. CVE-driven severity with CVSS and EPSS

A post-parse step resolves finding severity from the local vulnerability database when a CVE identifier is present on the finding. The CVSS base score determines the severity band, using NVD qualitative ratings: 0.0 info, 0.1-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10.0 critical.

EPSS score and CISA KEV membership are carried on the finding but do not set severity. They feed the priority computation in PR 3.

Lookup order: local database only (data/vulndb.db). No network call at finding-creation time. When no CVE is present, or the CVE has no CVSS score, the adapter severity stands. Every finding records which source set its severity: nvd or adapter.

This is the structural fix for the nikto class of bug: a CVE reference in a raw line no longer determines severity, because the adapter is no longer asked to guess.

### 1f. Vulnerability database

core/vulndb.py manages a local SQLite database at data/vulndb.db, built from three sources: NVD (CVSS scores, severity, descriptions), EPSS (exploitation probability, daily gzipped CSV), CISA KEV (known exploited catalog, daily JSON).

Downloaded via whaxon vulndb update. No automatic network calls. Ships as a release asset for air-gapped installs. Refreshed weekly or on demand.

CLI: whaxon vulndb update, whaxon vulndb status, whaxon vulndb lookup cve-id.

### 1g. Priority computation (PR 3 preview)

Severity is CVSS. Priority is CVSS + EPSS + KEV + business context. The report ranks by priority, not severity. Rule: priority HIGH if KEV or EPSS > 0.2 or CVSS >= 9.0; MEDIUM if EPSS > 0.05 or CVSS >= 7.0; else LOW.

This turns 34 Critical findings into 3 findings that need action this week.

PR 1 does not touch the report structure beyond 1d. The sections stay in the same order. The content becomes correct.

---

## PR 2 — Restructure

### 2a. Five-layer report

1. **Executive brief** (1-2 pages). Overall risk rating, top 3 findings in business language, one recommendation, trend if available.
2. **Remediation roadmap.** Immediate / Short-term / Medium-term / Backlog. Choke points identified.
3. **Attack narrative.** How findings chain. Automatic once the attack graph engine (section 25) exists. Hand-written until then; optional section.
4. **Technical findings.** Deduplicated, one entry per unique finding, with the list of jobs.
5. **Appendices.** Raw evidence, tool output, job history, ATT&CK coverage (later).

### 2b. Findings to appendix

The current report leads with 34 Critical bullets. The restructure moves findings to layer 4 and puts the executive brief first.

### 2c. Job history to appendix

The job history moves to layer 5 and filters test jobs.

---

## PR 3 — Commercial framing

### 3a. Business-impact severity

The report's severity is not the adapter's severity. It is the impact on the organization. A CVSS 9.8 on an isolated admin panel behind MFA is lower business impact than a CVSS 7.5 on the login page every customer touches.

Implementation: a `business_impact` layer computed at `_load` time from the finding's kind, its data, and the engagement's context. Deterministic. Table-driven.

### 3b. Cost/impact ranges

Each finding class carries an estimated impact range: downtime, data breach, regulatory fine. Ranges, not precise numbers. Sourced from industry defaults, documented in the file.

---

## PR 4 — Visual design

### 4a. HTML/PDF rendering

The current HTML wraps markdown in `<pre>`. The redesign is a proper layout: severity chart, per-finding cards, color, typography.

### 4b. Charts

Severity donut, trend line, ATT&CK coverage matrix (later).

### 4c. Appendix formatting

Raw tool output formatted readably.

---

## Cross-cutting rules

- Deterministic. No LLM in the report path.
- Every change has a test.
- Reports generated from the store. No parallel state.
- Adapter severity tables are load-bearing. New adapters get the same audit as the 24 existing ones.
- `docs/reports-and-evidence.md` is updated in the same PR as the change.

## Ship order

PR 1 → PR 2 → PR 3 → PR 4. Each is a separate branch and PR. None starts until the previous one is merged.

## What is not in scope

- A new finding model.
- New adapters.
- The attack graph engine (section 25).
- Live collaboration.
- Client portal.