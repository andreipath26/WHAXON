# WHAXON — FINDINGS, REPORTS, EVIDENCE AND RETENTION MASTER

> **Current code/acceptance boundary — 2026-11-06.** `src/whaxon/core/findings.py` defines typed findings and parser routines; `core/report.py` provides Markdown, JSON, HTML and PDF paths; web and CLI report/evidence endpoints exist. Bounded G04 report/coverage acceptance is frozen at PR #138 merge `20198b3`; PR #142 established the client-facing engagement HTML/PDF baseline, and PR #144 expanded it to the current engagement and per-job reports at `edb427be5449ba511d91a53becee169a2967b0f9`, from exact head `28543e33e9a7480086728f019330d78693754303`, with exact-head CI run `42249696631` passing 20/20 jobs. This validates recorded report rendering and safety regressions; it does **not** establish independently witnessed evidence custody, every scanner in customer environments, an external audit trust anchor, or production readiness. Historical design sections below remain historical.

**Canonical findings/reporting/evidence lifecycle reference, consolidated 2026-11-05.** Preserve raw evidence, provenance, verification state and deterministic authorization. Design proposals are not released features. Data retention requirements and evidence integrity remain binding where applicable, independent of the consolidation.

- Part 1: findings.md
- Part 2: reports-and-evidence.md
- Part 3: report-redesign.md
- Part 4: report-visual-design.md
- Part 5: DATA_RETENTION.md

---


## Current engagement report rendering — 2026-11-06

The engagement HTML template and PDF path now render the same server-populated report content. The report presents engagement/client/preparer/classification metadata; recorded job and target counts; unique findings and observations; severity and verification summaries; prioritized finding cards with raw evidence, remediation, job attribution, and recorded CVE/CVSS/EPSS/KEV or reproduction details; persisted coverage gaps; job history; and explicit interpretation limits. Empty reports explain that no findings in the record do not prove that targets are vulnerability-free.

The standalone HTML is designed for desktop viewing and print-to-PDF; it supports finding search and source-JSON export. PR #142 had introduced a responsive browser layout; PR #144 removed its mobile/responsive breakpoint, consistent with the current desktop-only operator instruction. Dynamic report values are escaped for HTML, while the embedded JSON escapes tag delimiters; placeholder substitution is single-pass so user-controlled text cannot expand template tokens. Regression coverage includes populated and empty reports, PDF content, coverage and provenance, XSS payloads across report sections, and literal template tokens. The report can only describe recorded data; it does not create an external evidence trust anchor, prove unrecorded checks, or verify findings independently. Historical sections below preserve their original design proposals and dated implementation descriptions.

**Business-impact implementation source:** [technical severity/cost design](business-impact.md), implemented alongside `src/whaxon/core/business_impact.py` and severity/reporting code. Cost bands are not verified losses for any particular client.

## Part 1 — findings.md

# Findings

Findings are structured records extracted from tool output by an adapter.

## Shape

Every finding is a whaxon.core.findings.Finding:

- kind (str): discriminator, e.g. open_port, ntlm_hash, smb_share, impacket_loot
- severity (str): critical / high / medium / low / info
- source (str): adapter that produced it (usually the tool id)
- raw_line (str): original source output line; the Finding dataclass does not impose a universal truncation limit
- data (dict): structured payload, adapter-specific
- cvss (float or None): CVSS base score
- cwe (str): CWE id, e.g. CWE-522
- impact (str): business impact text
- remediation (str): remediation advice
- references (tuple[str, ...]): reference URLs
- lookup_hint (str): optional search hint for a later lookup
- request_context (dict): optional request metadata for deterministic validation/retest

## Lifecycle

1. Adapter returns list[Finding] from parse().
2. Runner publishes JobFindings(job_id, findings=[...]) on the EventBus.
3. Store subscribes and persists each finding row, including structured data, raw line, references and request context. Verification and business-impact enrichment are stored alongside the base finding record.
4. Web UI renders findings as a color-coded expandable table.
5. Reports include findings grouped by severity; loot-kind findings go into Loot Summary.

## Kinds used today

- open_port          - nmap
- service            - nmap
- web_issue          - nikto
- sql_injection      - sqlmap
- dbms               - sqlmap
- smb_share          - impacket
- ntlm_hash          - impacket
- impacket_loot      - impacket
- cracked_hash       - hashcat
- msf_session        - msf
- exploit_suggestion - suggest
- burp_issue         - burp

Adapters can introduce new kinds freely - the store persists any string.

## Querying

- Per job: GET /api/jobs/<job_id>/findings
- Loot-only: GET /api/loot
- In reports: GET /api/report?format=md includes critical/high findings plus Loot Summary

## Severity ordering

Reports order severities critical -> high -> medium -> low -> info (_SEV_ORDER in whaxon.core.report).

---

## Part 2 — reports-and-evidence.md

# Reports & Evidence

## Reports

Two report shapes.

### Per-job

The CLI supports Markdown, HTML, PDF and JSON for a single job:

    whaxon report <job_id>                    # Markdown to stdout
    whaxon report <job_id> --format html      # HTML
    whaxon report <job_id> --format pdf       # PDF
    whaxon report <job_id> --format json      # JSON
    whaxon report <job_id> --out scan.md      # To file

HTTP: GET /api/jobs/<job_id>/report?format=md or `?format=html`.

### Engagement

Engagement reports support Markdown, HTML, PDF, JSON and the integrity-wrapped WHAXON JSON format. JSON and WHAXON output preserve the complete engagement dataset, including findings and job history. Markdown provides the executive summary, all-severity counts, loot, coverage, and job history; its detailed Technical Findings appendix includes critical/high findings by default, not every low/informational record. HTML/PDF use the engagement report renderer. The engagement report also includes pivot chains when available.

    curl -u whaxon:whaxon http://127.0.0.1:5001/api/report?format=md   > engagement.md
    curl -u whaxon:whaxon http://127.0.0.1:5001/api/report?format=json > engagement.json

Engagement Markdown structure:

- WHAXON Engagement Report header with scope, generated timestamp, counts
- Executive Summary - narrative paragraph, top-3 findings, recommended action
- Remediation Roadmap - findings grouped by urgency band, plus choke points
- Loot Summary - one table per loot kind
- Session Findings - findings from live sessions (if any)
- Attack Surface - pivot chains as a tree of sessions to hosts to loot (if any)
- Known Vulnerabilities - searchsploit cross-reference for lookup hints (if lookup enabled)
- AI Runs - summary of AI planner runs (if any)
- Appendix: Technical Findings - per-severity detail, each finding shows both technical severity and business impact
- Appendix: Job History - a table of every job

### Two severity scales

Each finding carries two severities:

- severity - the technical severity (critical / high / medium / low). Resolved from CVSS when the finding carries a CVE (source = nvd), otherwise adapter-assigned (source = adapter). The source is stored as severity_source on the finding.
- business_impact - a second scale answering what does this cost us. Computed deterministically at resolve time from the finding kind and the target production/lab status. Same vocabulary as severity. Cost-range tables and sources live in docs/business-impact.md.

Both scales render in the Technical Findings appendix as [severity / Business: business_impact], for example [critical / Business: high]. The executive brief ranks the top findings by business impact first, technical severity as tiebreaker. The Remediation Roadmap shifts a finding up one band when its business impact is higher than its technical severity.

Retroactive resolution: whaxon findings resolve re-resolves every stored finding and writes business_impact into the enrichment alongside severity and severity_source.

### Escaping

Per-job HTML report (render_html): Markdown is wrapped in a pre tag after being HTML-escaped. A finding whose raw_line contains a script tag cannot execute in a browser viewing the report. Guarded by tests/test_report.py::test_render_html_escapes_script_in_raw_line.

Engagement HTML report (to_html): Generates a standalone ui-v4 HTML file with inline CSS, inline vanilla JS, and the full engagement dict serialized as JSON in a script tag with type application/json. Every less-than character in the JSON is escaped as u003c, which cannot appear as a tag delimiter. Raw tool output cannot truncate the script block or inject markup.

Engagement PDF (to_pdf_bytes): Renders the same standalone ui-v4 HTML via weasyprint. Print CSS rules are embedded in the template for page-safe output.

Per-job PDF (render_pdf): Builds a job-shaped report dict and routes through to_pdf_bytes, so per-job and engagement PDFs share the same renderer.

## Evidence

Evidence attaches notes or files to any job.

    whaxon evidence <job_id> --note Confirmed weak ciphers
    whaxon evidence <job_id> --add screenshot.png
    whaxon evidence <job_id>                 # List

HTTP:

- GET    /api/jobs/<job_id>/evidence                 - list
- POST   /api/jobs/<job_id>/evidence                 - add note or upload
- DELETE /api/jobs/<job_id>/evidence/<seq>           - remove
- GET    /api/jobs/<job_id>/evidence/<seq>/download  - stream file

Evidence is persisted in SQLite (evidence table) and referenced from reports.

---

## Part 3 — report-redesign.md

# Report redesign

**Status (2026-11-02): HISTORICAL IMPLEMENTATION DESIGN.** The PR sequence records the report-redesign rationale and plan at the time. It is not an active PR plan and its problem statements are not assertions about the current report. For current behavior, use [Reports and Evidence](#part-3--report-redesignmd), current report source/tests and the master roadmap's release gates.
**Owner:** andreipath
**Depends on:** docs/reports-and-evidence.md
**Non-goals:** does not change the finding model, does not add new adapters.

---

## Why

At the time this design was drafted, the report was not considered a client deliverable. Four concrete failures:

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

---

## Part 4 — report-visual-design.md

# Report visual design — PR 4

**Status (2026-11-02): HISTORICAL DESIGN RECORD.** This file preserves the original visual specification and PR planning notes. It is not a live design task or proof that every visual requirement is currently implemented. Compare the current report renderer and tests with [Reports and Evidence](#part-4--report-visual-designmd); acceptance remains subject to the master roadmap's release gates.
**Owner:** andreipath.
**Depends on:** docs/report-redesign.md §4, docs/reports-and-evidence.md.
**Non-goals:** this doc does not design the in-app report preview, the reports store, or the past-reports menu. Those are follow-on units (named at the end) and get their own design docs. It does not change the report data model.

---

## 1. Two surfaces, two purposes

The report is rendered for two surfaces with different audiences.

**PDF — for print and email.** A client-facing deliverable. Someone prints it and hands it across a table, or attaches it to an email. It must look like a finished product: a cover page, running header and footer, page numbers, restrained print-safe colour, charts that survive greyscale, and page-break rules that keep sections from splitting awkwardly.

**HTML — for screen.** Opened in a browser, standalone. It looks like it belongs to the WHAXON product: the same palette, type scale, spacing, and card treatment as the ui-v4 web interface. It is not a markdown dump wrapped in `<pre>`.

Both render from the same report dict. Both are generated from the same section list. They differ in chrome, colour mode, and page behaviour.

## 2. Shared source

- Input: the report dict from `_load` in `core/report.py`.
- Section order is defined once: header, executive brief, remediation roadmap, loot, session findings, attack surface, known vulnerabilities, AI runs, appendix: technical findings, appendix: job history.
- `to_markdown` is unchanged. It remains the text path for CLI output and anything that consumes markdown directly.
- The two new renderers consume the report dict directly. They do not parse the markdown.

## 3. Design tokens

The ui-v4 design system is defined in `src/whaxon/interfaces/web/static/style.css`, in the `:root` block. It is the source of truth for both surfaces.

**HTML** uses the tokens as they are. The report document embeds a `<style>` block with the same tokens plus report-specific rules. Dark theme.

**PDF** uses a print variant of the same tokens. A light background, a darker accent, and severity colours adjusted for legibility on white and in greyscale. The mapping:

| Token | Screen (HTML) | Print (PDF) |
|---|---|---|
| --bg | #0a0a0f | #ffffff |
| --bg-elev | #111118 | #f8f8fa |
| --bg-elev-2 | #16161f | #f0f0f4 |
| --text | #f2f2f5 | #1a1a24 |
| --text-dim | #a8a8b8 | #4a4a56 |
| --text-mute | #6a6a7a | #6a6a7a |
| --border | rgba(255,255,255,0.06) | rgba(0,0,0,0.10) |
| --border-strong | rgba(255,255,255,0.12) | rgba(0,0,0,0.18) |
| --accent | #8b5cf6 | #7c3aed |
| --critical | #ef4444 | #dc2626 |
| --high | #f97316 | #ea580c |
| --medium | #eab308 | #ca8a04 |
| --low | #22c55e | #16a34a |
| --info | #64748b | #475569 |

Type and spacing scale are identical between surfaces; only the luminance changes. `--font-sans` and `--font-mono` resolve on any Linux or Mac system, so no web font is loaded and no font is embedded in the PDF beyond weasyprint defaults.

## 4. PDF layout

Page sequence:

1. **Cover page.** WHAXON wordmark (text). Engagement name. Client name (from `data/scope.json`, optional). Prepared by (from `data/whaxon.env`, optional). Date generated. Classification marking.
2. **Executive brief.** The narrative summary and the top-3 findings, re-ranked by business impact.
3. **Remediation roadmap.** Findings grouped by urgency band, plus the choke points subsection.
4. **Findings.** The critical and high findings, as cards.
5. **Appendices.** Technical findings by severity, then job history, then known vulnerabilities. Raw tool output is monospaced, wrapped, and page-break-safe.

**Running header and footer.** Every page except the cover has a footer: classification marking on the left, engagement name centred, page number on the right.

**Page-break rules.** The cover, executive brief, roadmap, and findings each start a new page. Within a section, a finding card does not split across pages. The appendix may split at finding boundaries, never mid-line.

**Print colour.** Severity chips render with a solid background and white text, or a white background with a coloured border, whichever stays legible in greyscale. The donut uses the print palette; segment labels carry the severity name and count so the chart is readable without colour.

## 5. HTML layout

A single standalone document. It embeds the ui-v4 tokens (dark) and report rules in a `<style>` block. It does not load external CSS or JS.

Structure:

1. **Header.** Engagement name, generated timestamp, job and finding counts, severity summary.
2. **Executive brief.** Same content as the PDF, styled as a card.
3. **Remediation roadmap.** Urgency-band sections, each a card.
4. **Findings.** Critical and high findings, one card each.
5. **Appendices.** Collapsible by `<details>`: technical findings by severity, job history, known vulnerabilities. Raw tool output in monospace, escaped.

No JavaScript. No interactivity beyond `<details>`.

## 6. Finding cards

Both surfaces render one finding as a card. Shared structure:

- A severity chip: technical severity and, when present, business impact. Format: `[critical / Business: high]`.
- A title line: the finding's raw line, wrapped and escaped.
- A meta line: target, tool, seen count, CVE if present.
- The evidence body: remediation guidance, lookup hint, or full raw line for the appendix view.

**PDF card.** Solid border in the severity colour from the print palette. Slight background tint from the `-dim` variant. No shadows. Page-break-inside: avoid.

**HTML card.** `border-radius: var(--r-lg)`, `background: var(--bg-elev)`, `border: 1px solid var(--border)`, `box-shadow: var(--shadow-sm)`. The severity chip is filled from the `-dim` token with text in the `-line` token.

## 7. Charts

**Severity donut.** Rendered as inline SVG in both surfaces. Segments coloured by severity. Labels carry severity name and count so the chart is readable without colour. Diameter: 200px in HTML, 120pt in PDF.

**Trend line.** Deferred until the store records finding history over time. Not in this unit.

**ATT&CK coverage matrix.** Deferred. Not in this unit.

No chart library. A donut is arithmetic and an SVG path.

## 8. Appendix formatting

Rules:

- Rendered inside `<pre>` in HTML, with `white-space: pre-wrap` and `word-break: break-word`.
- Rendered in `--font-mono` at `--t-sm` in HTML, `10pt` in PDF.
- Every byte HTML-escaped before insertion (existing test preserved).
- Non-printable characters replaced with a visible placeholder or stripped.
- Line length capped at 200 characters with a continuation marker.

## 9. Escaping and safety

Every value in the report that comes from tool output is treated as untrusted. HTML and PDF both escape before insertion.

- HTML: `html.escape` on every raw line, every finding field, every lookup hint.
- PDF: the HTML that weasyprint renders is already escaped.
- `test_report.py::test_render_html_escapes_script_in_raw_line` continues to apply.
- New tests added for PDF text extraction.

## 10. Configuration additions

Two fields added to `data/scope.json`:

- `client` — optional string, empty by default.
- `classification` — optional string, default `Confidential`.

One field added to `data/whaxon.env`:

- `WHAXON_REPORT_PREPARED_BY` — optional string, empty by default.

All optional. Existing engagement files read cleanly with defaults. No migration.

`to_pdf_bytes(report, overrides=None)` gains an optional `overrides` dict. Keys: `client`, `classification`, `prepared_by`. Any value takes precedence over config.

## 11. Test plan

- **HTML snapshot.** Fixed report dict, compared against stored snapshot.
- **PDF magic bytes.** `render_pdf` output starts with `%PDF-`.
- **PDF text extraction.** Assert engagement name, a finding title, classification, page number appear.
- **Escaping (HTML).** Existing test preserved. Add script-tag cases for remediation and lookup_hint.
- **Escaping (PDF).** Script tag in raw line must not appear as executable markup, must not disrupt generation.
- **Config fallback.** No client or classification renders with defaults.
- **Page-break sanity.** Many findings produce multiple pages.
- **Donut rendering.** HTML contains `<svg>` with expected segment count.

## 12. Dependencies

None new. Jinja2 via Flask. weasyprint is the PDF path. Inline SVG by a helper. For tests, `pypdf` may be added as a dev dependency in the same commit (R48 applies to dependency additions).

## 13. Follow-on units (not in PR 4)

**Unit 2 — reports store.** New SQLite table `reports(id, engagement, job_id, format, path, created_at, size_bytes)`. Every generated report written to `data/reports/<engagement-slug>/<filename>` and recorded. Own design doc.

**Unit 3 — past-reports menu.** New page in ui-v4 shell, new API routes to list and stream stored reports. Uses the LESSONS §14 page-wiring pattern. Own design doc.

**Unit 4 — in-app report preview.** Report page shows HTML report inside app chrome. Own design doc.

## 14. Cold resume

- Repo at HEAD when this doc was written: `f8c024b`.
- Tag: `v0.10.0`.
- Tests at HEAD: 689 passing under `.venv/bin/pytest`.
- This document is a design, not an implementation.
- After this doc: PDF renderer, HTML renderer, tests, CHANGELOG, roadmap, PR.

---

## Part 5 — DATA_RETENTION.md

# Data Handling and Retention

**Status reviewed 2026-11-02.** This is an operational guide, not a legal opinion, a certification statement, or a claim that WHAXON enforces a retention schedule. Set applicable retention rules in the engagement contract and under the law that applies to the data and parties.

## 1. Data WHAXON may persist

The default data directory is `data/`; an operator may select another path. Depending on enabled features and the engagement, persistent data may include:

| Data | Typical location | Notes |
|---|---|---|
| Scope and authorization configuration | `data/scope.json` | Application-level scope policy |
| Jobs and lifecycle state | `data/whaxon.db` | SQLite database |
| Raw tool output | `lines` table in SQLite | May contain hostnames, paths, banners, tokens or other sensitive output |
| Findings and verification state | `findings` and related tables | Payloads and request context may contain sensitive target data |
| Evidence metadata | `evidence` table | Referenced files may be stored separately from SQLite |
| AI run history | `ai_runs` and `ai_run_steps` tables | Prompts, proposed actions and results may contain target data |
| Scope override records | `data/scope_overrides.log` | Authorization and operator decision trail |
| Logs, exports and reports | Operator-configured paths | May contain copies of findings and raw evidence |

The exact paths depend on the configured data directory, evidence handling, logging and export choices. Backups, copied reports and uploaded evidence must be inventoried separately.

## 2. Sensitive information

Do not assume findings, raw output, request context, evidence, logs or reports are automatically scrubbed. A tool can return credentials, session tokens, personal data or other secrets; those values may be persisted as part of raw output or a finding. Redaction of recognized secret-valued settings is not a general-purpose sanitizer for engagement evidence.

Use dedicated lab credentials, restrict filesystem permissions, avoid collecting unnecessary data, and inspect exports before sharing them. If a real credential is captured, treat it as exposed and rotate it through the system owner.

## 3. External services and AI providers

Local persistence does not mean every enabled operation is offline. When a cloud AI provider is explicitly configured, WHAXON sends the prompt and context needed for that provider to generate a planning response. External tools and optional integrations may also communicate with their own services or target systems. Review each provider's data terms and configure only services approved for the engagement. The default AI provider is `null`; no AI planning provider is selected unless configured and enabled.

## 4. Retention and deletion

WHAXON does not impose a universal engagement-retention period or guarantee automatic deletion of every copy. The operator must define the schedule based on the engagement contract, applicable law, client policy and backup requirements.

At engagement close:

1. Export and deliver only the approved report and evidence.
2. Identify the configured WHAXON data directory, separately stored evidence, logs, exports and reports.
3. Retain only records required by the agreed schedule; protect archives with appropriate access controls and encryption.
4. When retention expires, stop WHAXON and remove the relevant data and separately stored copies using the organization's approved deletion process.
5. Account for backups, snapshots, cloud-provider retention, endpoint backups and removable media. Deleting the active directory does not delete those copies.
6. Record what was deleted, when, by whom and which backup-retention exceptions remain.

Removing a row or evidence reference through an API is not proof that every underlying file or backup copy has been securely erased. Do not claim secure erasure unless the storage medium and deletion process have been independently verified.

## 5. Operator responsibility

The operator is responsible for lawful authorization, data minimization, access control, encryption, backup protection, retention decisions, disclosure to clients and deletion verification. This document does not establish PASSI compliance or prescribe a legally required 30-day or one-year retention period.

## 6. References

- [ANSSI — PASSI certification](https://cyber.gouv.fr/offre-de-service/certification-des-prestataires-daudit-de-securite-informatique/)
- [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [French Penal Code, Article 323-1](https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000006418292)

