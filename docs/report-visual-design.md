# Report visual design — PR 4

**Status:** draft, active.
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