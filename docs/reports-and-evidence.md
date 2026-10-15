# Reports & Evidence

## Reports

Two report shapes.

### Per-job

Markdown or HTML for a single job plus its findings.

    whaxon report <job_id>                    # Markdown to stdout
    whaxon report <job_id> --format html      # HTML
    whaxon report <job_id> --out scan.md      # To file

HTTP: GET /api/jobs/<job_id>/report?format=md or ?format=html

### Engagement

Markdown or JSON covering every job and finding, plus the loot summary and pivot chains.

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

HTML report output escapes markdown before wrapping in pre. A finding whose raw_line contains script tag cannot execute in a browser viewing the report. Guarded by tests/test_report.py::test_render_html_escapes_script_in_raw_line.

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