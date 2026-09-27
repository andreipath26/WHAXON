# Reports & Evidence

## Reports

Two report shapes.

### Per-job

Markdown or HTML for a single job plus its findings.

    whaxon report <job_id>                    # Markdown to stdout
    whaxon report <job_id> --format html      # HTML
    whaxon report <job_id> --out scan.md      # To file

HTTP: GET /api/jobs/<job_id>/report?fmt=md or ?fmt=html

### Engagement

Markdown or JSON covering every job and finding, plus the loot summary and pivot chains.

    curl -u whaxon:whaxon http://127.0.0.1:5001/api/report?fmt=md   > engagement.md
    curl -u whaxon:whaxon http://127.0.0.1:5001/api/report?fmt=json > engagement.json

Engagement Markdown structure:

- WHAXON Engagement Report header with scope, generated timestamp, counts
- Executive Summary - severity counts
- Critical Findings / High Findings - detail for the top two severities
- Loot Summary - one table per loot kind
- Pivot Chains - if any pivot edges exist, a tree of sessions to hosts to loot
- Job History - a table of every job

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