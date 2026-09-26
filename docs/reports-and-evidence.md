# Reports & Evidence

## Reports

A report is a formatted summary of a single job.

### CLI

    whaxon report 5fae0b1b36f4
    whaxon report 5fae0b1b36f4 --format html
    whaxon report 5fae0b1b36f4 --out scan-report.md
    whaxon report 5fae0b1b36f4 --format html --out scan-report.html

### Web

    curl -u whaxon:whaxon http://127.0.0.1:5001/api/jobs/5fae0b1b36f4/report
    curl -u whaxon:whaxon "http://127.0.0.1:5001/api/jobs/5fae0b1b36f4/report?format=html" > report.html

### TUI

Select a History row, press s. Report saved to
~/.local/share/whaxon/reports/<job_id>.md

### GUI

Right-click a History item -> Save report (Markdown or HTML).

### Report contents

- Job metadata (id, tool, target, status, duration, exit code)
- Findings summary (count by severity)
- Per-finding detail
- Full raw output

## Evidence

Evidence is anything attached to a job: notes, screenshots, saved dumps.

Two kinds:

    note    Only text in the database
    file    Stored at data/evidence/<job_id>/<name>

### CLI

    whaxon evidence 5fae0b1b36f4
    whaxon evidence 5fae0b1b36f4 --note "Confirmed weak ciphers"
    whaxon evidence 5fae0b1b36f4 --add ~/Desktop/screenshot.png
    whaxon evidence 5fae0b1b36f4 --rm 2

### Web API

    JOB=5fae0b1b36f4

    curl -u whaxon:whaxon http://127.0.0.1:5001/api/jobs/$JOB/evidence

    curl -u whaxon:whaxon -X POST http://127.0.0.1:5001/api/jobs/$JOB/evidence \
         -H "Content-Type: application/json" \
         -d '{"note": "Confirmed weak ciphers on port 22"}'

    curl -u whaxon:whaxon -X POST http://127.0.0.1:5001/api/jobs/$JOB/evidence \
         -F "file=@screenshot.png" \
         -F "note=Port scan result"

    curl -u whaxon:whaxon -O -J http://127.0.0.1:5001/api/jobs/$JOB/evidence/1/download

    curl -u whaxon:whaxon -X DELETE http://127.0.0.1:5001/api/jobs/$JOB/evidence/1

### GUI

Right-click a History item -> Add note.

### Backup

Evidence files are in data/evidence/. Back up that directory and
data/whaxon.db together.
