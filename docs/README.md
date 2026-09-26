# WHAXON User Documentation

Welcome to the WHAXON user guide.

## Contents

| Document | What it covers |
| --- | --- |
| [Getting Started](getting-started.md) | Install, first launch, first scan |
| [Interfaces](interfaces.md) | TUI, GUI, Web - which to use when |
| [Tools](tools.md) | The tool catalog and how to add your own |
| [Findings](findings.md) | How WHAXON parses output into findings |
| [Reports & Evidence](reports-and-evidence.md) | Export results, attach notes/files |
| [Troubleshooting](troubleshooting.md) | Common problems and fixes |

## Quick reference

    whaxon tui                              # Terminal interface
    whaxon gui                              # Desktop interface
    whaxon web                              # Web (http://127.0.0.1:5001/ui)
    whaxon report <job_id>                  # Markdown report
    whaxon report <job_id> --format html    # HTML report
    whaxon evidence <job_id>                # List evidence
    whaxon evidence <job_id> --note "text"  # Add a note
    whaxon evidence <job_id> --add file.png # Attach a file
