# Documentation assets

This directory contains historical screenshots and UI-v4 design references. They are not all screenshots of the current runtime UI and must not be presented as proof of current functionality.

## Current inventory

| File pattern | Status | Use |
| --- | --- | --- |
| `screenshot-ui-v4-*.png` | Design references | UI concept only; not live engagement data |
| `screenshot-old-ui.png` | Historical screenshot | Archive/reference only |
| `screenshot-02.png` through `screenshot-14.png` | Historical captures | Verify against the current runtime before publishing |
| `dvwa-findings.png`, `engagement-nikto.png`, `engagement-report.png`, `engagement-webui.png` | Historical engagement captures | Verify target ownership and redact sensitive information before publishing |

## Release screenshot requirements

Before release marketing uses a screenshot as evidence of current behavior:

1. Capture it from the current commit's running application.
2. Use only a local lab or an explicitly authorized target.
3. Remove secrets, credentials, session identifiers, and personal data.
4. Label mock data and design references clearly.
5. Replace or remove any image whose provenance cannot be confirmed.

Current-runtime screenshots have not yet been captured and verified for this audit.
