## 2026-10-30 (UI Pass 2 - live Attack Surface graph and session interaction)

**Added**
- Replaced the hardcoded Attack Surface SVG with a live graph loaded from `GET /api/pivot/graph`.
- Exploit, session, and forwarding nodes are laid out from persisted pivot edges; edges show their relationship type.
- Nodes support pointer and keyboard selection and expose their connected relationships. Empty and request-error states are explicit.
- Sessions now distinguish live from stored/closed sessions. Live sessions expose an explicit command form backed by `POST /api/msf/sessions/<id>/exec`; stored sessions are read-only.
- Added API and Playwright browser coverage for graph data, rendering, empty state, node inspection, refresh, live/stored sessions, and command output.

**Fixed**
- Removed duplicate Retest, Sessions, and Catalog page loader blocks that issued duplicate requests and could overwrite one another's results.
- Session command and session metadata are rendered with text nodes rather than interpolated HTML.

