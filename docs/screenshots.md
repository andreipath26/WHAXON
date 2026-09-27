# Screenshot & Demo Capture Guide

Everything here is for you to execute. Nothing is auto-generated.

## Prerequisites

- A live WHAXON instance with a few jobs in the store
- A target you own (Metasploitable2 in a VM is ideal)
- A 1400x900 or larger display

## Terminal capture (TUI)

    whaxon tui

Wait for the catalog to populate, then press / and type nmap. The filtered catalog is the shot.

- File: docs/assets/tui.png
- Alt text: WHAXON terminal UI showing the filtered tool catalog.
- Dark theme, no cursor visible. Use gnome-screenshot --interactive or flameshot and crop to the terminal window only.

## Web UI capture

    whaxon serve --daemon
    xdg-open http://127.0.0.1:5001/ui

Run nmap against your target from the UI. Wait for findings to appear, expand one finding, then capture.

- File: docs/assets/web-ui.png
- Alt text: WHAXON web interface showing a live nmap job and expanded findings.

## Desktop capture

    whaxon gui

Wait for the embedded web view to load, then capture the whole window.

- File: docs/assets/gui.png
- Alt text: WHAXON desktop application rendering the same web UI.

## PDF report capture

    JID=$(curl -s -u whaxon:whaxon http://127.0.0.1:5001/api/history | python3 -c "import sys,json;print(json.load(sys.stdin)[0][chr(39)+chr(105)+chr(100)+chr(39)])")
    whaxon report "$JID" --format pdf --out /tmp/report.pdf
    xdg-open /tmp/report.pdf

Capture the executive summary page.

- File: docs/assets/report-pdf.png
- Alt text: Exported WHAXON PDF report showing the executive summary.

## Pivot chain capture

Requires at least one pivot edge in the store. Run an exploit through MSF, add a port forward, then open the Chain tab in the web UI.

- File: docs/assets/pivot-chain.png
- Alt text: WHAXON pivot chain graph: exploit, session, forward.

## Demo GIF

A 20-40 second loop showing one workflow end to end. Record with peek or byzanz, then convert:

    ffmpeg -i raw.mp4 -vf "fps=12,scale=900:-1" -loop 0 docs/assets/demo.gif

- File: docs/assets/demo.gif
- Alt text: WHAXON demo: run nmap, view findings, export a PDF report.

## After capture

1. Move every file into docs/assets/ with the exact filename above.
2. Run: git add docs/assets/*.png docs/assets/*.gif
3. Reference them from README and docs by relative path.
4. Commit with: docs: add screenshots
