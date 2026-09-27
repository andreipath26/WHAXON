# Demo Script

A 90-second scripted walkthrough. Every command is copy-pasteable. Use a Metasploitable2 VM at 10.0.0.42 or substitute your own authorised target.

## 0:00 - Setup (off camera)

    cd whaxon
    source .venv/bin/activate
    whaxon serve --daemon
    xdg-open http://127.0.0.1:5001/ui

Browser opens on the WHAXON web UI. Login whaxon / whaxon.

## 0:10 - Scope check

Open a terminal beside the browser. Run:

    whaxon scope --show

WHAXON is fail-closed. Everything outside RFC1918 is refused by default. The scope decision is a file, not a UI toggle.

## 0:20 - Run a tool

In the browser, pick nmap from the catalog. Target: 10.0.0.42. Hit Run. Output streams in; findings render below.

The adapter turned nmap output into structured findings: open ports, service fingerprints, severity. Everything the report will need.

## 0:35 - A correlated finding

When the nmap job finishes, the correlator fires. A correlated finding appears: web_service on port 80 or exposed_service on 139/445.

The correlator noticed a pattern across findings - a web port plus a service fingerprint - and produced a single finding that says more than the parts.

## 0:45 - The AI planner

In the terminal:

    WHAXON_AI_ENABLED=true WHAXON_AI_PROVIDER=ollama WHAXON_AI_MODEL=qwen2.5:1.5b whaxon ai "assess 10.0.0.42 for open web services" --target 10.0.0.42

Steps print one per line - each showing the tool it chose and why. The target lock prevents the model from scanning anything else.

The AI never executes anything. It proposes an action. The executor validates every proposal against the catalog, the scope, and a target lock before a single process starts.

## 1:05 - Reports

Back in the browser, click Export PDF (or run in terminal):

    JID=$(curl -s -u whaxon:whaxon http://127.0.0.1:5001/api/history | python3 -c "import sys,json;print(json.load(sys.stdin)[0][chr(39)+chr(105)+chr(100)+chr(39)])")
    whaxon report "$JID" --format pdf --out /tmp/demo.pdf
    xdg-open /tmp/demo.pdf

A rendered PDF report opens with executive summary, findings table, and remediation.

The whole engagement - discoveries, correlations, suggestions, remediation advice - in one PDF.

## 1:20 - Cleanup

    kill "$(cat data/whaxon.pid)" && rm -f data/whaxon.pid

WHAXON - one platform, every layer of security.

## Tips for recording

- Terminal: 14pt monospace, dark theme, cursor hidden while typing.
- Browser: 1400x900 viewport, hide bookmarks bar.
- Timing: cut nothing; keep the whole thing under 2 minutes.
- Voice: script it, then record audio separately; sync in post.
