# Proof A — DVWA, four tools

**Status:** verified. Committed artifacts are the reports, not the store.

## What this is

A clean four-tool run against a local DVWA container. Proves recon through findings: nmap finds port 80, nikto/gobuster/ffuf enumerate, the correlator fires web_service. It does NOT prove initial access, validation, coverage disclosure, or retest — those are §32 work.

## Target

DVWA (vulnerables/web-dvwa), container IP 172.17.0.3, port 80. Authorized: local container, owned and operated by the tester.

## Regenerate

One command per line, in order:

1. mkdir -p data/proof-dvwa && cp data/tools.json data/proof-dvwa/tools.json
2. write data/proof-dvwa/scope.json with engagement, enabled true, in_scope [172.17.0.3], out_of_scope [], notes
3. .venv/bin/whaxon run nmap 172.17.0.3 --data data/proof-dvwa --extra "-sV -F"
4. .venv/bin/whaxon jobs drain --data data/proof-dvwa
5. .venv/bin/whaxon run gobuster 172.17.0.3 --data data/proof-dvwa
6. .venv/bin/whaxon run ffuf 172.17.0.3 --data data/proof-dvwa

Then the reports, per job id and engagement, in md/html/json.

## Artifacts

15 report files, four jobs, 45 findings, one web_service correlation. The store (whaxon.db) is gitignored — regenerate it with the commands above.
