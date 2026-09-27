# HTTP API

Base: http://127.0.0.1:5001. Every /api/* endpoint requires HTTP Basic auth (WHAXON_AUTH_USER / WHAXON_AUTH_PASS). UI routes (/, /ui, /settings) use the same auth.

Defaults: whaxon:whaxon. Change via environment variables before exposing the port.

## Health and status

- GET /api/health      - liveness, unauthenticated
- GET /api/status      - counters, MSF status

## Tools

- GET /api/tools       - catalog + availability

## Jobs

- POST   /api/run                              - body: {tool_id, target, extra_args} -> {job_id}
- GET    /api/jobs/<job_id>                    - job + lines
- GET    /api/jobs/<job_id>/stream             - SSE: job_started, job_output, job_finished, job_findings
- POST   /api/jobs/<job_id>/cancel             - kill the subprocess
- GET    /api/jobs/<job_id>/findings           - findings array
- GET    /api/jobs/<job_id>/report             - per-job report (?fmt=md or ?fmt=html)
- GET    /api/jobs/<job_id>/evidence           - list evidence
- POST   /api/jobs/<job_id>/evidence           - add note / upload
- DELETE /api/jobs/<job_id>/evidence/<seq>     - remove
- GET    /api/jobs/<job_id>/evidence/<seq>/download  - stream file

## History and reports

- GET /api/history                     - recent jobs
- GET /api/report?fmt=md - engagement report, includes pivot chains
- GET /api/loot                        - loot-kind findings
- GET /api/tree                        - session tree

## Scope

- GET  /api/scope              - current config
- POST /api/scope/check        - body: {target} -> {allowed, reason}
- POST /api/scope/override     - body: {target, reason} -> allow once, logged

## Metasploit

- GET    /api/msf/status                       - RPC reachable?
- GET    /api/msf/sessions                     - active sessions
- POST   /api/msf/run                          - body: {module, options}
- POST   /api/msf/sessions/<id>/exec           - run a command in a session
- GET    /api/msf/sessions/<id>                - session detail
- GET    /api/msf/modules/<module_type>        - search modules
- GET    /api/msf/sessions/<id>/portfwd        - list forwards
- POST   /api/msf/sessions/<id>/portfwd        - add forward
- DELETE /api/msf/sessions/<id>/portfwd        - remove forward

## Pivot

- GET /api/pivot/graph                       - full graph
- GET /api/pivot/sessions/<id>/chain         - chain rooted at a session
- GET /api/pivot/candidates                  - auto-detected pivot candidates

## Import and settings

- POST /api/import/burp     - multipart upload of Burp XML
- GET  /api/settings        - current settings
- POST /api/settings        - update settings

## UI

- GET /           - redirect to /ui
- GET /ui         - browser UI
- GET /settings   - settings page

## Examples

    curl http://127.0.0.1:5001/api/health

    curl -u whaxon:whaxon http://127.0.0.1:5001/api/tools | python3 -m json.tool

    RESP=$(curl -s -u whaxon:whaxon -H Content-Type:application/json -X POST http://127.0.0.1:5001/api/run -d tool_id=impacket,target=10.10.10.20,extra_args=secretsdump)
    JID=$(echo $RESP | python3 -c import sys json; print json.load sys.stdin job_id)

    curl -u whaxon:whaxon http://127.0.0.1:5001/api/jobs/$JID/findings

    curl -u whaxon:whaxon http://127.0.0.1:5001/api/report?fmt=md

    curl -u whaxon:whaxon -X POST http://127.0.0.1:5001/api/jobs/$JID/cancel