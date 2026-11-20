# Engine V2 legacy execution inventory

This inventory records Python callsites that invoke `run_tool` or
`run_in_session` directly. It is guarded by
`tests/test_engine_v2_legacy_callsite_inventory.py`: adding, removing, or moving
a callsite requires reviewing its execution path and updating the classification.

| Source | Caller | Classification | Notes |
| --- | --- | --- | --- |
| `interfaces/web/server.py` | `_run_job_blocking` | Legacy | `/api/run`; scope checked, but no persisted V2 request or task lease. |
| `core/ai_bridge.py` | `_run_tool`, `build_executor._run_in_session` | Legacy | Used only by legacy `/api/ai/run` and explicit `whaxon ai --legacy` execution/resume; approvals remain in legacy `ai_runs`. The separate `propose_v2_workflow_plan` path creates reviewable plan tasks and does not dispatch. |
| `ai/executor.py`, `ai/providers/*` | Executor/provider actions | Legacy | Indirect callbacks still dispatch through `ToolRunner`. |
| `interfaces/cli/run_cmd.py` | default proposal path / `main._go` | Mixed; default V2 plan-only | `whaxon run <tool> <target>` saves a provider-pinned review plan after scope/readiness checks; it does not approve or execute. `--v2-plan` submits a durable run request for a previously persisted plan; the supervised worker owns dispatch. Direct ToolRunner and session transports require explicit `--legacy`; there is no V2-to-legacy fallback. |
| `core/worker.py` | `drain_async` | Legacy compatibility path | One-shot `run --legacy` drains only follow-ups caused by that invocation; long-lived `Core.initialize(drain=True)` leaves legacy rows pending unless `WHAXON_LEGACY_QUEUE_DRAIN_ENABLED=true`. Legacy auto-chain work remains outside workflow-plan authorization. |
| `interfaces/gui/main_window.py` | `_run_tool` | Legacy; dormant module; explicit opt-in | The shipped `whaxon-gui` entry point is `interfaces.gui.app:main` and embeds `/ui-v2`; repository search found no import of this older widget. The module remains packaged for import compatibility, but direct ToolRunner dispatch is blocked unless `WHAXON_LEGACY_GUI_EXECUTION_ENABLED=true`. |
| `interfaces/tui/screens/main.py` | catalog Run handoff / workflow screen | Engine V2 workflow client | Catalog Run opens V2 authoring with tool and target prefilled. The workflow screen proposes fixed-tool and sealed-evidence plans, reviews task bindings, records per-task approval, submits durable requests, reconnects and requests cancellation through shared Core services. No direct ToolRunner call remains in the TUI. |
| `core/providers.py` | `dispatch` | Engine V2 | Canonical provider dispatch after workflow authorization and scheduler checks. |

The legacy routes already apply scope checks and tool validation. Their remaining
gap is lifecycle and policy parity: workflow-bound authorization, durable request
identity, task leases, plan-bound approval, cancellation, reconnect, and recovery.
This inventory is evidence of caller coverage, not a claim that those controls
are absent from every legacy path or that a migration is safe.

The workflow CLI also provides `plan propose-tool` for supported catalog tools.
It creates a fixed-argument, provider-pinned review proposal only after current
scope and provider readiness checks. Saving remains explicit; approval and
execution are separate commands. The default `whaxon run <tool> <target>` now
uses this proposal path and persists the plan; unsupported/session transports
remain available through explicit `--legacy` dispatch only.

`plan propose-verification` similarly prepares V2 verify/retest plans for
supported SQLi and reflected-XSS findings. The selected verifier rechecks the
source job's V2 execution marker, evidence seal, exact finding sequence, target,
and prior verification state for retests. This is a separate route for eligible
V2 evidence. Legacy CLI/API validator entry points now refuse V2-owned evidence
before sending a request or mutating its finding; legacy job behavior remains.
This does not add unsupported validator kinds or finish full validator client
parity.

The V2 Run builder admits the fixed-input, moderate-impact
`dns.recon.passive` provider when it is installed and selected. Its plan is
provider-pinned and remains unapproved and undispatched until the operator
reviews, approves, and submits it. Target preview uses the DNS-query scope
policy and accepts hostnames only; generic target checks retain the stricter
execution policy. The CLI also provides
`whaxon workflow plan propose-dns-recon --mission-id M --id P --target HOST`
with optional `--save`. The recon providers expose fixed-plan proposals for
headers, robots and `security.txt`; `propose-headers-recon` and
`propose-security-txt-recon` create pinned, unapproved plans for one fixed HTTPS
request each. `propose-redirect-recon` creates a pinned, unapproved plan for
one HTTPS GET to `/`; it records response status and a redacted first-hop
Location display and never follows that Location. This is not redirect-chain
parity. Proposal creation never dispatches network work.

Additional execution actions need their own semantic inventory. CLI passive
recon and legacy-job CLI/API validate/retest callers still use dedicated legacy
services rather than `ToolRunner`. A separate V2 provider now covers
only sealed-finding SQLi verification/retest under a plan-bound contract; this
does not migrate those legacy callers or cover the other validator kinds.

## Dedicated network-service entry points

These paths can perform network work without calling `ToolRunner`. The
callsite guard pins their current production entry points separately from the
runner inventory.

| Source | Caller | Service path | Scope/consent boundary | Persistence and V2 status |
| --- | --- | --- | --- | --- |
| `interfaces/cli/recon_cmd.py` | default proposal / `--engine v2 --plan-id` / explicit `--legacy` | Default creates one fixed multi-provider plan and never dispatches; approved saved V2 plans use Core workflow services; legacy `core.recon.run` is behind `--legacy` plus `WHAXON_LEGACY_RECON_ENABLED=true` | Each included task is preflighted by its provider proposal and remains unapproved until the operator grants exact task consent. Explicit selections block if any requested provider is unsupported or unavailable. | V2 task attempts and evidence use the shared workflow store. `tech`, `cookies`, and `waf` remain legacy-only; a default plan lists them as omitted and does not claim full recon parity. |
| `interfaces/cli/validate_cmd.py` | `main` | `Validator.validate` | V2-owned evidence is refused before target replay; legacy jobs still require target and active scope. | Legacy job updates remain in `JobStore`; V2 verification uses the plan-bound provider path. |
| `interfaces/cli/retest_cmd.py` | `main` | `Validator.revalidate` → `Validator.validate` | V2-owned evidence is refused before replay; legacy findings still require prior verification and current scope. | Legacy job updates remain in `JobStore`; V2 retest uses the plan-bound provider path. |
| `interfaces/web/server.py` | `create_app.api_validate` | `Validator.validate` | V2-owned jobs receive HTTP 409 before replay; legacy jobs still pass `_validation_scope_error` before the probe. | Legacy job updates remain in `JobStore`; V2 verification uses the plan-bound provider path. |
| `interfaces/web/server.py` | `create_app.api_retest` | `Validator.revalidate` → `Validator.validate` | V2-owned jobs receive HTTP 409 before replay; legacy findings still require prior verification and current scope. | Legacy job updates remain in `JobStore`; V2 retest uses the plan-bound provider path. |
| `interfaces/web/server.py`, `adapters/msf.py` | `create_app.msf_run._do_run` → `MSFAdapter.run_module` | `MSFClient.execute` (module and optional auto-chain post modules) | The MSF route validates module/target inputs and checks target scope before enqueueing its worker. This direct adapter path is not a `ToolRunner` dispatch. The optional post-module auto-chain is not plan-bound V2 dispatch. | Persists job output/findings through `JobStore`; no V2 workflow task, lease, attempt or cancellation record. Keep separate from catalog tools routed through `ToolRunner`. |
| `interfaces/web/server.py` | `create_app.msf_session_exec` | `MSFClient.session_exec` | `_msf_session_scope_error` resolves the session host and checks current scope before sending the supplied session command. | Returns output directly; no V2 task/attempt record or durable workflow evidence link. |
| `core/runner.py` | `run_in_session` → `_run_msf_session` | `MSFClient.session_exec` | Runner requires a persisted open session, authorizes its stored host, re-reads the live RPC session and authorizes its host, rejects host identity drift, and enforces a required session type when available before dispatch. | Emits legacy job events and stores capped output; this session-scoped execution path is not scheduler-owned V2 workflow dispatch. |

The legacy CLI/API validator paths remain separate from the bounded V2 provider.
For SQLi, the current replay uses three baseline and three injected samples
and verifies only when a specific SQL parser error appears consistently after
the quote probe. Missing proof, network failure and timing-only signals remain
`candidate`; legacy retest reports those as `inconclusive`. The SQLi path has
no `refuted` result, so it cannot currently establish `fixed`. Existing
validator tests use synthetic HTTP fixtures; they do not replace a seeded-lab
validation run for the scheduler-owned provider.

`Validator.revalidate` calling `self.validate` is an internal service delegation,
not a second external dispatch. The dedicated tests currently include
`test_recon.py`, `test_validate_cmd.py`, `test_validator_retest.py`,
`test_validator_security_regressions.py`, and `test_web_trust_layer.py`. UI tests exercise client requests but are not the route-level security evidence cited here.
These prove selected service and route behavior; they do not establish
cross-client V2 parity, durable workflow ownership, operator consent, or
deployment acceptance. Keep the service paths classified as legacy until a
separate capability mapping and migration with rollback evidence is accepted.

## Adapter subprocess ownership

`HashcatAdapter.run_module` and `ImpacketAdapter.run_module` contain direct
subprocess hooks, but repository callsite search found no callers for either
hook. The only direct `adapter.run_module(...)` invocation is in the MSF route,
which resolves the MSF adapter. Do not treat the Hashcat/Impacket hooks as
reachable execution paths until a caller is added and its authorization owner
is reviewed. Current Impacket catalog and SMB/WMI session execution goes through
`ToolRunner`, which applies target/scope checks before dispatch.

## Packaged catalog and Engine V2 admission

The packaged catalog contains 24 tool IDs across five declared transports:
17 `cli`, three `msf_session`, two `smb`, one `ssh`, and one `wmi`. The V2
catalog bridge admits 12 of the CLI entries. For each admitted entry it creates
both a `tool.<id>` compatibility capability and one stable semantic operation
alias. These aliases share the same local-process provider, fixed catalog argv,
`network.scan` permission, moderate impact, network-traffic/service-log side
effects, scope and approval checks, and ToolRunner dispatch. Dynamic task
arguments are unsupported; a successful tool exit is not independent
verification.

| Catalog IDs | V2 status | Transport and reason |
| --- | --- | --- |
| `arjun`, `dig`, `dnsrecon`, `ffuf`, `gobuster`, `nikto`, `nmap`, `nuclei`, `sqlmap`, `theharvester`, `whois`, `wpscan` | Admitted | `cli` → `local_process`, provider-bound; target-type allowlist applies. |
| `commix`, `echo`, `hydra`, `impacket`, `netexec` | Not admitted | `cli`; no Engine V2 provider admission. Some have legacy adapters. |
| `msf_getuid`, `msf_hashdump`, `msf_sysinfo` | Unsupported in V2 | `msf_session`; requires a separately accepted session provider. |
| `smb_ls`, `smb_shares` | Unsupported in V2 | `smb`; requires a separately accepted session provider. |
| `ssh_cmd` | Unsupported in V2 | `ssh`; no registered adapter in the inspected runtime. |
| `wmi_exec` | Unsupported in V2 | `wmi`; requires a separately accepted session provider. |

Exact V2 operation aliases and declared target types:

| Tool | Compatibility capability | Semantic capability | Target types |
| --- | --- | --- | --- |
| `arjun` | `tool.arjun` | `web.parameters.discover` | URL |
| `dig` | `tool.dig` | `dns.records.query` | Hostname |
| `dnsrecon` | `tool.dnsrecon` | `dns.records.enumerate` | Hostname |
| `ffuf` | `tool.ffuf` | `web.paths.fuzz` | URL |
| `gobuster` | `tool.gobuster` | `web.directories.enumerate` | Hostname, IP |
| `nikto` | `tool.nikto` | `web.server.audit` | Hostname, IP, URL |
| `nmap` | `tool.nmap` | `network.services.discover` | Hostname, IP |
| `nuclei` | `tool.nuclei` | `web.templates.assess` | URL |
| `sqlmap` | `tool.sqlmap` | `web.sql_injection.assess` | URL |
| `theharvester` | `tool.theharvester` | `osint.domain.contacts.search` | Hostname |
| `whois` | `tool.whois` | `domain.registration.lookup` | Hostname, IP |
| `wpscan` | `tool.wpscan` | `web.wordpress.audit` | URL |

The separately bound HTTP verifier adds four V2-only operations outside the
local-process catalog table:

| Capability | Provider | Target and permission | Supported contract | Readiness |
| --- | --- | --- | --- | --- |
| `tool.verify_sqli` | `whaxon.verifier.http` (`v2-sqli-xss-verifier.1`) | IP-literal HTTP(S) URL; `network.verify`; moderate impact | A successful same-target Engine V2 SQLi finding with an intact workflow evidence seal; separate exact-plan approval; fixed quote probe; scope reload before each request; redirects and changed paths blocked; result stored as a separate sealed job. | Registered; smoke, lab and end-to-end flags remain false. |
| `tool.retest_sqli` | `whaxon.verifier.http` (`v2-sqli-xss-verifier.1`) | IP-literal HTTP(S) URL; `network.verify`; moderate impact | Requires a prior V2 `verified` result from `tool.verify_sqli`; reports `still_vulnerable` or `inconclusive`, never `fixed` when proof is absent; separate exact-plan approval and sealed result job. | Registered; smoke, lab and end-to-end flags remain false. |
| `tool.verify_xss` | `whaxon.verifier.http` (`v2-sqli-xss-verifier.1`) | IP-literal HTTP(S) URL; `network.verify`; moderate impact | A successful same-target Engine V2 reflected-XSS finding with an intact workflow evidence seal; separate exact-plan approval; unique non-destructive SVG console probe; scope reload before each request; redirects and changed paths blocked; result stored as a separate sealed job. | Registered; smoke, lab and end-to-end flags remain false. |
| `tool.retest_xss` | `whaxon.verifier.http` (`v2-sqli-xss-verifier.1`) | IP-literal HTTP(S) URL; `network.verify`; moderate impact | Requires a prior V2 `verified` result from `tool.verify_xss`; reports `still_vulnerable` or `inconclusive`, never `fixed` when proof is absent; separate exact-plan approval and sealed result job. | Registered; smoke, lab and end-to-end flags remain false. |

These operations require separate plans because their source job and finding
sequence must already exist when each task is authorized. The provider supports
SQLi and reflected-XSS validation only; timing and observation validators are
not registered. IP literals avoid DNS rebinding in the current urllib transport;
hostname verification remains unsupported until the transport pins the
validated destination address.

The built-in adapter registry also reports four adapter-only IDs—`burp`,
`hashcat`, `msf`, and `whatweb`—without packaged catalog entries. The prior
V2 allowlist declared `whatweb` even though no catalog item could bind it. The
allowlist and semantic alias map now exclude that stale declaration; the
catalog/transport guard will fail if the shipped catalog or admitted set drifts
without explicit G01 review. `echo` and `ssh_cmd` are catalog entries without a
registered adapter. Portfolio classification for non-admitted tools does not
replace this separate adapter-presence fact.

### Read-only live snapshot

The earlier local portfolio audit reported 24 catalog entries and 26 discovered
adapters: 12 bound, five not admitted, seven unsupported transports, and four
adapter-only. That snapshot preceded the two verifier operations. The current
Core inventory includes 12 compatibility capabilities, 12 semantic aliases,
and the two registered verifier operations; the verifier's smoke, lab and
end-to-end flags remain false. The earlier snapshot found **zero executable
providers**, with all 12 admitted binaries absent from that environment. These
are environment-specific readiness observations, not claims about a deployment
host. The audit command is read-only and explicitly does not enable execution.
A same-session executable preflight also found no Docker CLI
and none of the 12 admitted binaries (`arjun`, `dig`, `dnsrecon`, `ffuf`,
`gobuster`, `nikto`, `nmap`, `nuclei`, `sqlmap`, `theharvester`, `whois`,
`wpscan`) on this workspace host. No scanner, container or network operation
was attempted. This host therefore cannot supply the required controlled-lab
execution evidence; deployment-host readiness remains unverified.

### Client and service boundary summary

| Client surface | V2 path | Existing legacy path | Durable owner / relevant evidence |
| --- | --- | --- | --- |
| CLI workflow | `whaxon run`, default `whaxon ai`, default `whaxon recon`, and `whaxon workflow` use shared `Core` workflow/proposal/approval/provider services; `recon --engine v2 --plan-id` submits a durable request for an approved fixed recon plan | `whaxon run --legacy`, `whaxon ai --legacy`, `recon --legacy`, `validate`, and `retest` retain compatibility paths; `whaxon msf` only inspects status/sessions/modules | Default recon saves one reviewable plan from ready fixed providers, reports omitted checks, and never approves or dispatches. Explicit check selections fail as a unit if any check is unsupported or unavailable. Legacy recon requires both `--legacy` and `WHAXON_LEGACY_RECON_ENABLED=true`. V2 plans, approvals, requests, tasks, events and evidence use `JobStore`/`WorkflowRunQueue`; see `test_recon_v2_cli.py`, `test_engine_v2_recon_plan_proposal.py`, `test_workflow_cli.py`, `test_workflow.py`, `test_workflow_run_requests.py`, and `test_providers.py`. |
| HTTP API and web clients | `/api/v2/ai/proposals`, `/api/v2/workflow-proposals`, workflow lifecycle APIs and V2 AI, Findings, BAS, Retest and Approvals clients use shared Core services | `/api/run`, `/api/ai/run`, `/api/ai/runs/<id>/answer`, `/api/msf/run`, `/api/msf/sessions/<id>/exec`, `POST /api/msf/sessions/<id>/portfwd`, `/api/validate`, `/api/retest` remain separate legacy paths for older clients; gates are route-specific | `/api/run` and legacy AI execution/answer routes are default-denied unless respectively `WHAXON_LEGACY_TOOL_EXECUTION_ENABLED=true` and `WHAXON_LEGACY_AI_EXECUTION_ENABLED=true`. MSF module launch, session commands, and port-forward creation require `WHAXON_LEGACY_MSF_EXECUTION_ENABLED=true`; port-forward DELETE remains available for cleanup. Validate/retest are gated by `WHAXON_LEGACY_VALIDATION_ENABLED=true` for legacy evidence and still reject V2-owned evidence before replay. V2 clients do not call legacy executor, answer, validation or retest mutations; proposals and approvals remain separate from submission. |
| Headless service | `whaxon serve` plus `whaxon workflow plan serve-requests` | Legacy worker/Automator follow-ups remain separate and do not auto-drain by default | V2 worker claims durable requests; see `test_workflow_continuous_worker.py`, E5 systemd and Docker tests. Legacy queue drain requires `WHAXON_LEGACY_QUEUE_DRAIN_ENABLED=true`. |
| Native desktop and terminal | `whaxon-gui` embeds `/ui-v2`; TUI workflow screen and catalog Run-to-plan handoff use shared V2 workflow services | The unreferenced older `interfaces/gui/main_window.py` retains direct `Core.runner` calls behind `WHAXON_LEGACY_GUI_EXECUTION_ENABLED=true`; no TUI catalog legacy action remains | The legacy gate has explicit default-deny coverage. Desktop destination/root-route behavior is covered by `test_gui_entrypoint.py`; see also `test_tui_main.py`. Clean-wheel desktop launch and broader UI acceptance remain open. |

### Consequential HTTP route ownership

`test_api_route_methods_and_handlers_are_explicit` pins the method, path and
handler binding for all Flask `/api/*` routes, including read/status/export
routes. The matrix below summarizes consequential ownership and authorization
boundaries; it does not claim to guard UI controls.

A static decorator census currently finds 104 `/api/*` method/path bindings,
22 distinct `/ui-v2/*` page handlers with 23 route aliases, and five other
health/root/settings/favicon routes in `interfaces/web/server.py`. The matrix below covers consequential
execution, authorization-state, cancellation and provisioning routes. This census makes every method/path/handler binding reviewable. It does not replace the handler-family semantics, persistence, access-control or test evidence mapped below; those remain bounded and are not inferred from route registration.
The UI page/control inventory is frozen and is not being edited here.

The UI route aliases below are recorded as an Engine V2 caller crosswalk; this
is not UI acceptance or authorization to change the frozen pages.

| Method | Exact route | Handler |
| --- | --- | --- |
| `GET` | `/ui-v2` | `ui_v2_home` |
| `GET` | `/ui-v2/dashboard` | `ui_v2_home` |
| `GET` | `/ui-v2/run` | `ui_v2_run` |
| `GET` | `/ui-v2/findings` | `ui_v2_findings` |
| `GET` | `/ui-v2/scope` | `ui_v2_scope` |
| `GET` | `/ui-v2/report` | `ui_v2_report` |
| `GET` | `/ui-v2/reports` | `ui_v2_reports` |
| `GET` | `/ui-v2/history` | `ui_v2_history` |
| `GET` | `/ui-v2/diagnostics` | `ui_v2_diagnostics` |
| `GET` | `/ui-v2/evidence` | `ui_v2_evidence` |
| `GET` | `/ui-v2/ai` | `ui_v2_ai` |
| `GET` | `/ui-v2/retest` | `ui_v2_retest` |
| `GET` | `/ui-v2/chains` | `ui_v2_chains` |
| `GET` | `/ui-v2/adapters` | `ui_v2_adapters` |
| `GET` | `/ui-v2/settings` | `ui_v2_settings` |
| `GET` | `/ui-v2/audit` | `ui_v2_audit` |
| `GET` | `/ui-v2/monitoring` | `ui_v2_monitoring` |
| `GET` | `/ui-v2/bas` | `ui_v2_bas` |
| `GET` | `/ui-v2/bug-bounty` | `ui_v2_bug_bounty` |
| `GET` | `/ui-v2/compliance` | `ui_v2_compliance` |
| `GET` | `/ui-v2/ptaas` | `ui_v2_ptaas` |
| `GET` | `/ui-v2/threat-intel` | `ui_v2_threat_intel` |
| `GET` | `/ui-v2/approvals` | `ui_v2_approvals` |

#### Exact Flask API method/path/handler census

The following index lists every one of the **105** `/api/*` decorator bindings
from the AST guard. It is a binding census, not a security approval: GET routes
are reads/status/exports; POST and DELETE routes may mutate state or dispatch
work, as classified in the family tables below. Handler source and the cited
test family remain authoritative for side effects and access-control limits.

| Method | Exact path | Handler | Owning state/service |
| --- | --- | --- | --- |
| `GET` | `/api/ai/pending` | `ai_pending_list` | Legacy AI run state/executor |
| `POST` | `/api/ai/run` | `ai_run` | Legacy AI run state/executor |
| `GET` | `/api/ai/runs` | `ai_runs_list` | Legacy AI run state/executor |
| `GET` | `/api/ai/runs/<run_id>` | `ai_run_get` | Legacy AI run state/executor |
| `POST` | `/api/ai/runs/<run_id>/answer` | `ai_run_answer` | Legacy AI run state/executor |
| `GET` | `/api/ai/runs/<run_id>/stream` | `ai_run_stream` | Legacy AI run state/executor |
| `POST` | `/api/approvals/<job_id>/<int:seq>/resolve` | `api_approval_resolve` | Legacy finding review state |
| `POST` | `/api/bounty/import` | `import_bounty_program` | Bounty import/review draft |
| `GET` | `/api/coverage/<job_id>` | `api_coverage` | Legacy coverage records |
| `GET` | `/api/dependencies` | `api_dependencies_get` | Local dependency/readiness or installer service |
| `GET` | `/api/dependencies/audit` | `api_dependencies_audit_get` | Local dependency/readiness or installer service |
| `GET` | `/api/dependencies/drift` | `api_dependencies_drift_get` | Local dependency/readiness or installer service |
| `GET` | `/api/dependencies/history` | `api_dependencies_history_get` | Local dependency/readiness or installer service |
| `POST` | `/api/dependencies/install` | `api_dependencies_install` | Local dependency/readiness or installer service |
| `POST` | `/api/dependencies/install-batch` | `api_dependencies_install_batch` | Local dependency/readiness or installer service |
| `GET` | `/api/dependencies/install/<operation_id>` | `api_dependencies_install_status` | Local dependency/readiness or installer service |
| `POST` | `/api/dependencies/install/<operation_id>/cancel` | `api_dependencies_install_cancel` | Local dependency/readiness or installer service |
| `POST` | `/api/dependencies/plan` | `api_dependencies_plan` | Local dependency/readiness or installer service |
| `POST` | `/api/dependencies/snapshots` | `api_dependencies_snapshot_post` | Local dependency/readiness or installer service |
| `POST` | `/api/dependencies/verify` | `api_dependencies_verify_post` | Local dependency/readiness or installer service |
| `GET` | `/api/health` | `health_probe` | Runtime diagnostics |
| `GET` | `/api/health/simple` | `health_simple` | Runtime diagnostics |
| `GET` | `/api/history` | `list_history` | Legacy job history |
| `POST` | `/api/import/burp` | `import_burp` | Legacy imported finding/evidence store |
| `GET` | `/api/jobs/<job_id>` | `get_job` | Legacy JobStore, evidence and job registry |
| `POST` | `/api/jobs/<job_id>/cancel` | `cancel_job` | Legacy JobStore, evidence and job registry |
| `GET` | `/api/jobs/<job_id>/evidence` | `list_evidence` | Legacy JobStore, evidence and job registry |
| `POST` | `/api/jobs/<job_id>/evidence` | `add_evidence` | Legacy JobStore, evidence and job registry |
| `DELETE` | `/api/jobs/<job_id>/evidence/<int:seq>` | `delete_evidence` | Legacy JobStore, evidence and job registry |
| `GET` | `/api/jobs/<job_id>/evidence/<int:seq>/download` | `download_evidence` | Legacy JobStore, evidence and job registry |
| `GET` | `/api/jobs/<job_id>/findings` | `get_job_findings` | Legacy JobStore, evidence and job registry |
| `GET` | `/api/jobs/<job_id>/findings.csv` | `download_findings_csv` | Legacy JobStore, evidence and job registry |
| `GET` | `/api/jobs/<job_id>/findings.json` | `download_findings_json` | Legacy JobStore, evidence and job registry |
| `GET` | `/api/jobs/<job_id>/output.txt` | `download_output_txt` | Legacy JobStore, evidence and job registry |
| `GET` | `/api/jobs/<job_id>/report` | `get_report` | Legacy JobStore, evidence and job registry |
| `GET` | `/api/jobs/<job_id>/stream` | `stream_job` | Legacy JobStore, evidence and job registry |
| `GET` | `/api/jobs/active` | `list_active_jobs` | Legacy JobStore, evidence and job registry |
| `GET` | `/api/loot` | `api_loot` | Legacy report, finding or loot view |
| `GET` | `/api/msf/modules/<module_type>` | `msf_list_modules` | Legacy Metasploit RPC/session service |
| `POST` | `/api/msf/run` | `msf_run` | Legacy Metasploit RPC/session service |
| `GET` | `/api/msf/sessions` | `msf_sessions` | Legacy Metasploit RPC/session service |
| `GET` | `/api/msf/sessions/<session_id>` | `msf_session_info` | Legacy Metasploit RPC/session service |
| `POST` | `/api/msf/sessions/<session_id>/exec` | `msf_session_exec` | Legacy Metasploit RPC/session service |
| `DELETE` | `/api/msf/sessions/<session_id>/portfwd` | `pf_del` | Legacy Metasploit RPC/session service |
| `GET` | `/api/msf/sessions/<session_id>/portfwd` | `pf_list` | Legacy Metasploit RPC/session service |
| `POST` | `/api/msf/sessions/<session_id>/portfwd` | `pf_add` | Legacy Metasploit RPC/session service |
| `GET` | `/api/msf/status` | `msf_status` | Legacy Metasploit RPC/session service |
| `GET` | `/api/pivot/candidates` | `api_pivot_candidates` | Legacy pivot/session graph |
| `GET` | `/api/pivot/graph` | `api_pivot_graph` | Legacy pivot/session graph |
| `GET` | `/api/pivot/sessions/<session_id>/chain` | `api_pivot_chain` | Legacy pivot/session graph |
| `GET` | `/api/report` | `api_report` | Legacy report, finding or loot view |
| `POST` | `/api/retest/<job_id>/<int:seq>` | `api_retest` | Default-denied unless `WHAXON_LEGACY_VALIDATION_ENABLED=true`; when enabled, legacy Validator handles legacy jobs and V2 jobs still fail closed before replay |
| `POST` | `/api/run` | `run_tool` | Legacy ToolRunner and JobStore |
| `GET` | `/api/scope` | `get_scope` | Scope policy service/configuration |
| `POST` | `/api/scope` | `save_scope` | Scope policy service/configuration |
| `POST` | `/api/scope/check` | `check_scope` | Scope policy service/configuration |
| `POST` | `/api/scope/override` | `log_override` | Scope policy service/configuration |
| `POST` | `/api/v2/scope/check` | `check_v2_authoring_scope` | Capability-aware authoring scope preview; scheduler rechecks before execution |
| `GET` | `/api/settings` | `api_settings_get` | Application settings store |
| `POST` | `/api/settings` | `api_settings_post` | Application settings store |
| `GET` | `/api/status` | `api_status` | Runtime diagnostics |
| `GET` | `/api/tools` | `list_tools` | Packaged catalog advertisement |
| `GET` | `/api/tree` | `get_tree` | Legacy report, finding or loot view |
| `GET` | `/api/ui-v2/findings` | `api_ui_v2_findings` | Legacy finding/evidence API adapter |
| `GET` | `/api/v2/capabilities` | `workflow_v2_capabilities` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/ai/proposals` | `workflow_v2_ai_proposal` | AI Action to V2 workflow proposal; optional immutable plan persistence; no approval or execution |
| `POST` | `/api/v2/workflow-proposals` | `workflow_v2_workflow_proposal` | Fixed-argument tool or evidence-bound verification plan proposal; optional immutable plan persistence; no approval or execution |
| `GET` | `/api/v2/missions` | `workflow_v2_missions` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/missions` | `workflow_v2_missions` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/missions/<mission_id>/budget` | `workflow_v2_mission_budget` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/missions/<mission_id>/budget` | `workflow_v2_mission_budget` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/missions/<mission_id>/cost` | `workflow_v2_mission_cost` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/missions/<mission_id>/cost` | `workflow_v2_mission_cost` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/missions/<mission_id>/deadline` | `workflow_v2_mission_deadline` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/missions/<mission_id>/plans` | `workflow_v2_mission_plans` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/missions/<mission_id>/report` | `workflow_v2_mission_report` | Ordered mission-level, evidence-bound report; partial status is preserved |
| `GET` | `/api/v2/missions/<mission_id>/rate-limit` | `workflow_v2_mission_rate_limit` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/missions/<mission_id>/rate-limit` | `workflow_v2_mission_rate_limit` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/providers` | `workflow_v2_providers` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/providers/portfolio-audit` | `workflow_v2_portfolio_audit` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflow-runs/<request_id>` | `workflow_v2_run_request_status` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflow-runs/<request_id>/cancel` | `workflow_v2_cancel_run_request` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflow-runs/<request_id>/snapshot` | `workflow_v2_run_snapshot` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflow-runs/summary` | `workflow_v2_run_queue_summary` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflows` | `workflow_v2_save_plan` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>` | `workflow_v2_plan_details` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/approvals` | `workflow_v2_approvals` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflows/<plan_id>/approvals` | `workflow_v2_approvals` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/approval-queue` | `workflow_v2_approval_queue` | Bounded pending/blocked moderate+ V2 tasks with exact approval state for the V2 Approvals UI |
| `POST` | `/api/v2/workflows/<plan_id>/approvals/<approval_id>/revoke` | `workflow_v2_revoke_approval` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/attempts` | `workflow_v2_attempts` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/audit` | `workflow_v2_audit` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflows/<plan_id>/cancel` | `workflow_v2_cancel` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflows/<plan_id>/followups` | `workflow_v2_followups` | Evidence-sealed, scope-checked follow-up proposal; optional plan persistence without approval or execution |
| `POST` | `/api/v2/workflows/<plan_id>/deadline` | `workflow_v2_set_deadline` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflows/<plan_id>/event-ack` | `workflow_v2_event_ack` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/event-inbox` | `workflow_v2_event_inbox` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/events` | `workflow_v2_events` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/evidence` | `workflow_v2_evidence` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/limits` | `workflow_v2_limits` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflows/<plan_id>/limits` | `workflow_v2_set_limits` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/progress` | `workflow_v2_progress` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflows/<plan_id>/rate-limit` | `workflow_v2_set_rate_limit` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/report` | `workflow_v2_plan_report` | Evidence-scoped persisted plan report; never implies release approval |
| `GET` | `/api/v2/workflows/<plan_id>/audit-snapshot` | `workflow_v2_audit_snapshot` | Read-only lifecycle digest; not an independent anchor |
| `GET` | `/api/v2/workflows/<plan_id>/readiness` | `workflow_v2_readiness` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflows/<plan_id>/audit-verify` | `workflow_v2_audit_verify` | Compare caller-retained digest without claiming third-party anchoring |
| `POST` | `/api/v2/workflows/<plan_id>/reconcile` | `workflow_v2_reconcile` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/reconciliation` | `workflow_v2_reconciliation` | Core workflow registry, stores and lifecycle services |
| `GET` | `/api/v2/workflows/<plan_id>/resources` | `workflow_v2_resources` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflows/<plan_id>/run` | `workflow_v2_run` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/v2/workflows/attempts/<attempt_id>/cost` | `workflow_v2_attempt_cost` | Core workflow registry, stores and lifecycle services |
| `POST` | `/api/validate/<job_id>/<int:seq>` | `api_validate` | Default-denied unless `WHAXON_LEGACY_VALIDATION_ENABLED=true`; when enabled, legacy Validator handles legacy jobs and V2 jobs still fail closed before replay |

| Route group | Paths and owner | Authorization/effect boundary | V2 ownership and evidence |
| --- | --- | --- | --- |
| V2 capability and lifecycle | `GET /api/v2/capabilities`, `/providers`, `/providers/portfolio-audit`; `POST /api/v2/workflows`; `POST /api/v2/workflows/<plan_id>/run`; `POST /api/v2/workflow-runs/<request_id>/cancel` | Core capability registry, workflow contracts, approvals and durable request queue. A run submission is persisted work, not a success result. | Shared Core path; see `test_server_workflow_v2.py`, `test_workflow_run_requests.py`, and `test_workflow.py`. |
| Legacy tool and AI dispatch | `POST /api/run` → `_run_job_blocking`; `POST /api/ai/run` → legacy AI executor/bridge; `POST /api/ai/runs/<run_id>/answer` → legacy resume | `/api/run` is default-denied unless `WHAXON_LEGACY_TOOL_EXECUTION_ENABLED=true`; request-field, extra-argument, scope, and catalog checks precede this gate and remain prerequisites when enabled. `/api/ai/run` validates goal/target and scope before its `WHAXON_LEGACY_AI_EXECUTION_ENABLED=true` gate; the answer/resume route applies that gate before parsing the answer or looking up the run. None creates V2 plan-bound task attempts. | Legacy path; see `test_server.py`, `test_server_ai.py`, runner and AI bridge tests. |
| Legacy Metasploit | `POST /api/msf/run`; `POST /api/msf/sessions/<session_id>/exec` | Both are default-denied unless `WHAXON_LEGACY_MSF_EXECUTION_ENABLED=true`; module path validates inputs and scope before worker dispatch. Session command checks live session scope before RPC. | Legacy job/session paths; no V2 task/attempt lifecycle. |
| Metasploit pivot forwarding | `GET`, `POST`, and `DELETE /api/msf/sessions/<session_id>/portfwd` | GET inspects; POST creation is gated by `WHAXON_LEGACY_MSF_EXECUTION_ENABLED=true` and checks session plus destination scope; DELETE cleanup remains available and checks the session host. | Network/pivot side effects remain outside V2 task ownership. See `test_server_portfwd.py` and scope-denial cases in `test_server.py`. |
| Verification and human resolution | `POST /api/validate/<job_id>/<seq>`; `POST /api/retest/<job_id>/<seq>`; `POST /api/approvals/<job_id>/<seq>/resolve` | Validate/retest default-deny before finding reads, replay or mutation unless `WHAXON_LEGACY_VALIDATION_ENABLED=true`; with opt-in, they recheck current target scope and retest requires existing verified status. V2-owned evidence remains rejected before replay. The separate resolve route writes verified/refuted state using a caller-supplied display label; it is not a plan-bound V2 approval. | Validator routes are legacy and not scheduler-owned. Route trust-boundary evidence includes `test_web_trust_layer.py`, `test_validator_retest.py`, and `test_server.py`. |
| V2 authoring scope preview | `POST /api/v2/scope/check` | Uses the selected capability's target policy for authoring feedback; passive DNS requires a hostname and DNS-query scope. This preview does not authorize or dispatch a task. | Core scheduler and the supervised DNS child recheck current scope before execution. |
| Scope policy | `GET`, `POST /api/scope`; `POST /api/scope/check`; `POST /api/scope/override` | Scope POST persists rules and requires explicit confirmation to disable enforcement. Scope check evaluates a target. Override only writes a legacy audit-style record; it does not authorize dispatch. | Scope configuration feeds shared Core checks, but the legacy override record is not a V2 approval. See `test_web_scope.py`, `test_scope_failclosed.py`, and `test_server.py`. |
| Legacy job cancellation | `POST /api/jobs/<job_id>/cancel` | Calls `_cancel_job_blocking` for a legacy job process/event state. | Separate from durable V2 run-request and plan cancellation endpoints. Route-level lifecycle parity remains open under G05. |
| Dependency provisioning | `POST /api/dependencies/install`, `/install-batch`; `POST /api/dependencies/install/<operation_id>/cancel` | Runs only from a current approved install plan and uses separate OS/package-manager authority; this is system provisioning, not target assessment. | Outside workflow task dispatch. See `test_dependencies.py`, `test_dependency_installer.py`, and dependency server tests. |

The legacy `/api/tools` catalog and `/api/v2/capabilities` registry are different
advertisements: catalog presence is not V2 admission, and provider installation
does not prove smoke, lab, end-to-end or authorization acceptance.

### Read, status and export API semantics

The remaining HTTP GET surfaces are mapped by handler class below. Exact route
and handler names are pinned by the 104-binding AST guard; this table records
which state each family reads and what it cannot establish.

| API family | Handlers/routes | Data owner and truth limit | Existing evidence |
| --- | --- | --- | --- |
| V2 capabilities and providers | `/api/v2/capabilities`, `/providers`, `/portfolio-audit` | Core registries and inventory; registered, bound, installed and executable are distinct from smoke/lab/end-to-end acceptance. | `test_server_workflow_v2.py`, `test_providers.py` |
| V2 mission state | `/api/v2/missions`, `/missions/<id>/budget`, `/cost`, `/plans`, `/rate-limit` | Core mission, plan, budget and rate-limit records. Configuration/readiness is not execution. | `test_server_workflow_v2.py`, `test_workflow.py` |
| V2 run and plan state | `/api/v2/workflow-runs/summary`, `/workflow-runs/<id>`, `/snapshot`, `/workflows/<id>` | Durable run request, queue and workflow store. Queued, active, terminal and successful remain distinct; snapshots are not atomic cross-table reads. | `test_workflow_run_requests.py`, `test_server_workflow_v2.py` |
| V2 approval, attempts and proof | `/api/v2/workflows/<id>/approvals`, `/attempts`, `/audit`, `/event-inbox`, `/events`, `/evidence`, `/limits`, `/progress`, `/readiness`, `/reconciliation`, `/resources` | Core store and workflow integrity/readiness services; only persisted attempts/evidence count, unavailable cost/worker signals are not inferred. | `test_server_workflow_v2.py`, `test_workflow.py`, `test_engine_v2_e3_audit_semantic_integrity.py` |
| Health and advertised tools | `/api/health`, `/api/health/simple`, `/api/status`, `/api/tools` | Health checks database/data-dir writability and optional MSF status. When `WHAXON_V2_EXTERNAL_WORKER=1`, health also requires a fresh V2 worker heartbeat. Catalog rows and health do not prove V2 admission or assessment success. | `test_server.py`, `test_server_workflow_v2.py`, `test_engine_v2_e5_core_readiness.py` |
| Legacy AI, jobs and history | `/api/ai/pending`, `/api/ai/runs*`, `/api/jobs/active`, `/api/jobs/<id>`, `/history`, `/jobs/<id>/stream` | Legacy AI run records, JobRegistry, event bus and JobStore. These are not V2 plan/request status. | `test_server_ai.py`, `test_server.py` |
| Legacy findings, evidence and exports | `/api/coverage/<id>`, `/api/jobs/<id>/evidence*`, `/findings`, `/findings.csv`, `/findings.json`, `/output.txt`, `/report`, `/api/report`, `/api/loot`, `/api/tree`, `/api/ui-v2/findings` | Legacy finding/evidence/report stores and export serializers. Their presence does not establish V2 evidence-seal provenance or complete coverage. | `test_server.py`, `test_coverage.py`, `test_report.py`, `test_engine_v2_e3_audit_semantic_integrity.py` |
| MSF and pivot inspection | `/api/msf/status`, `/sessions`, `/sessions/<id>`, `/modules/<type>`, `/api/pivot/graph`, `/pivot/candidates`, `/pivot/sessions/<id>/chain` | Live RPC inventory and stored pivot graph. Session/module visibility is legacy capability discovery; derived pivot edges are not proof a path is executable or authorized. | `test_server_msf.py`, `test_server_portfwd.py`, `test_server.py` |
| Dependency readiness | `/api/dependencies`, `/audit`, `/history`, `/drift`, `/install/<operation_id>` | Local dependency report, snapshots and install-operation records. They do not establish target capability or Engine V2 workflow readiness. | `test_dependencies.py`, `test_dependency_installer.py`, dependency server tests |
| Scope and settings | `/api/scope`, `/api/settings` | Core scope and settings records. Scope configuration is policy input; settings output must preserve secret redaction. | `test_web_scope.py`, `test_scope_failclosed.py`, `test_server.py` |

The static inventory contains 40 V2 and 64 legacy `/api/*` method/path
bindings. The API remains mixed during migration: route presence does not imply
that the route delegates to V2, and legacy exports must not be presented as
V2-owned evidence.

### Remaining API mutations

| Mutation group | Paths and persisted state | Authority/truth limitation | Evidence |
| --- | --- | --- | --- |
| V2 mission and plan controls | Mission create, budget/cost/rate/deadline writes; plan approval grant/revoke, cancellation, reconciliation, event acknowledgement, attempt cost and plan limit/deadline/rate writes all delegate to Core workflow services and durable stores. | Approval `actor` and attempt-cost `source` are accepted from the request body; route tests establish binding and validation, not an authenticated principal or provider-origin proof. Reconciliation fences stale attempts as uncertain; it does not prove external work stopped or recovered. | `test_server_workflow_v2.py`, `test_workflow_run_requests.py`, `test_workflow.py` |
| Legacy AI answer | `POST /api/ai/runs/<run_id>/answer` writes the operator response to legacy AI-run state and may resume the legacy executor. | Not a V2 plan/task approval. The route ignores a client-supplied user identity and records its local actor behavior. | `test_server_ai.py::test_ai_run_answer_records_operator_response` |
| Legacy evidence mutation | `POST`/`DELETE /api/jobs/<job_id>/evidence[/<seq>]` writes/removes files and JobStore evidence rows. | Legacy job evidence, not V2 attempt-sealed evidence. | `test_server.py`, `test_server_ai.py` evidence note/delete cases |
| Bounty program import | `POST /api/bounty/import` fetches or parses source and returns a disabled review-required draft. | Ingestion only; draft is not persisted as authorization and does not activate testing. | `test_web_bounty_ingest.py`, `test_bounty_ingest.py` |
| Burp report import | `POST /api/import/burp` parses uploaded XML, creates a legacy job and persists imported findings. | User-supplied evidence import; no target dispatch and no V2 attempt/evidence seal. | `test_server.py::test_burp_import_route_persists_imported_findings`, plus invalid-upload cases |
| Dependency checks and local config | `POST /api/dependencies/verify`, `/snapshots`, `/plan` run bounded local checks, save a local snapshot, or create a remediation preview; `POST /api/settings` persists application settings. | Not target assessment or V2 capability execution. Settings are configuration state, not target authorization. | `test_dependencies.py`, `test_dependency_installer.py`, `test_server.py` settings/dependency cases |

The V2 and legacy mutations above have different actor, persistence and
evidence contracts. V2 approval and attempt-reconciliation routes derive their
audit actor from the local peer identity or the username on a Basic-auth request
that has passed the shared request gate; legacy `actor` body fields are ignored
for compatibility. A remote username identifies the configured authenticated
account, not a distinct role or independent approver. Attempt-cost `source`
remains caller-supplied metadata and is not provider-origin proof. The route map
is source/test traceability; unresolved trust and authorization acceptance
remains open under the relevant later gates and must not be inferred from route
registration alone.

### Deployment entry points and readiness semantics

| Entry point or report | Current source behavior | G01 limit |
| --- | --- | --- |
| `whaxon web` | `server.main` starts Flask's development server. | Development path; not the production serving mode. |
| `whaxon serve` | `interfaces/web/serve.py` starts Waitress in foreground; `--daemon` uses `os.fork` double-fork. | Daemon mode is Unix-specific in source; do not infer native Windows support from OS documentation. |
| systemd | `whaxon.service` uses Gunicorn with `create_app_factory()`; paired worker unit runs durable request polling. | Unit contract and CI are not a successful supported-host install or live worker verification. |
| `docker-compose.e5.yml` | Repository-source web and dedicated worker share `/data`; host-published port `5001` is bound to `127.0.0.1` (the app listens on `0.0.0.0` inside the container). | Distinct from root `docker-compose.yml`, which is the vulnerable lab target. Docker assets are excluded from sdist; this is a checkout/source deployment path. |
| Wheel/package | `pyproject.toml` exposes `whaxon`, `whaxon-tui`, and `whaxon-gui` and packages systemd units. | Installed TUI/GUI data directory behavior has not been reconciled with `WHAXON_DATA`; GUI startup also launches `whaxon serve --daemon`. Installed-wheel GUI/TUI acceptance remains unverified. |
| `/api/health` | `core_ready` means SQLite responds and the data directory is writable; Metasploit is reported as optional degraded state. With an external V2 worker configured, a fresh heartbeat after startup recovery is also required. | Does not prove scanner readiness, workflow approval, or assessment success. |
| `whaxon workflow providers`, `/api/v2/providers` | `executable=true` means local manifest/catalog binding plus installed binary. `smoke_tested`, `lab_validated`, and `end_to_end_verified` remain separate fields and currently false. | “Executable” does not mean authorized, smoke-tested, lab-validated, end-to-end verified, or production-ready. |
| `whaxon doctor` | `overall_status=READY` means required dependency checks are ready. | Does not establish service, worker, workflow or deployment acceptance. |

Top-level CLI modes from `src/whaxon/cli.py` are `setup`, `doctor`, `init`,
`up`, `down`, `serve`, `web`, `tui`, `gui`, `msf`, `bounty`, `scope`,
`install`, `suggest`, `burp-import`, `evidence`, `report`, `jobs`, `ai`,
`cve`, `vulndb`, `lookup`, `validate`, `retest`, `coverage`, `recon`,
`findings`, `run`, `workflow`, and `state`. `workflow` and the default `recon`
proposal path use Engine V2 capability and plan services. Of the assessment
commands, `run` and `ai` default to reviewable V2 plans; `recon` defaults to a
reviewable multi-provider plan containing ready fixed checks. Legacy recon
remains available only with `--legacy` plus
`WHAXON_LEGACY_RECON_ENABLED=true`. `validate` and `retest` remain conservative
legacy compatibility commands and do not dispatch for Engine V2 evidence;
`msf` is an inspection CLI, while module/session execution remains behind
web/runner legacy gates. Environment/bootstrap commands and read/report
commands do not become V2 assessment dispatch merely because they share the
`whaxon` binary.

Installed terminal and desktop paths need a separate packaging check: `WhaxonApp`
and `EmbeddedServer` derive their data directory from the checkout-relative
package path rather than `WHAXON_DATA`; GUI starts `serve --daemon`. Their source
checkout behavior therefore does not establish installed-wheel data-path or
daemon support.

All `whaxon workflow` verbs call shared `Core` capability, policy, store,
scheduler or queue methods; only `plan run` and the durable request worker
dispatch providers. The remaining verbs are read or control-plane operations.
CLI `plan approval grant --actor` accepts a caller-supplied actor label, so that
label is not authenticated-principal evidence.

| Workflow command group | Ownership and effect | Existing CLI/domain evidence |
| --- | --- | --- |
| `capabilities`, `providers`, `portfolio-audit` | Read-only registry, live provider and catalog/adapter portfolio views. | `test_workflow_cli.py`, `test_providers.py` |
| `mission create/list/plans`, `cost`, `cost-limit`, `rate`, `rate-limit`, `deadline`, `limits`, `budget` | Shared Core mission state and policy limits; no target dispatch. | `test_workflow_cli.py`, mission enforcement cases in `test_workflow.py` |
| `plan save`, `followups`, `show` | Validate/persist a plan, propose followups, or inspect state; no provider dispatch. `followups --save` only persists a new unapproved plan. | CLI coverage in `test_workflow_cli.py`; `test_engine_v2_followups.py`; core plan tests in `test_workflow.py`. |
| `plan approval list/grant/revoke`, `record-cost`, `cancel`, `reconcile`, `rate-limit`, `deadline`, `limits` | Consent, accounting and lifecycle control-plane mutations. Approval actor identity supplied as CLI text is not authenticated identity. | Approval, cancel, recovery and limit tests in `test_workflow_cli.py` and `test_workflow.py`. |
| `plan readiness`, `evidence`, `report`, `resources`, `audit`, `audit-snapshot`, `audit-verify`, `attempts`, `progress`, `events`, `event-inbox`, `event-ack`, `reconciliation-report` | Persisted diagnostics and evidence views; `report` renders only attempts linked to its named plan and marks failed, incomplete or unsealed evidence partial. It does not collect arbitrary job IDs or call the legacy engagement report. `event-ack` advances a consumer cursor but does not dispatch. | `test_workflow_report.py`, `test_workflow_cli.py`, `test_engine_v2_e3_audit_cli.py`, `test_workflow.py`. |
| `plan submit-run`, `serve-requests`, `drain-requests`, `queue-summary`, `run-request`, `run-snapshot`, `cancel-request` | Durable request queue and supervised worker lifecycle; submit returns queued state and does not assert completion. | `test_workflow_run_requests.py`, `test_workflow_continuous_worker.py`, `test_workflow_cli.py`. |
| `plan run` | Persists a durable V2 run request and returns queued state; the supervised worker owns provider execution and lease lifecycle. | `test_workflow_cli.py::test_workflow_cli_runs_headless_without_draining_legacy_jobs`, `test_workflow_run_requests.py`, `test_workflow_continuous_worker.py`. |

The CLI now routes both `workflow plan run` and `whaxon run --v2-plan <id>`
through the durable request queue and supervised worker. `whaxon run <tool>
<target>` and default `whaxon recon <target>` create saved plans but do not
execute. Explicit `whaxon run --legacy`, `ai --legacy`, and `recon --legacy`
remain compatibility paths outside V2 request ownership. Recon default
proposal and legacy-opt-in behavior are guarded by `test_recon_v2_cli.py` and
`test_engine_v2_recon_plan_proposal.py`; the top-level help omission for
`recon` remains guarded by `test_engine_v2_cli_surface.py`.

### G01 controlled solo-chain crosswalk

The release chain is scope → recon → enumeration → supported initial access →
independent verification → evidence/report → retest. Current source maps as
follows; the gaps below prevent a G01 pass.

| Stage | Current V2 path/evidence | G01 result |
| --- | --- | --- |
| Scope and bounded plan | Mission, typed plan/task, scope authorization, exact approval, limits and scheduler path in `Core`; see `test_workflow.py`, `test_providers.py`, and `test_engine_v2_e1_boundary.py`. | Implemented components; full cross-client and controlled-target acceptance is open under G02/G05. |
| Recon and enumeration | Admitted local-process providers listed above; fixed catalog argv goes through `ToolRunner`. | Provider contracts exist, but this local environment has no installed V2 binaries and none is smoke/lab/E2E verified. |
| Supported initial access | `lab.initial_access.samba_usermap` is a registered critical-impact provider restricted to the checked-in Metasploitable2 target `172.28.0.10`, fixed module `exploit/multi/samba/usermap_script`, fixed payload `cmd/unix/reverse_netcat`, and callback `172.28.0.11:4444`. It accepts no dynamic task inputs; requires `WHAXON_ENABLE_V2_LAB_INITIAL_ACCESS=1`, a scope reload/check, and exact plan-bound critical approval. It creates local evidence before dispatch, records the remote MSF job ID, accepts only a newly created matching session and stops that session if local evidence persistence fails. Normal success leaves the session open for operator follow-up; the G01 CI harness closes its session in `finally`. | **Implemented, not accepted.** Fake-client contract tests cover fixed options, opt-in, target, scope reload, RPC binding, non-reuse of pre-existing sessions, and evidence-failure cleanup. The isolated `docker-compose.g01-lab.yml` pins the target image and Rapid7 Metasploit Framework 6.5.4 image, places the RPC runner at `.11` with MSF RPC bound to loopback, and places the seeded boolean SQLi fixture in the `.10` target's network namespace, so recon, enumeration, initial access, verification and retest share the same IP. The mission aggregate now normalizes and requires one target identity across all stage plans. CI checks and retains the mission JSON plus a SHA-256 sidecar. Rapid7 source review checked the selected module, payload, session metadata/stop RPC and daemon flags. Exact-head CI #2157 exposed Compose credential ordering, SQLmap final confirmation and report typing issues; those are fixed. The exact-source candidate tree `75880425cdaf4857989f229638e59c5b65de099f` then passed the full isolated chain in CI run #43624338670: the G01 job built and started the fixed .10 target, .11 RPC runner, and .12 seeded fixture, ran scope through retest with persisted seals and mission report, and retained artifact `engine-v2-g01-controlled-lab-evidence` (artifact ID 14125401711, SHA-256 `cc11c73e2d5b3f59617047cec68a8cba20c5d4c15802f1feb729d095e98ea265`). This is repeatable isolated CI evidence, not independent external target qualification or production readiness; exhaustive caller/path inventory and the broader release scope remain open. |
| Independent verification | `tool.verify_sqli`/`tool.retest_sqli` and `tool.verify_xss`/`tool.retest_xss` run bounded SQLi or reflected-XSS probes as approved V2 scheduler tasks, require a successful same-target V2 finding of the matching kind with a valid evidence seal, and write separate sealed result jobs. Every HTTP request rechecks scope and exact URL path; only IP-literal targets are accepted to avoid DNS rebinding. | **Partial.** Timing/observation paths are not covered; each operation requires a separate plan and neither verifier family has been independently lab-validated. G03 remains open. |
| Evidence, report, retest | `Core.workflow_report` and `whaxon workflow plan report --id PLAN` render only persisted evidence linked to one named plan, excluding unsealed findings and marking failed, incomplete or truncated attempts partial. Scheduler-owned SQLi/XSS verification and retests each produce sealed jobs. | Component paths are implemented, but no accepted end-to-end chain/report/retest proof exists; legacy export/report parity also remains open under G04/G05. |

`Core.workflow_mission_report` and `whaxon workflow mission report --id MISSION`
aggregate only plan IDs persisted under that mission (or an explicitly
selected subset of those plans). Required order is scope → recon → enumeration
→ initial access → verification → report → retest. Scope is rechecked against
each immutable plan's exact task authorization and readiness; stage plans must
have complete reports with recorded, integrity-verified attempts. The aggregate
itself supplies the report stage after sealed verification evidence, so no
synthetic report plan or arbitrary job ID is accepted. A partial/missing stage,
failed authorization/readiness check, truncated report, or unsealed attempt
keeps the result partial. This is chain-report evidence only, not G01 acceptance
or production deployment approval. See `tests/test_workflow_mission_report.py`.

Existing tests establish component and client behavior; none is the required
controlled full solo-chain run with retained, independently verified proof.
The opt-in provider is limited to the repository's exact lab target and plan
approval; its presence does not establish working target compatibility or
authorize any other target. G01 remains open until its topology, execution,
evidence retention and complete chain satisfy controlled-lab acceptance.

This matrix is not G01 closeout. It records source mappings and a local
readiness snapshot; the required controlled full solo chain has not been
executed. The initial-access provider is not accepted based on fake-client
tests; the `.11` callback and loopback MSF RPC endpoint must be reachable in
the deployed lab topology, and the fixed Samba module must open a matching
session on the actual `.10` image. Catalog/admission/transport changes are guarded by
`test_catalog_transports_and_v2_admission_are_explicit` in addition to the
runner and service callsite guards.

## Migration constraint

Do not redirect `/api/run`, `/api/ai/run`, CLI tool/session execution, recon, or
retest in bulk. The Run and AI Gate pages now hand off to persisted V2 plans;
the legacy HTTP routes remain for older clients, CLI AI still uses separate
legacy run records, and recon retains its dedicated service. Each migration
needs an explicit capability mapping and parity before retiring the legacy
caller. UI-10 and broader E6 acceptance remain open.

## AI-to-V2 proposal boundary

`whaxon workflow plan ai-propose` and `POST /api/v2/ai/proposals` convert one
legacy AI `Action` into a reviewable, single-task V2 plan. They reject
out-of-scope targets before invoking the provider and expose only installed
and selected moderate-impact catalog providers, and pin the current manifest
fingerprint. The proposal requires the AI target to exactly match the
operator-supplied target and rejects session actions or dynamic arguments.
`--save` or API `save: true` persists the immutable plan; neither grants
approval, submits a run request, or dispatches work. Operators use the existing
plan approval and run-request commands separately.

The AI Gate page now uses the V2 proposal endpoint and hands saved plans to the
Run page. Default `whaxon ai "<goal>"` now creates and saves a scope-checked V2
proposal, then prints separate review, approval and submission commands. It
does not grant approval or submit a run. The old autonomous executor and
`--resume` path require explicit `--legacy`; `/api/ai/run` remains a legacy API
for existing clients. V2 AI action generation is still bounded to one
moderate-impact catalog action with an exact target and no dynamic arguments;
multi-step autonomous planning remains outside this migration slice.

The V2 Approvals page now reads `GET /api/v2/approval-queue` and grants
plan/task-bound, expiring consent through
`POST /api/v2/workflows/<plan_id>/approvals`. It never resumes a legacy AI
run: `/api/ai/pending` is displayed read-only, and
`POST /api/ai/runs/<id>/answer` remains available only for older clients.
Granting consent does not submit the separate V2 run request; blocked tasks
remain blocked and must be replanned.

The V2 Findings, BAS and Retest pages no longer call the legacy validation or
retest mutation routes. They hand off candidate findings for V2 verification
plans and verified findings for V2 retest plans. The server requires sealed V2
evidence and current scope before saving either plan. Legacy validation and
retest APIs remain available for compatibility clients; saved plans still
require review, approval, and separate run submission.

## Cancellation ownership boundary — 2026-11-11

`GET /api/jobs/active` now marks each row with its durable Engine V2 ownership.
V2 UI emergency-halt controls must cancel legacy rows through
`POST /api/jobs/<job_id>/cancel` and V2 runs through
`POST /api/v2/workflow-runs/<request_id>/cancel`. The legacy job-cancel route
rejects a marked V2 execution job with HTTP 409, so a client cannot bypass the
workflow plan's persisted stop barrier. Durable cancellation records a request
to stop; it does not prove that an already-dispatched external effect stopped.
The V2 request and its task outcomes may require reconciliation. This boundary
covers cancellation ownership; it does not migrate the remaining legacy
execution routes listed above.

## Recon capability parity ledger — 2026-11-12

The legacy `ReconRunner` path runs named protocol checks directly and publishes
legacy `JobStarted`/`JobFindings` events; it now requires `--legacy` plus
`WHAXON_LEGACY_RECON_ENABLED=true`. The default CLI proposes a reviewable V2
plan from ready fixed providers. `--engine v2 --plan-id` validates fixed task
bindings and submits a durable request; only the supervised worker dispatches
an approved plan. V2 providers are migrated individually; wrapping
`ReconRunner.run()` as a single V2 provider would preserve internal threads and
legacy event writes outside scheduler attempt ownership.

| Legacy check | Current behavior / output contract | V2 capability overlap | Parity |
| --- | --- | --- | --- |
| `dns` | Queries A, AAAA, MX, NS, TXT and SOA through dnspython; emits `dns_record` findings and per-query errors. | `dns.records.query` (`dig`) and `dns.records.enumerate` (`dnsrecon`) are admitted fixed-argv catalog providers. Dedicated `dns.recon.passive` provider implemented with fixed inputs and a supervised child process. | Catalog tools remain partial. The dedicated provider preserves the query/finding contract in source, but is not yet test-qualified or wired into the legacy CLI; no recon parity is claimed. |
| `ssl` | Connects to port 443, checks certificate validity, SANs and expiry; emits certificate/error findings. | `tls.certificate.inspect` (`whaxon.recon.tls_cert`) uses a supervised child, scope-pinned numeric socket addresses, fixed port 443, and certificate verification before any bounded invalid-certificate detail retry. Focused provider tests cover scope denial, socket pinning, findings, output bounds, and registration. | The V2 provider covers bounded certificate inspection and is runtime-tested at the provider boundary; exact legacy finding/output parity and full recon release qualification remain open. |
| `headers` | Fetches the target (HTTPS first, HTTP fallback) and reports configured security headers missing from the response. | Dedicated `web.recon.headers` provider makes one root-path HTTPS GET, checks pinned scope inside a supervised child, reads only bounded response headers, and persists attempt-linked evidence. | Bounded HTTPS header observations are implemented and covered by focused tests; HTTP fallback and complete legacy parity/release qualification remain open. |
| `tech` | Detects server/framework markers from HTTP headers and emits technology/port findings. | `web.server.audit` may expose server banners among broader findings. | Not equivalent; no fixed technology-detection contract. |
| `robots` | Fetches at most 64 KiB from `robots.txt` and `sitemap.xml` without following redirects; emits disallowed paths, sitemap references and up to 100 sitemap URLs. | Dedicated `web.recon.robots` V2 provider makes only two fixed HTTPS GETs, checks pinned scope inside a supervised child, bounds parsing/output, and persists attempt-linked evidence. | Bounded provider is implemented and covered by source/tests; full legacy parity/release qualification remains open. |
| `security_txt` | Fetches `/.well-known/security.txt`, parses recognized RFC 9116 fields, and emits field observations or an informational missing/no-recognized-fields finding; it does not validate `Expires`. | Dedicated `web.recon.security_txt` V2 provider makes one fixed HTTPS GET, checks pinned scope inside a supervised child, bounds headers/body/output, and persists attempt-linked evidence. | Bounded provider is implemented and covered by focused tests; full legacy parity/release qualification remains open. |
| `cookies` | Fetches the target and audits `Set-Cookie` flags (`Secure`, `HttpOnly`, `SameSite`). | `web.server.audit` may report some cookie issues. | Not equivalent; no stable cookie-only output contract. |
| `redirects` | Manually follows at most 10 hops, records HTTPS-to-HTTP and cross-origin hops, and stops before contacting a new cross-origin destination. | Dedicated `web.recon.redirect_observe` provider makes exactly one scope-pinned HTTPS GET to `/`, records status and a credential/query/fragment-redacted Location display, classifies HTTP(S) downgrade/cross-origin, and never follows Location. Other schemes are displayed as unsupported destinations, not classified as web origins. Hostname scope resolution may also produce a DNS query and resolver log. | Bounded first-hop observation only; not redirect-chain parity. |
| `waf` | Fingerprints known WAF/CDN signatures from response headers and cookies. | No equivalent fixed V2 provider. | Absent. |
| `dns_full` | Checks CAA, DMARC and SPF posture and emits dedicated policy findings. | Dedicated `dns.recon.full` V2 provider makes only fixed CAA(host), TXT(_dmarc.host), and TXT(host) queries with DNS-query scope checks and bounded child execution. | Bounded provider is implemented and covered by focused tests; complete legacy parity/release qualification remains open. |

The legacy HTTP helpers use short per-request socket timeouts, and the DNS
resolver has a timeout setting. However, `ReconRunner` waits for its
`ThreadPoolExecutor` context to close; a scheduler timeout cannot guarantee
that a stuck Python thread has stopped. A V2 implementation therefore needs
hard-bounded execution ownership (for example, a supervised worker process)
before it can claim durable cancellation. The implemented TLS, headers, robots, security.txt, and dns_full providers select fixed inputs, recheck scope in supervised workers, and record results in attempt-linked evidence. Their broader release qualification remains open; absent checks still require separate migrations. The two DNS catalog capabilities are partial overlap, not recon parity. The first
`dns.recon.passive` implementation requires an explicit hostname scope rule
when IP/CIDR rules are configured; Core preflight avoids uncancellable DNS
resolution, then the provider repeats the full scope decision in its supervised
child before querying. Static syntax checks passed; tests were not run, so
runtime readiness, cancellation and evidence-seal behavior remain unqualified.

The `web.recon.redirect_observe` provider and
`workflow plan propose-redirect-recon` authoring path add one fixed root GET.
The response status and first Location value are recorded with credentials,
query and fragment omitted; the provider never follows the Location. This is
first-hop observation only, not full legacy redirect-chain parity. Approval and
submission remain separate steps, and no runtime or release acceptance is
claimed by this source inventory.
