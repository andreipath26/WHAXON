

**File:** docs/bounty-addon.md
**Status:** DRAFT — reference for the bounty add-on only.
**Owner:** andreipath
**Depends on:** §3 (current capabilities), §22 (session log), §13 (out-of-scope items)
**Non-goals:** does not replace the main roadmap; does not weaken its own policy; does not self-authorize.

---

## §26.0 — Purpose and capability model

The add-on exists to help a single hunter find and prove the bug classes that YesWeHack-style programs pay for: IDOR, horizontal/vertical privilege escalation, authentication bypass, business logic errors with real impact, and access-control flaws in authenticated multi-user web apps.

It does this by being a program-policy-driven harness with differential analysis at its core. The hunter drives. The policy gates what the tool is allowed to do at a given target. The override log records what actually happened.

### Capability model

Capability is unconditional. Authorization is per-target and fail-closed.

The add-on contains every capability described in this document — including scanner orchestration, AI action selection, AI-authored live requests, and catalog extension. None of those capabilities are removed. All of them are gated by the active program policy. When no policy is loaded, existing WHAXON behavior applies (host-scope gate only). When a policy is loaded, the policy decides what runs.

This mirrors the existing scope.py design: the tool is capable of running nmap; scope decides whether it does. The bounty add-on extends that discipline upward to a program layer.

### The one unconditional non-goal

The add-on never weakens its own policy. No self-modification. No self-permission. No automatic expansion of the program list, the allowed tools, or the AI flags. Policy files are human-authored and human-reviewed. A malformed policy is refused, not repaired. A missing policy is refused, not defaulted-permissive.

This is R69 (authority narrows, never expands, without explicit human re-authorization) applied at the add-on level.

### Why this shape

Every program reviewed on YesWeHack (50/50 in the sampled list, including all examples) contains: "Do not use automated scanners or tools that generate large amount of network traffic." HARMAN explicitly names the legal consequence: non-compliant testing removes CFAA safe-harbor protection.

The economics: first clean report wins, systemic issues decay 100% to 10% by the sixth report, triage responds in under 1 day. The edge a solo hunter has is being correct and being first with a bug a scanner cannot find.

But the same capabilities that are prohibited on most programs are permitted on some, and on the hunter's own infrastructure, sanctioned labs, CTFs, and self-owned targets they are simply ordinary tools. The design serves both by making authorization data, not code.

---

## §26.1 — Program policy layer

### Purpose

A per-program configuration file that encodes the rules the platform and program impose, and the tool permissions the operator grants for that target. Without it, the add-on refuses to touch a target. This is the outer gate. The existing scope.json remains the inner gate (host-level authorization). Both must pass.

### Location

data/programs/<slug>.yaml
data/programs/<slug>.overrides.log

The slug matches the program's URL slug (for example xelians-blackbox-program, cryptobox-bug-bounty).

### Schema

Platform-agnostic. `platform` names the source; `platform_extras` holds
per-platform fields that only that platform exposes. The common fields
below are what every platform publishes.

```yaml
slug: example-program
platform: yeswehack          # yeswehack | hackerone | bugcrowd | intigriti | immunefi | other
program_url: https://yeswehack.com/programs/example-program
title: "Example Program"
organization: "Example Corp"
program_type: bug_bounty     # bug_bounty | vdp
visibility: public           # public | private
last_reviewed: 2026-10-13
last_update: 2026-10-08
supported_languages: [en]

identity:
  user_agent_suffix: " bugbounty-0421"
  email_alias: "hunter-alias@yeswehack.ninja"
  hunter_username: "andreipath"

account_access:
  mode: self_register          # self_register | invite | trial | none
  notes: "Register at https://... with your YesWeHack alias."
  vpn_required: false

rate:
  max_requests_per_second: 2   # operator-set; programs rarely publish this
  max_concurrent_connections: 1
  respect_robots_txt: false

reward_model:
  type: grid                   # grid | severity_table | vrt_tier | range | impact_matrix
  currency: EUR
  grid:                        # only when type == grid
    - asset_value: critical
      low: 50
      medium: 500
      high: 1000
      critical: 2000
    - asset_value: high
      low: 100
      medium: 300
      high: 800
      critical: 1200
  max_reward: 2000
  avg_reward: null
  systemic_decay:
    - { report: 1, percent: 100 }
    - { report: 2, percent: 100 }
    - { report: 3, percent: 75 }
    - { report: 4, percent: 50 }
    - { report: 5, percent: 25 }
    - { report: "6+", percent: 10 }

scope:
  in_scope:
    - { scope: "https://api.example.com", type: api, asset_value: critical }
    - { scope: "*.example.com", type: wildcard, asset_value: high }
    - { scope: "https://apps.apple.com/.../id123", type: mobile_ios, asset_value: high }
  out_of_scope:
    - "All domains not listed In-Scope"
    - "Third-party widgets on www.example.com"

hunting_requirements:
  proof_of_exploitation: "screenshots required; raw HTTP req/resp mandatory"
  first_reporter_wins: true
  reporting_window_hours: null
  disclosure_allowed: false
  automated_scanners: forbidden   # forbidden | limited | allowed
  data_handling: "no data alteration; redact PII in PoC"

tools:
  mode: denylist
  allowlist: []
  denylist:
    - nmap
    - nikto
    - ffuf
    - nuclei
    - sqlmap

ai_policy:
  allow_action_selection: false
  allow_live_requests: false
  allow_auto_mode: false
  require_human_confirm: true

reporting:
  platform_form: yeswehack
  required_fields:
    - description
    - exploit
    - impact
    - remediation
    - proof
    - repro_steps
  title_format: null

bug_classes:
  qualifying:
    - sqli
    - xss
    - rce
    - idor
    - privesc
    - auth_bypass
    - business_logic
    - lfi
    - xxe
    - ssrf
    - open_redirect
    - exposed_secrets
  non_qualifying:
    - missing_cookie_flags
    - clickjacking
    - self_xss
    - user_enumeration
    - rate_limiting
    - weak_password_policy
    - stack_traces
    - directory_listing
    - software_versions
    - graphql_introspection
    - missing_security_headers
    - hsts
    - cve_no_poc
    - csv_injection

platform_extras:
  yeswehack:
    credits_cost: 2
    hunters_collaboration: true
    max_collaborators: 5
  hackerone: {}
  bugcrowd: {}
  intigriti: {}
  immunefi: {}

population: clipboard_parse

override_log:
  path: data/programs/example-program.overrides.log
  append_only: true
  cross_check_at_report: true

```

### Reward model variants

Five shapes, because five platform families publish rewards differently:

| `type` | Used by | Fields |
|---|---|---|
| `grid` | YesWeHack | `grid[]` of asset_value x CVSS band -> amount |
| `severity_table` | HackerOne | `table[]` of severity -> amount |
| `vrt_tier` | Bugcrowd | `tiers[]` of P1-P5 -> points and/or amount |
| `range` | Intigriti, early programs | `min`, `max` only |
| `impact_matrix` | Immunefi | `impacts[]` of impact category x asset type -> amount |

v1 implements `grid` only (YesWeHack). The schema accepts all five so a later
platform does not force a schema rewrite. An unimplemented `type` refuses at
load time with `reward_model.type '<x>' is not implemented in v1`.

### Scope objects

Scopes are objects, not flat strings, because `asset_value` changes the payout
and `type` changes what tooling is appropriate (a mobile app scope is not
scanned by nmap). The resolver matches on `scope`; the reward calculation and
the tool-permission check both read `asset_value` and `type`.

### Platform portability (SS26.1.2)

The schema above is platform-agnostic by construction:

- Common fields are what every platform publishes.
- `platform_extras` is validated only for the named platform, passed through
  untouched for `other`.
- `reward_model` is a tagged union, so a HackerOne severity table and a
  Bugcrowd VRT tier are expressible without inventing new top-level keys.

**v1 population is `clipboard_parse`.** The human copies a program page's text
and runs `whaxon bounty policy init <slug> --from-clipboard`. The parser
(`core/bounty_parse.py`) turns the pasted text into the policy dict. No network
call to any platform. This sidesteps two real risks: YesWeHack's ToU forbids
derivative use of their site materials, and their internal API is unversioned
and changes without notice. A parser is honest and stable; an API client is
neither.

**Adding HackerOne, Bugcrowd, Intigriti, or Immunefi** is a parser per page
shape plus a `platform_extras` validator per platform. The schema does not
change. That is the portability guarantee.

### Behavior when missing or malformed

- Missing file: refuse; error names the missing file and the expected path.
- Malformed YAML: refuse; error names the parse failure and line number.
- Missing `tools.mode`: refuse. No default.
- Empty `scope.in_scope`: refuse.
- Unknown `platform`: refuse, key named.
- Unknown `reward_model.type`: refuse, type named.
- `reward_model.type` known but not implemented in v1: refuse, naming the type.
- Unknown top-level key anywhere: refuse, key named. `platform_extras` is the
  exception: its contents are validated only for the named platform.
### Relationship to existing scope.json

Both gates apply, in order: program gate (scope.in_scope in the policy), then host gate (data/scope.json). Out-of-scope wins. Existing scope.py behavior preserved.

### Choosing a policy for a target

The add-on resolves the policy by matching the target host against each policy's scope.in_scope. If exactly one matches, that policy applies. If more than one, refusal. If none, refusal for bounty subcommands.

---

## §26.1.1 — Override log specification

### Purpose

The override log records every moment the operator enables a capability a policy would otherwise forbid. Its purpose is to make the decision to bypass a program rule expensive, so the default is compliance and the exception is deliberate, documented, and visible at report time.

### Properties

- Append-only. Opened with O_APPEND. Never truncated, rewritten, or deleted.
- Mandatory. Writes on: enabling ai_policy.allow_action_selection, enabling allow_live_requests, enabling allow_auto_mode, running a tool from tools.denylist, running a tool outside tools.allowlist, or any manual override flag passed to a bounty subcommand.
- Human-attributed. Each entry names the invoking user and the ISO-8601 timestamp with timezone.
- Cross-checked. The report generator reads the log before producing submission-ready output.

### Entry format

One line per override, newline-delimited JSON:

{"ts":"2026-10-13T16:04:22+02:00","operator":"andreipath","slug":"example-program","kind":"tool_bypass","tool":"nmap","mode":"denylist","reason":"operator flag --allow-forbidden-tool","session_id":"job-abc123"}
{"ts":"2026-10-13T16:09:11+02:00","operator":"andreipath","slug":"example-program","kind":"ai_flag_enabled","flag":"allow_auto_mode","previous":false,"new":true,"reason":"policy edit"}

The reason field is required. No reason, no override.

### Report cross-check

When the report generator runs with a bounty-submission format, it reads the override log and the session's tool and AI records, computes the intersection, and:

- If non-empty: refuses submission-ready output, names each override.
- --force-submit overrides the refusal, writes another log entry, marks the report with a warning banner.

### What the log is not

Not a legal instrument. Not a license. Not a substitute for judgment. It makes the override expensive, not impossible.

### Why mandatory

Because a silent override makes the policy advisory. Under pressure, advisory policies get ignored. A mandatory log prevents the unrecorded override. That is the difference between a compliance failure and a compliance failure with a paper trail, and that difference matters if a program ever asks how you found something.

---

## §26.2 — Core analysis capabilities

### §26.2.1 — Differential session analysis

Record two authenticated sessions (Principal A, B). Replay the same logical request from each. Diff responses. Emit findings only on violations.

Not fuzzing. Not brute-forcing. Not parameter tampering. Replays requests the hunter already made, with the identity changed.

Data model:

- SessionPair: a_session_id, b_session_id, target_host, program_slug, created_at
- RequestPair: a_request, b_request, logical_key, created_at
- DiffResult: request_pair_id, classification, evidence, severity

Classification values: cross_owner_read, cross_owner_write, unauthenticated_success, lower_privilege_success, precondition_violation, no_violation, inconclusive.

Classification rules (deterministic):

- A 200, B 403/401, same logical request, B is owner -> cross_owner_read
- A 200/201/204 on state-changing method, B cannot perform -> cross_owner_write or lower_privilege_success
- Unauthenticated request indistinguishable from authenticated -> unauthenticated_success
- State-requiring step succeeds without prior state -> precondition_violation
- A and B both 200 with identical bodies for per-principal request -> inconclusive

No finding without evidence pointing at both principals' requests.

Input: HAR (existing adapter), Burp XML (existing importer).

Commands:

    whaxon bounty pair  <session-a> <session-b>
    whaxon bounty diff  <pair-id>
    whaxon bounty report <pair-id>

Maps to: IDOR, horizontal privesc, vertical privesc, broken auth, broken function-level access control, business logic.
Status: DRAFT.

### §26.2.2 — Invariant engine

Declarative assumptions checked across sequential actions. Hunter writes invariants.yaml. Add-on executes the sequence and checks each invariant.

Not a fuzzer. Not a model checker.

Why it exists: "Business Logic Errors with real security impact" is on every qualifying list, and no scanner tests for it.

Schema:

target: https://example.com
session_principal: a

sequence:
  - id: login
    request: { method: POST, path: /auth/login, body: "user={{alias}}&pass={{password}}" }
    capture: { session_cookie: "Set-Cookie" }
  - id: create_invoice
    request: { method: POST, path: /invoices, body: "amount=100" }
    capture: { invoice_id: "$.id" }
  - id: refund
    request: { method: POST, path: "/invoices/{{invoice_id}}/refund" }
    capture: { refund_id: "$.id" }

invariants:
  - id: balance_never_negative
    check_after: refund
    assertion: "response.body.balance >= 0"
    violation_severity: high
  - id: refund_not_exceed_payment
    check_after: refund
    assertion: "response.body.refunded_amount <= response.body.paid_amount"
    violation_severity: critical
  - id: invoice_owner_cannot_be_changed
    check_after: create_invoice
    assertion: "response.body.owner == session_principal.identity"
    violation_severity: high

Assertion language: dotted paths, comparisons, boolean operators. No eval. Parsed and evaluated by the add-on.

Commands:

    whaxon bounty invariants run  invariants.yaml
    whaxon bounty invariants report <run-id>

Status: DRAFT.

### §26.2.3 — State machine / workflow inference

From a HAR or Burp capture, build the observed request graph. Flag illegal transitions and missing preconditions.

Not a crawler. Works from captures the hunter took.

Violation types: precondition_missing, entry_point_unexpected, role_mismatch, terminal_reentry.

Commands:

    whaxon bounty workflow build <session-id>
    whaxon bounty workflow diff  <session-a> <session-b>
    whaxon bounty workflow report <graph-id>

Status: DRAFT.

---

## §26.3 — AI role (gated)

Available when the policy enables them: offline analysis, hypothesis generation, report drafting, action selection (allow_action_selection), live-request authorship (allow_live_requests), auto mode (allow_auto_mode).

All flags default to false. Enabling any writes to the override log.

Unavailable regardless of policy: automatic submission, policy modification, override log modification.

Why the gate: most programs forbid what AI action selection amounts to. Some do not. Some targets are under no policy. The gate makes the decision data, not code.

---

## §26.4 — Report generation

Submission-ready on first attempt. YesWeHack canonical shape: description, exploit, impact, remediation, proof, repro steps.

Output: report.md plus report.json. Per-program template via reporting.platform_form. Unknown -> refusal.

Redaction: credentials, tokens, cookies, PII (unless the program requires otherwise), out-of-scope hostnames. Redaction failure = generator failure.

Override log cross-check: read log, read session records, compute intersection. Non-empty -> internal report only, with refusal naming each override. --force-submit writes another log entry and marks the report.

Commands:

    whaxon bounty report <finding-id>  --format yeswehack
    whaxon bounty report <finding-id>  --format md
    whaxon bounty report <finding-id>  --format yeswehack --force-submit

Status: DRAFT.

### Redaction boundary

Redaction is a report-generation concern, not an ingest concern. The store holds unredacted evidence: request and response headers verbatim, bodies truncated but not scrubbed. The submission-format generator (yeswehack, hackerone, bugcrowd) applies the program's redaction rules immediately before output, driven by reporting.redact_fields in the program policy. Internal formats (md, json) do not redact. This preserves the evidence the differential engine needs (§26.2.1) while ensuring nothing unredacted reaches a program's submission form.

---

## §26.5 — Scope

### Unconditional non-goal

The add-on never weakens its own policy. No self-modification, no self-permission, no program-list expansion without a human editing the file.

### Gated

- Scanner tools: tools.mode plus allow/deny lists
- Catalog extension: subject to tools.mode when a policy is loaded
- AI action selection: ai_policy.allow_action_selection
- AI live-request authorship: ai_policy.allow_live_requests
- AI auto mode: ai_policy.allow_auto_mode
- Per-request human confirm: ai_policy.require_human_confirm
- Active scanning, fuzzing: tools.mode

### Out of scope project-wide

- DoS or resource exhaustion
- Data destruction beyond proving a finding
- PII extraction beyond minimum needed
- Bulk extraction
- Circumventing WHAXON's own executor boundary (R86)
- Wireless, SDR, forensics, RE, malware, social engineering, hardware (§13)
- Public disclosure


---

## §26.6 — Relationship to existing WHAXON components

Reused as-is: core/store.py, core/scope.py, core/events.py, adapters/har.py, adapters/burp.py, core/report.py (extended), core/pivot.py (read-only).

Not replaced: core/runner.py catalog path (gated at policy layer), ai/executor.py (gated), core/ai_bridge.py, core/msf.py, core/msf_tracker.py, interfaces/gui/.

New modules: interfaces/cli/bounty_cmd.py, core/bounty/program.py, core/bounty/override_log.py, core/bounty/pairing.py, core/bounty/diff.py, core/bounty/invariants.py, core/bounty/workflow.py, core/bounty/report.py.

New finding kinds: http_request (existing), cross_owner_read, cross_owner_write, unauthenticated_success, lower_privilege_success, precondition_violation, invariant_violation, role_mismatch, terminal_reentry, entry_point_unexpected. Added to _SEV_ORDER in report.py, excluded from correlator recon-burst counting.

---

## §26.7 — Program state

| Section | Status |
|---|---|
| §26.0 Purpose and capability model | DRAFT |
| §26.1 Program policy layer | DRAFT |
| §26.1.1 Override log | DRAFT |
| §26.2.1 Differential session analysis | DRAFT |
| §26.2.2 Invariant engine | DRAFT |
| §26.2.3 Workflow inference | DRAFT |
| §26.3 AI role (gated) | DRAFT |
| §26.4 Report generation | DRAFT |
| §26.5 Scope | DRAFT |
| §26.6 WHAXON relationship | DRAFT |
| §26.8 Legal boundary | DRAFT |
| HAR adapter (existing, untracked) | UNDER REVIEW |

Ship gate for §26.1: loader implemented, refuses on missing or malformed policy, has tests, integration test with synthetic program file, override log writes on each gate event.

Ship gate for §26.2.1: pairing, diff, finding emission, evidence bundle, one end-to-end test with two synthetic sessions and a deliberately cross-owner resource.

Nothing beyond §26.1 ships until §26.1 and §26.2.1 are green under R12.

Resume from cold: read §26.7 first. Next unit: §26.1.

---

## §26.8 — Legal and ethical boundary

Three structural constraints:

1. No request fires that a policy does not authorize. Either the target has no policy (existing WHAXON behavior) or the policy permits the action. The override log records every override.
2. No scope violation. Two gates: program scope and host scope. Both must pass. Out-of-scope wins.
3. No self-authorization. The add-on cannot change its own permissions.

The add-on does not decide what is legal. The operator decides, the policy records the decision, and the log records the override. The rest is the operator's responsibility.

---

End of DRAFT.