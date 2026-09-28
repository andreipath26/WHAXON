# Scope

WHAXON enforces scope fail-closed. A missing or broken config never silently permits everything.

## Default config

If data/scope.json does not exist at Core.__init__, ScopeManager.load() writes:

    {
      engagement: default,
      enabled: true,
      in_scope: [
        127.0.0.0/8,
        10.0.0.0/8,
        172.16.0.0/12,
        192.168.0.0/16,
        ::1,
        fe80::/10,
        fc00::/7
      ],
      out_of_scope: [],
      notes: Auto-generated default scope. Loopback and RFC1918 only.
    }

Covers:

- IPv4 loopback 127.0.0.0/8
- RFC1918 (10/8, 172.16/12, 192.168/16)
- IPv6 loopback ::1
- IPv6 link-local fe80::/10
- IPv6 unique-local fc00::/7

Does NOT cover 169.254.0.0/16 (link-local / cloud metadata) - treating that as an accidental target would be a mistake.

## Precedence

check(target) returns a result with .allowed and .reason. Order:

1. enabled == false -> allowed (operator opt-out, explicit).
2. out_of_scope match -> denied, regardless of in_scope.
3. in_scope match -> allowed.
4. No match -> denied.

## CLI

    whaxon scope --show                # Print the current config
    whaxon scope --check <target>      # Exit 0 allowed / 1 denied
    whaxon scope --set scope.json      # Replace config from file
    whaxon scope --enable              # Set enabled=true
    whaxon scope --disable             # Set enabled=false
    whaxon scope --clear               # Delete file (default rewritten next load)

## HTTP API

- GET  /api/scope             - current config
- POST /api/scope/check       - body: {target: ...} -> {allowed, reason}
- POST /api/scope/override    - body: {target, reason} -> allow once, logged to data/scope_overrides.log

## Escaping enforcement

Two paths:

1. Set enabled: false - global opt-out. Only for labs.
2. allow_out_of_scope=True on runner.run_tool(...) - per-call override, only available from code that can call the runner directly, not from the web API.

## AI scope expansion

The AI planner obeys the same fail-closed scope checker as everything else. `WHAXON_AI_SCOPE_EXPANSION` selects the policy for how discovered hosts are treated:

| Value | Behavior | Status |
| --- | --- | --- |
| `strict` | Only explicitly-listed targets. Discovered hosts are never automatically in scope. The agent may *propose* adding one via `ask_human`, but the executor refuses any action against an out-of-scope target regardless of the human's answer. | **v1 default and only implemented policy.** |
| `inherited` | Any host that resolves from an in-scope domain, and any host in the same RFC1918 subnet as an in-scope host, would be in scope. | Documented; **not implemented in v1**. Selecting it logs a warning and falls back to `strict`. |
| `recommended` | As inherited, but every auto-expansion is logged and the human can veto before the first action against the discovered host. | Documented; **not implemented in v1**. Selecting it logs a warning and falls back to `strict`. |

**Why strict for v1.** Scope enforcement is the safety property the whole tool rests on. Starting strict and moving to looser is a small change. Starting loose and trying to tighten is a rewrite. The design (`docs/agent-architecture.md` §9) makes this explicit.

**Env var default:** unset = `strict`. Any value other than `strict` warns at startup and uses `strict`.

## Failure modes

- File missing: strict default written, enforcement enabled
- File unreadable / malformed JSON: RuntimeError at Core.__init__ - WHAXON refuses to start
- enabled key missing: defaults to true (fail-closed)
- in_scope missing: empty list; everything denied

## Tests

- tests/test_scope_failclosed.py - default scope covers IPv4 loopback CIDR and IPv6 (::1, fe80::/10, fc00::/7); 127.0.0.1 and RFC1918 allowed; external hosts denied.
- tests/test_scope.py - out_of_scope precedence, wildcards, exact hosts, fail-closed on missing file.