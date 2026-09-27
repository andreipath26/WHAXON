# Security Policy

## Reporting a vulnerability

Do not open a public issue. Email the maintainer directly (see the repository commit metadata) or open a GitHub Security Advisory (https://docs.github.com/en/code-security/security-advisories).

Include:

- A minimal reproduction
- The affected version or commit
- Whether the vulnerability is exploitable without authentication

You can expect a response within 7 days.

## Scope

WHAXON runs security tools and accepts remote AI model responses. The following are in scope for security reports:

- Command injection via tool arguments
- Authentication bypass in the web UI
- SQL injection or path traversal in the store or evidence handlers
- Scope enforcement bypass
- AI-layer guardrail bypass (getting the executor to run an action the operator did not authorise)

The following are not in scope:

- Vulnerabilities in third-party tools (nmap, nikto, sqlmap, etc.) - report those upstream
- Anything requiring physical access to the host
- Social engineering

## Hardening already in place

- Fail-closed scope: a missing or malformed scope.json never allows everything.
- Every AI-proposed action is validated against the catalog, scope, and a target lock before it runs.
- HTML reports HTML-escape markdown before rendering.
- The AI layer cannot emit shell commands - only run_tool, ask_human, or stop actions, each carrying a catalog tool id.

See docs/scope.md and docs/ai.md for details.
