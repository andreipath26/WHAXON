# WHAXON

**Open-source security assessments grounded in evidence—not assumptions.**

[![CI](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)](LICENSE)
![Status: Beta](https://img.shields.io/badge/status-beta-64748b)

WHAXON is an independently developed, open-source cybersecurity project that brings **authorized security testing, vulnerability validation, evidence, reporting, and retesting** into one workflow.

Security scanners can produce hundreds of alerts. WHAXON is being built around the harder questions: **What was actually tested? What does the evidence prove? What remains uncertain? And did the fix work?**

Its long-term goal is to help defenders move from discovery to evidence-backed decisions and safer remediation, with optional AI assistance that does not replace authorization or proof.

> **Current status:** Active beta (`0.11.16`), Python 3.11+. The core application and substantial Engine V2 components exist, but the complete V2 migration, production deployment acceptance, and v1.0 release are **not finished**. This is a development-stage project, not a certified security service.

## Why WHAXON exists

Defensive security work is often fragmented across scanner consoles, raw logs, spreadsheets, reports, and separate retest sessions. Findings can look definitive even when they are only tool observations. Evidence and execution context can get lost between discovery and remediation.

WHAXON's design starts with three principles:

- **Evidence before conclusions.** Tool output is a lead, not automatic proof. Supported validation paths distinguish verified findings from candidates and inconclusive results.
- **Control stays with the operator.** Scope restrictions and approval boundaries govern supported execution. AI suggestions cannot independently authorize targets or actions.
- **Make results reproducible.** Keep relevant findings, execution context, coverage, and supporting evidence connected to reports and retests.

We are not trying to claim that every vulnerability can be found or automatically verified. We are trying to make each supported assessment result clearer, more accountable, and more useful.

## What exists today

| Capability | Current implementation |
| --- | --- |
| **Tool orchestration** | Shared runner, catalog, adapters, and persistent job history for supported external security tools |
| **Authorized execution** | Explicit target scope checks and policy/approval controls in supported paths |
| **Finding analysis** | Normalized observations, correlation, severity information, and finding lifecycle states |
| **Deterministic validation** | Evidence-based checks for supported vulnerability types; unsupported or ambiguous cases are not automatically marked verified |
| **Evidence and reports** | Stored assessment information and Markdown, HTML, PDF, and JSON reporting paths |
| **Remediation retesting** | Tracked retests with outcomes such as fixed, still vulnerable, or inconclusive, where supported |
| **Interfaces** | Command-line interface, developing `/ui-v2` browser workspace, and optional terminal/desktop interfaces |
| **Engine V2 workflow services** | Versioned mission plans and durable requests; capability/provider routing; approval-bound task execution; bounded scheduling, leases, cancellation, recovery and audit; shared workflow CLI and HTTP APIs |

WHAXON supports integrations with established security tools through its catalog and adapters. **An adapter or catalog entry is not a guarantee that the external tool is installed, fully integrated, or validated on every platform.**

### The workflow we're building

```text
Define authorized scope
          ↓
Run supported assessments
          ↓
Collect and correlate observations
          ↓
Validate what can be independently checked
          ↓
Preserve evidence and disclose coverage gaps
          ↓
Produce an assessment report
          ↓
Retest after remediation
```

A supported validator may replay a specific request and evaluate a response marker or other observable evidence. Where the required context or a reliable validation method is absent, WHAXON must retain uncertainty instead of inventing certainty.

## Engine V2: reliability is a feature

WHAXON is evolving from several tool-specific execution paths toward **one durable, capability-driven workflow engine** shared by its CLI, web interface, and headless services.

Engine V2 now has implemented shared workflow services, beyond the initial foundation:

- **Durable workflows:** versioned missions, plans, task graphs and run requests, with bounded concurrency, time/rate/cost limits, approval bindings, worker leases, cancellation, emergency halt and conservative recovery of uncertain external effects.
- **Provider and audit boundaries:** a capability registry, trusted provider routing, provider-bound plans, lifecycle events, recovery reconciliation and checks that evidence cannot be claimed verified solely because a task completed.
- **Operator interfaces:** workflow commands and V2 HTTP endpoints for missions, plans, approvals, progress, evidence and run-request state. The developing Run page can discover missions and plans and offers durable workflow controls; it does not mean every supplied UI control is integrated.
- **Reviewable AI handoff:** the workflow CLI and `POST /api/v2/ai/proposals` can turn a constrained AI suggestion into a provider-pinned proposal. Saving a proposal does **not** approve it, submit a run request or execute tools. Scope and input bounds are checked fail-closed.

The shared-service/headless phase has **bounded engineering acceptance**, supported by CI and supervised systemd/Docker smoke checks. These checks do not establish deployment acceptance or independent real-target validation.

**Work still underway:** migrating the remaining legacy CLI/web/AI/session execution paths into one V2 lifecycle; completing provider/transport and cross-interface parity; finishing supplied UI control wiring; validating audit/evidence integrity and authorized external-tool failure recovery; and completing security, accessibility, deployment and rollback acceptance. The current beta is **not production-approved**.

For the technical implementation and acceptance boundaries, see [Engine V2](docs/ENGINE_V2_MASTER.md) and the [master roadmap](WHAXON%20ROAD%20MAP%20-%20WHATS%20NEXT%20-%20FULL%20SCOPE.md).

## Where we're going

We are prioritizing a dependable **single-operator defensive assessment workflow** before expanding the platform.

**Near-term priorities**
1. Complete the shared Engine V2 execution paths and supported deployment checks.
2. Validate authorization, evidence quality, reporting, and remediation retesting end to end in controlled environments.
3. Complete the supplied browser workspace's remaining real-service controls, state consistency and accessibility acceptance.
4. Improve installation, operational diagnostics, documentation, and reproducibility.

**Research and longer-term directions** *(planned, not shipped)*

- **Local-first evidence portability:** exportable evidence packages and independently checkable integrity records.
- **Evidence-grounded AI investigation:** structured analysis that references observations, discloses uncertainty, and proposes reviewable next steps.
- **Safe remediation assistance:** reviewable fixes, isolated testing, explicit authorization before changes, and evidence-backed retesting.
- **Controlled multi-asset assessments:** bounded resource budgets, per-target authorization, and provenance-preserving attack-path analysis.
- **Open evaluation methods:** reproducible tests of verification quality, false-positive handling, reliability, and security boundaries.

These are research and product goals, not claims of delivered functionality. See the [roadmap and release gates](WHAXON%20ROAD%20MAP%20-%20WHATS%20NEXT%20-%20FULL%20SCOPE.md).

## Try WHAXON

WHAXON is a Python project intended for **systems you own or are explicitly authorized to assess**. Start with a lab environment; the current release is for evaluation and development.

```bash
git clone https://github.com/andreipath26/WHAXON-AI-Forensics.git
cd WHAXON-AI-Forensics

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[web]"

whaxon --help
whaxon setup --profile core
whaxon doctor --json
```

The setup profile command **previews** dependency requirements; it does not silently install every security tool.

To open the developing local browser workspace:

```bash
whaxon web
```

Then visit [http://127.0.0.1:5001/](http://127.0.0.1:5001/) (redirects to `/ui-v2`). Some visible UI features remain under integration. Supported external tools must be installed and configured separately.

Read the [operations guide](docs/OPERATIONS_MASTER.md) for installation, supported environments, and deployment precautions. Do not expose a development service to an untrusted network without reviewing authentication, transport, and configuration.

## Open development, responsible AI, and research

WHAXON is developed by an independent founder based in **Toulouse, France**, with AI-assisted tools used in parts of implementation, testing, and documentation. AI assistance does **not** imply independent verification: code, tool outputs, security claims, and proposed changes require appropriate review and tests.

AI is an **assistant**, not an authority on whether a vulnerability exists or whether an action is permitted. Local workflows and independent checks are important to the project's direction; optional external AI services must not be mistaken for a requirement of every workflow.

This project welcomes collaboration with open-source contributors, security researchers, academic groups, and organizations interested in **defensive cybersecurity, evidence quality, reproducible testing, and responsible remediation**.

**For potential research and funding partners:** the most useful areas of support are controlled evaluation infrastructure, independent security testing, evidence-provenance research, and the development and publication of reusable open-source defensive components. WHAXON is seeking to advance these objectives; no external grant award, sponsorship, partnership, or institutional endorsement is implied by this README.

- [Project issues and discussions](https://github.com/andreipath26/WHAXON-AI-Forensics/issues) — feature proposals, collaboration inquiries, and reproducible bugs
- [Contributing](CONTRIBUTING.md) — contribution process and CLA
- [Security policy](SECURITY.md) — **report security vulnerabilities privately**, not as public issues
- [Evidence and reporting design](docs/EVIDENCE_AND_REPORTING_MASTER.md) — implementation and documentation
- [Acceptance register](docs/V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md) — what is and is not accepted for v1.0

## License and safety

WHAXON's public source is licensed under **[AGPL-3.0-or-later](LICENSE)**, with separate commercial licensing terms described in the repository. Third-party tools and dependencies retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).

Use WHAXON only with explicit authorization. Application-level scope controls do not replace network isolation, and neither scanner output nor AI-generated text constitutes universal proof of a vulnerability. The software is provided as an actively developed beta, without a claim of production certification.

---

**The principle behind WHAXON: discover responsibly, verify independently, preserve the evidence, and prove what changed.**
