# WHAXON

**Evidence-led, scope-controlled security assessments.**

[![CI](https://github.com/andreipath26/WHAXON/actions/workflows/ci.yml/badge.svg)](https://github.com/andreipath26/WHAXON/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)](LICENSE)
![Status: Beta](https://img.shields.io/badge/status-beta-64748b)

WHAXON is an open-source Python platform for **authorized security testing**. It brings supported tools, assessment findings, evidence, reports, and retesting into one operator-led workflow.

Scanners produce observations. WHAXON helps organize those observations, check what can be independently validated, and keep uncertainty visible where evidence is incomplete.

> **Project status:** WHAXON 0.11.16 is an active beta for evaluation and development. Engine V2 migration and product acceptance are still in progress. WHAXON has not passed production deployment acceptance and is not a certified security service.

## What WHAXON does

- **Runs supported security tools** through a shared catalog, adapters, and execution history. Tools may need to be installed and configured separately.
- **Applies scope and approval checks** to supported execution paths. Operators remain responsible for authorization and target selection.
- **Organizes findings and evidence** so tool output is distinguishable from independently validated results.
- **Validates selected finding types** with deterministic checks where a reliable method exists. Unsupported or inconclusive cases remain unverified.
- **Creates reports and retest records** to help track findings through remediation.
- **Provides operator interfaces** including a CLI and a developing local browser workspace, with optional terminal and desktop interfaces.
- **Develops Engine V2** as a shared, durable workflow engine for supported CLI, web, and headless operations. The migration and full interface integration are not complete.

No scanner or AI model can prove every vulnerability. A tool result is a lead; verification depends on the evidence and the supported validation path.

## How an assessment flows

1. Define the assets and scope you are explicitly authorized to assess.
2. Run supported checks with the tools available on your system.
3. Review and correlate the resulting observations.
4. Validate findings where WHAXON has a supported evidence-based check.
5. Preserve the results, report coverage and uncertainty, then retest after remediation.

AI assistance is optional. It can help prepare constrained proposals; it does not grant authorization, approve a run, or establish that a vulnerability exists.

## Quick start

WHAXON requires Python 3.11 or newer. Install from the repository:

    git clone https://github.com/andreipath26/WHAXON.git
    cd WHAXON
    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e ".[web]"

    whaxon --help
    whaxon setup --profile core
    whaxon doctor --json

The core setup command previews dependency requirements; it does not silently install every security tool. Review the plan and install only the tools you need.

Start the local browser workspace with:

    whaxon web

Then open [http://127.0.0.1:5001/](http://127.0.0.1:5001/). The browser workspace is under active development; some controls and workflows remain incomplete. On PowerShell, activate the environment with .venv\Scripts\Activate.ps1.

## Current limitations

- External-tool availability and behavior depend on your operating system, installed versions, configuration, and permissions.
- Validation covers selected finding types, not every scanner result or vulnerability class.
- Some Engine V2 execution paths and user-interface controls are still being integrated.
- Production security, deployment, accessibility, and rollback acceptance remain open.

Use a lab or other explicitly authorized environment while evaluating WHAXON. Scope controls do not replace network isolation or careful operator review.

## Project status and documentation

- [Engine V2 release decision](docs/ENGINE_V2_G10_RELEASE_DECISION.md) — current readiness and remaining release gates
- [Engine V2 technical master](docs/ENGINE_V2_MASTER.md) — architecture, implementation, and evidence
- [Operations guide](docs/OPERATIONS_MASTER.md) — installation, configuration, and deployment guidance
- [Project roadmap](WHAXON%20ROAD%20MAP%20-%20WHATS%20NEXT%20-%20FULL%20SCOPE.md)
- [v1.0 acceptance register](docs/V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md)

## Contributing and security

Contributions and collaboration on defensive cybersecurity, evidence quality, reproducible testing, and responsible remediation are welcome.

- [Issues and discussions](https://github.com/andreipath26/WHAXON/issues)
- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md) — report vulnerabilities privately, not in public issues

## License

WHAXON is licensed under [AGPL-3.0-or-later](LICENSE). Separate commercial licensing terms are documented in the repository. Third-party tools and dependencies retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).

---

**Discover responsibly. Verify independently. Preserve the evidence.**