# WHAXON — INSTALLATION, DEPLOYMENT AND OPERATIONS MASTER

> **Verified setup/deployment (2026-11-06):** Python `>=3.11`, optional `[web]`, `[tui]`, `[gui]`, `[metasploit]`, `[dev]` dependencies. `whaxon setup --profile core` previews, not installs. Curated automatic external-tool installation is bounded to supported Debian/Ubuntu/Kali `apt` and macOS Homebrew mappings/architectures; Windows package managers are diagnostics/manual. `whaxon serve` uses Waitress; the systemd web service uses Gunicorn and a separate `workflow plan serve-requests` worker; paired Docker E5 config is staged. G07 PR #143 upgrade smoke passed 22/22 checks across Python 3.11–3.13 for 0.11.14→candidate 0.11.16 and same-version 0.11.16 reinstall; production security, package rollback and disaster recovery remain open. Wheel installation alone does not start or production-authorize these services.

**Authoritative operator guide, consolidated 2026-11-05.** Contains first-run, dependencies, deployment, troubleshooting, demos, screenshots and installation design. Verify configuration and commands against current CLI/service code and installed package; historical aspirations are not current shipped functionality.

> **Engine V2 sequence:** This deployment guidance is for qualification after implementation. Complete the agreed Engine V2, Engine V2 UI, and remaining solo-v1.0 implementation scope first, with internal tests throughout. Defer real-target runs and production-like install/upgrade/rollback/recovery exercises until implementation is complete and internal checks pass. Use staging for candidate qualification; deploy to production only after qualification succeeds.

## Guide navigation

- Part 1: getting-started.md
- Part 2: dependency-readiness.md
- Part 3: deployment.md
- Part 4: troubleshooting.md
- Part 5: first-run-installation-redesign.md
- Part 6: demo.md
- Part 7: screenshots.md

---

## Part 1 — getting-started.md

# Getting Started

This guide describes the current `main` checkout of **andreipath26/WHAXON-AI-Forensics**. The inspected source declares version `0.11.16` in `pyproject.toml`; PyPI publication/version identity was not independently verified here. The repository may contain unreleased changes. Use `whaxon --help` to confirm the commands available in your installed copy.

## Requirements

- Python 3.11 or newer (Python 3.13 is included in CI).
- Linux, macOS or Windows; external tool installation support varies by OS.
- External security tools are separate dependencies. See [Tools](APPLICATION_ARCHITECTURE_MASTER.md) and [Dependency readiness](#part-2--dependency-readinessmd).

## Install from source

```bash
git clone https://github.com/andreipath26/WHAXON-AI-Forensics.git
cd WHAXON-AI-Forensics
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[tui,web]"
```

For PowerShell, create the environment with `py -3.11 -m venv .venv` and activate it with `.venv\Scripts\Activate.ps1`. Install the `gui` extra separately if you need the PySide6 desktop interface:

```bash
python -m pip install -e ".[gui]"
```

## Install the published package

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "whaxon[tui,web]"
```

The latest published version recorded on PyPI is **0.11.16 (October 23, 2026)**. The repository's `main` branch includes work beyond that published artifact; do not assume every current-main feature is present in the PyPI wheel.

## First run

```bash
whaxon setup --profile core
whaxon doctor
whaxon init
whaxon scope --show
whaxon --help
```

`whaxon setup --profile core` creates a read-only capability/dependency plan; it does not install anything. Use `standard`, `full` or `custom` to preview a different profile. Review the plan and use its exact approval ID only if you deliberately choose an eligible installation. Run `whaxon doctor --verify` when you need the curated external-tool version checks.

Review the generated data directory and the active scope before running anything. The default scope is restrictive and covers loopback and private address ranges; it is not authorization to assess every host in those ranges.

## Run an authorized lab assessment

1. Create or select a lab target that you own or are explicitly authorized to test.
2. Add only the approved target(s) to the scope configuration. See [Scope and authorization](APPLICATION_ARCHITECTURE_MASTER.md) for the configuration format and CLI.
3. Confirm the target with `whaxon scope --check <target>`.
4. Inspect the tool's supported arguments with `whaxon run --help` and the catalog documentation.
5. Run the selected tool and review the resulting job, findings and evidence.

Do not use `scanme.nmap.org` or another public test host as a default first-run target: it is outside the generated default scope and requires explicit scope configuration and compliance with the host owner's current testing terms. Never widen scope merely to make a tutorial command work.

## Browser interface

Start the local development server in the foreground:

```bash
whaxon web
```

Open [http://127.0.0.1:5001/](http://127.0.0.1:5001/). The root route redirects to the current Obsidian Kinetic interface at `/ui-v2`; `/ui` is retained as the legacy interface.

Loopback requests use the local-peer authentication shortcut, subject to Host and cross-origin protections. Remote requests require explicit non-default authentication credentials. Never expose the default local configuration to an untrusted network. See [Deployment](#part-3--deploymentmd).

## Useful data locations

Paths are relative to the configured `WHAXON_DATA` directory (default: `data/`):

- `whaxon.db` — SQLite job, finding, evidence and workflow state.
- Tool catalog and packaged resources — see [Tools](APPLICATION_ARCHITECTURE_MASTER.md) and [Dependency readiness](#part-2--dependency-readinessmd).
- Scope and other runtime configuration — see [Scope](APPLICATION_ARCHITECTURE_MASTER.md) and [Deployment](#part-3--deploymentmd).

Report output locations depend on the selected command and options; consult `whaxon report --help`.

## Next

- [Scope and authorization](APPLICATION_ARCHITECTURE_MASTER.md)
- [Tool catalog](APPLICATION_ARCHITECTURE_MASTER.md)
- [Interfaces](APPLICATION_ARCHITECTURE_MASTER.md)
- [Dependency readiness](#part-2--dependency-readinessmd)
- [Deployment](#part-3--deploymentmd)
- [Troubleshooting](#part-4--troubleshootingmd)


---

## Part 2 — dependency-readiness.md

# Dependency readiness and guided installation

## Scope and status

This implementation adds dependency diagnostics, deterministic remediation planning, a tightly allowlisted Python-package installer, single-package and profile-batch operation tracking, readiness history, authenticated web APIs, and a first-run profile planner in the existing Diagnostics page.

The Diagnostics page is the canonical web entry point; `whaxon setup` is the CLI first-run entry point. Both expose Core, Standard, Full and Custom profiles. The operator can review a read-only plan, explicitly approve the complete eligible Python-package batch, and track the sequential operation through verification. Individual package review remains available. External-tool OS packages are not part of the Python profile batch. A separate CLI flow supports exact-plan-approved apt/Homebrew installation for Nmap, Gobuster, SQLmap and ffuf, plus Nuclei through Homebrew only; unsupported combinations remain manual.

Its four states are:
1. Environment overview.
2. Dependency inventory.
3. Guided fix / plan review.
4. Installation progress and post-install verification.

The implementation reuses the existing `/ui-v2/diagnostics` page shell and design tokens. It does not add navigation or a replacement design system.

## Diagnostics

Run:

```bash
whaxon doctor
whaxon doctor --json
whaxon doctor --core-only
whaxon doctor --check python
whaxon doctor --verify
whaxon doctor --snapshot
whaxon doctor --drift
```

The versioned JSON report includes runtime details, active interpreter and virtual-environment state, required Python package metadata/import checks, optional extras, and external executable discovery from the packaged tool catalog. Mandatory packaged validation payloads are checked for presence and non-empty contents. External executable records include the selected path, distinct PATH candidates, a local filesystem-metadata identity fingerprint, and a PATH-ambiguity flag. This fingerprint helps detect a changed local file; it is not a publisher signature, content hash, or supply-chain attestation.

`--verify` runs only manifest-curated, bounded external-tool version probes. It does not run arbitrary tool commands or target scans.

### Status meanings

- `READY`: the declared Python minimum is met and the package import specification is resolvable, or the runtime meets the Python minimum.
- `MISSING`: a distribution or executable could not be found.
- `INCOMPATIBLE`: an installed package or Python runtime is below the declared minimum.
- `BROKEN`: package metadata/import or a required packaged resource could not be read.
- `DETECTED`: an external executable resolves on PATH but has not passed a trusted version probe. Multiple distinct PATH candidates are explicitly flagged for operator review.
- `BROKEN`: an executable resolves but its filesystem identity cannot be inspected; WHAXON will not run its version probe.

An overall `BLOCKED` result means a required runtime/package/resource is not READY. `DEGRADED` means optional integrations or external tools are missing or unverified. Optional tools do not block unrelated core functionality.

Diagnostics themselves do not install software, invoke package managers, access the network, use privilege escalation, or change PATH. Explicit external verification is a separate action.

## CLI first-run setup

Use `whaxon setup` to inspect the host and build a deterministic capability-profile plan without requiring the browser Diagnostics page:

```bash
# Read-only profile previews
whaxon setup --profile core
whaxon setup --profile standard
whaxon setup --profile full
whaxon setup --profile custom --capability core --capability tui

# Machine-readable preview
whaxon setup --profile core --json
```

The preview prints the exact plan ID and selected dependency actions. A profile selection does not install packages or grant permission. After reviewing the complete plan, the eligible Python-package batch can be approved explicitly:

```bash
whaxon setup --profile core --install --approve PLAN_ID
```

Replace `PLAN_ID` with the exact ID from the plan you reviewed. The batch is restricted to manifest-allowlisted Python packages, requires an active virtual environment, runs sequentially and stops on failure or cancellation. Already completed package operations are not rolled back.

External tools are a separate operation. Preview a curated OS-package plan, then approve that exact plan with explicit system-change consent:

```bash
whaxon setup --tool nmap
whaxon setup --tool nmap --install-tools --approve-tools PLAN_ID --allow-system-changes
```

Add `--allow-elevation` only when the reviewed plan requires a non-interactive privilege elevation. Automated OS-tool installation is limited to the supported apt/Homebrew mappings described above; other tools, distributions and platforms remain manual. The CLI does not install arbitrary catalog entries.

If a working `whaxon` command is already available, `whaxon setup --create-venv` can create a new `.venv` without overwriting an existing directory and prints activation instructions. Otherwise, create the virtual environment with Python's `venv` module before installing WHAXON.

For one dependency rather than a whole profile, `whaxon doctor --plan --check DEPENDENCY_ID` and the exact-plan `whaxon doctor --install --check DEPENDENCY_ID --approve PLAN_ID` path remain available. The older `whaxon install` command is a legacy apt-only installer; prefer `whaxon setup` for current guided setup.

## Manifest and policy

The packaged source of truth is `src/whaxon/data/dependencies.json`. It records the Python runtime, core packages, optional extras, profiles, curated external-tool probes and installation policy.

Python automatic installation is enabled only for manifest-listed `python-package` dependencies. External-tool installation uses a separate fixed package allowlist in `setup_installers.py`, exact-plan approval, explicit system-change consent, separate non-interactive elevation consent, shell-free package-manager invocation and trusted post-install version probes. The mapping is intentionally limited to apt on Debian/Ubuntu/Kali and Homebrew on supported macOS architectures; Windows package managers are detected for diagnostics only and remain manual because native Windows package IDs have not passed acceptance. Unsupported architectures and distributions remain manual even if a package manager binary is present. The UI cannot override the Python installer policy.

## Remediation preview

Generate a read-only plan:

```bash
whaxon doctor --plan
whaxon doctor --plan --check textual
```

A plan includes a deterministic plan ID, selected dependency, exact proposed argument array and display command, package source, network/privilege impact, virtual-environment requirement, and whether automation is enabled. A plan is not authorization. No command is run while preparing it.

The plan ID is bound to the current environment, manifest and action details. If those change, the previous approval is rejected.

## Explicitly approved Python-package installation

For an eligible package, first review the complete plan, then run:

```bash
whaxon doctor --install --check textual --approve PLAN_ID
```

Replace `PLAN_ID` with the exact ID from the reviewed plan.

The installer:
- Requires an activated Python virtual environment; it will not modify a system Python installation.
- Installs only a Python distribution declared in the packaged dependency manifest.
- Enforces the manifest's `automatic_installation_enabled` and allowed-kind policy.
- Uses the active interpreter's pip with isolated pip configuration and a fixed official PyPI index.
- Accepts binary wheels only; it does not execute source build scripts.
- Does not use a shell, sudo/admin elevation, or user-supplied executable/arguments.
- Has a 15-minute timeout and supports cancellation.
- Re-checks the installed distribution version and import after installation. A pip exit code of zero is not sufficient.
- Writes a local JSONL audit record under `~/.whaxon/audit/dependency-install.jsonl` with restrictive file permissions where supported.

**Important package impact:** pip may install or update transitive dependencies required by the approved package. The plan identifies this behavior, the configured PyPI source, and the exact command before approval. The operation is not a fully hash-pinned, offline-reproducible deployment. Do not use it where a locked, hash-verified software supply chain is mandatory.

## Web API and operation lifecycle

The authenticated API exposes:
- `GET /api/dependencies` — read-only diagnostics.
- `POST /api/dependencies/verify` — explicit curated version probes.
- `POST /api/dependencies/plan` — read-only plan preview.
- `POST /api/dependencies/install` — queues an exact plan-ID-approved single-package operation and returns an operation ID.
- `POST /api/dependencies/install-batch` — queues an exact plan-ID-approved profile batch, restricted to manifest-allowlisted Python packages, and returns an operation ID.
- `GET /api/dependencies/install/<operation-id>` — operation state, progress and verification result.
- `POST /api/dependencies/install/<operation-id>/cancel` — request cancellation.
- `POST /api/dependencies/snapshots` and `GET /api/dependencies/history` — local readiness history.
- `GET /api/dependencies/drift` — compare current readiness with the latest snapshot.

Operation state is stored under `<data-dir>/.whaxon/dependency-operations/` with restrictive permissions where supported. Per-dependency locks prevent concurrent installs, including conflicts between single-package and profile-batch operations; periodic progress updates support stale-worker detection. Cancellation terminates the package-manager process where possible.

The worker currently runs as a background thread in the web process. A process crash can interrupt an install; the persisted operation will be marked interrupted after its heartbeat expires. This is not a distributed job queue and does not guarantee survival across process restarts.

## Readiness snapshots and drift

The CLI supports `--snapshot` and `--drift`. History is bounded to 100 snapshots and stored under `<data-dir>/.whaxon/dependency-readiness.json`. Snapshots omit the current working directory and raw executable paths; paths are represented by one-way fingerprints so drift can be detected without persisting personal directory names.

## Failure recovery

A failed, timed-out or interrupted pip operation may have partially changed the active virtual environment. WHAXON does not claim rollback. Re-run `whaxon doctor`; if the environment is inconsistent, recreate the virtual environment and reinstall the approved dependency set. Audit and operation records include outcome and recovery guidance.

## Remaining deployment gates

**Verified implementation and CI evidence (not full deployment acceptance):**
- CI run [#41307525558](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/41307525558) passed Ruff, mypy, pytest and distribution build/metadata validation on Python 3.11, 3.12 and 3.13. Its clean Python 3.12 wheel smoke test exercised `whaxon doctor --json`; the sdist check verified the dependency manifest, tool catalog and payload files.
- Setup preview and virtual-environment smoke checks run on Ubuntu, macOS and Windows CI runners. Actual curated external-tool installation is exercised on Ubuntu/apt and Apple Silicon macOS/Homebrew, with trusted version probes and loopback-only functional checks for the selected tools.
- Restricted-host policy tests verify read-only planning when no supported package manager is present, manual-only apt plans without sudo, and rejection when elevation consent is missing.
- The manifest, packaged tool catalog and required validation payload resources are checked in wheel/sdist workflows.

**Still open; do not advertise as accepted or production-deployable:**
- Full clean-machine acceptance for each explicitly supported OS/distribution/architecture, including native Windows and WSL2 as separate environments. Windows package managers are diagnostic-only; their package IDs are not enabled for automatic installation.
- Physical offline-host acceptance, writable destination validation, resource integrity hashes, and a complete artifact/transitive-dependency integrity and pinning strategy.
- Full functional verification coverage for every advertised external-tool capability; the existing loopback checks cover only the selected curated tools and scenarios.
- Worker restart/recovery guarantees. The installer worker is a background thread in the web process; a process crash can interrupt an operation. Persisted state detects interruption but does not provide durable execution across restarts.
- Complete browser acceptance on supported desktop targets for keyboard navigation, screen-reader announcements, cancellation races, empty/error/loading states and all UI-to-API flows.
- Independent audit trust anchoring and realistic failure/recovery acceptance.

These are roadmap/release gates, not an instruction to keep a pull request in draft. The repository currently has no open pull request for this work. Do not publish dependency readiness as a finished production feature until the outstanding gates are closed with evidence.


## Evidence principle and audit lifecycle (mandatory)

WHAXON follows five mandatory operating principles: deterministic plans, explicit informed consent, bounded execution, independent verification, and **leave evidence**. Evidence is the accountability layer that makes the first four independently enforceable.

For dependency readiness, the audit lifecycle must cover:
- Plan created or regenerated: plan ID, canonical digest, manifest/policy version, environment binding, exact proposed action and impact disclosure.
- Approval or rejection: actor, decision, timestamp, exact plan digest, approval context and expiry/revocation where applicable. A submitted plan ID alone is not proof that an informed approval occurred.
- Action lifecycle: queued, started, parameters actually passed, process identity where available, progress/state transitions, cancellation, timeout, exit/result and finish time.
- Verification: verifier identity/version, inputs, checks performed, observed distribution/version/import state, evidence digest and explicit pass/fail/inconclusive outcome.
- Recovery: trigger, diagnosis, actions recommended or taken, operator decision, resulting state and follow-up verification.
- Exceptional paths: denied approval, stale/changed plan, audit failure, worker crash/interruption, lock recovery and partial installation.

Events must share stable plan, approval, operation and dependency identifiers so an auditor can reconstruct the complete sequence. Profile batches additionally record acceptance of the exact parent profile plan and a terminal batch outcome; each child package operation retains its own plan/action evidence. Store append-only records with restrictive access, secret redaction and minimal personal data. Add a verifiable integrity mechanism (for example, a hash chain with a documented trust anchor); append-only JSONL and filesystem permissions alone do not prove tamper-evidence. Provide an integrity-check/export path. Never report a consequential operation as fully successful when required evidence could not be persisted or verified.

**Current implementation boundary:** the installer now records plan creation, plan-ID approval submission, action start and terminal outcomes in a sequenced SHA-256-linked local JSONL chain. The chain is checked before appending and can be verified through `GET /api/dependencies/audit`; corruption fails closed. This is tamper-evident against partial modification or reordering, not immutable against an attacker who can rewrite the complete file. The current web/CLI interface does not provide a verified human identity or cryptographic proof that the plan was displayed and understood. The chain has no independently stored trust anchor, and writers are serialized with a cross-process file lock. The lack of an independently stored trust anchor remains a deployment blocker for stronger audit assurance; do not describe the ledger as tamper-proof or complete.


### Headless server support

WHAXON's CLI setup/diagnostics and production `whaxon serve` entry point are designed to run without a desktop session or terminal interaction. The Linux CI workflow removes DISPLAY/Wayland/session variables, executes setup and doctor, starts the Waitress server with stdin detached, and confirms an HTTP response on loopback. This does not replace remote deployment hardening: configure explicit credentials, TLS/reverse proxy, firewall rules, backups and a persistent protected data directory before network exposure.


---

## Part 3 — deployment.md

# Deploying WHAXON

WHAXON web interface can run headless and be accessed from any browser.

## Local browser server

    whaxon web

Starts the Flask development-server entry point in the foreground. Debug mode and the automatic reloader are disabled; it does not provide production WSGI serving or automatic reload-on-change. Keep it on loopback for local use.

## Production WSGI server

    whaxon serve
    whaxon serve --threads 8

Runs the application through Waitress in the foreground. This is the production-oriented WSGI command; the web extra includes Waitress.

## Daemon

    whaxon serve --daemon --log data/whaxon.log

On supported POSIX hosts, daemon mode double-forks, writes the PID to `<WHAXON_DATA>/whaxon.pid` (default `data/whaxon.pid`) and redirects stdout/stderr to the selected log. Startup rejects a live PID already occupying the PID file.

Stop the daemon with SIGTERM:

    kill -TERM "$(cat data/whaxon.pid)"

The daemon's signal handler removes its PID file. If a stale PID file remains, first verify that the recorded process is no longer running before removing it. For managed deployments, prefer the included systemd unit or a process supervisor.

## Environment

- WHAXON_HOST       default 127.0.0.1   bind address
- WHAXON_PORT       default 5001        port
- WHAXON_DATA       default data        data directory
- WHAXON_AUTH_USER  default whaxon      basic auth user
- WHAXON_AUTH_PASS  default whaxon      basic auth password
- WHAXON_TRUST_PROXY default off         trust one configured reverse proxy for forwarded client IP / HTTPS scheme
- WHAXON_ALLOWED_HOSTS comma-separated additional Host values accepted by the local Host-header guard

Loopback development defaults are accepted only on loopback. For a non-loopback listener, install the `web` extra and set an explicit non-default username plus either a strong, unique `WHAXON_AUTH_PASS` or a precomputed bcrypt `WHAXON_AUTH_PASS_HASH` with cost factor 12 or higher. Network-facing startup rejects SHA-256 password hashes and refuses to fall back to weak hashing if bcrypt is unavailable. Never use the demo credentials in a network deployment.

## systemd

whaxon.service is included in the repo root. Install:

    sudo cp whaxon.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now whaxon

Adjust User, WorkingDirectory, and paths to your layout.

## Engine V2 durable worker alongside the web service (systemd)

Engine V2 run requests are stored in SQLite and require a **separate supervised
worker**. Running only `whaxon.service` exposes the web interface but does
not guarantee that queued V2 work is being processed. Installing a service
unit is configuration, not proof that a process is healthy.

Use the two repository-provided units from the **same installed WHAXON
release**: `whaxon.service` and `whaxon-workflow-worker.service`. Both
specify `User=whaxon`, `WorkingDirectory=/opt/whaxon`,
`WHAXON_DATA=/var/lib/whaxon/data`, and `StateDirectory=whaxon`.
Provision the virtual environment and the protected `/etc/whaxon.env`
before enabling services. Never use default/demo network credentials;
restrict the environment file to administrators, and ensure the service
identity can access only its intended persistent state. Review and adjust
paths for the host instead of blindly copying a unit from another installation.

On a supported systemd host, after reviewing units and provisioning the
service user, application, environment and state:

```sh
sudo install -m 0644 whaxon.service whaxon-workflow-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now whaxon.service whaxon-workflow-worker.service
sudo systemctl status whaxon.service whaxon-workflow-worker.service
sudo journalctl -u whaxon-workflow-worker.service --no-pager -n 100
```

The web and worker services use a shared store, **not separate SQLite
databases**. Do not start an additional ad-hoc drain worker against the same
installation without first evaluating worker ownership and resource limits.
The worker runs `whaxon workflow plan serve-requests` in the foreground;
SIGTERM stops admission of additional claims. An external effect already in
flight may remain uncertain, not automatically cancelled or replayed.

For a local operational check, inspect the web's Core and supervised-worker
readiness at
`http://127.0.0.1:5001/api/health` using the configured authentication
when required. With `WHAXON_V2_EXTERNAL_WORKER=1`, this endpoint fails
readiness until the worker has completed startup recovery and refreshed its
heartbeat. Also check the worker's systemd status/journal and, as the service
account with the production data path, inspect
`whaxon workflow plan queue-summary`.
Verify a permitted, explicitly approved synthetic/controlled workflow
through submission, persisted run-request inspection, restart, reconnect
and cancellation without unauthorized external activity.

### Backup, recovery and release evidence

Protect the **entire** operator state: the consistent SQLite database
transactional snapshot, protected configuration and scope/approvals,
evidence/artifacts and installed-provider inventory. The automated
`test_engine_v2_e5_backup_restore.py` covers a SQLite-only snapshot, not
this full recovery. Never claim success from copying a live database file
without a consistent backup. Before a restore, stop **both** services,
retain the old state for investigation, restore files with service ownership
and restrictive permissions, then bring the services back under supervision.
Treat recovered in-flight/expired work as **uncertain** pending manual
reconciliation; never silently requeue potentially effectful operations.

Deployment acceptance requires a dated record of host OS, exact commit and
package version, chosen systemd paths, credentials/proxy/TLS safeguards,
start/stop/restart behavior, worker claims, approved test target, request
IDs, queue/audit evidence, complete backup/restore, failure injection,
known limitations, and reviewer sign-off. Until a real supported-host
rehearsal succeeds, E5 deployment readiness remains **NOT VERIFIED**.

## Docker

Hardened container:

    docker build -t whaxon:secure .
    docker run --rm -d --name whaxon --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop=ALL --security-opt=no-new-privileges:true -p 127.0.0.1:5001:5001 -v data:/data -e HOME=/tmp -e WHAXON_AUTH_USER=whaxon-admin -e WHAXON_AUTH_PASS=replace-with-a-long-unique-password -e WHAXON_DATA=/data whaxon:secure

Notes:

- --read-only filesystem; /tmp is a tmpfs.
- -v data:/data is the persistent volume.
- WHAXON_DATA points at the mounted volume.
- Tools installed inside the container are not persisted. Bake them into the image.
- The Dockerfile binds gunicorn to 0.0.0.0:5001 inside the container. This is required for the container to be reachable from the host. The example above publishes the port to 127.0.0.1 only via -p 127.0.0.1:5001:5001, so the container is not exposed to the host network. Do not remove the -p 127.0.0.1: prefix unless you intend to expose WHAXON on the host network.

## HTTPS

Recommended: reverse-proxy. Terminate TLS at nginx/caddy/traefik in front of 127.0.0.1:5001. Keep the WHAXON bind on loopback and let the proxy handle certificates, HSTS, and rate limiting. For the nginx pattern below, set `WHAXON_TRUST_PROXY=1` and add the public hostname to `WHAXON_ALLOWED_HOSTS` (for example, `whaxon.example.com`). Only enable proxy trust when the app is reachable exclusively through that trusted proxy; otherwise clients could spoof forwarded headers.

nginx example:

    server {
      listen 443 ssl http2;
      server_name whaxon.example.com;
      ssl_certificate     /etc/letsencrypt/live/whaxon.example.com/fullchain.pem;
      ssl_certificate_key /etc/letsencrypt/live/whaxon.example.com/privkey.pem;
      location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
      }
    }

### Opt-in Engine V2 Docker deployment

The root `docker-compose.yml` defines an intentionally separate target lab;
**do not** use it as a WHAXON production deployment. The new
`docker-compose.e5.yml` runs two non-root services from the same built image:
`web` and the persistent `workflow-worker`. They share the named
`e5-state` volume at `/data`, while only the web service publishes
`127.0.0.1:5001`. Both containers use read-only root filesystems, a
restricted tmpfs and dropped Linux capabilities.

Provide strong non-default `WHAXON_AUTH_USER` and `WHAXON_AUTH_PASS`
values via a private operator environment (or a protected Compose env file)
without committing credentials. Inspect the fully resolved configuration
before starting; do not post its output because it can contain secrets.

```sh
docker compose -f docker-compose.e5.yml config --quiet
docker compose -f docker-compose.e5.yml up -d --build
docker compose -f docker-compose.e5.yml ps
docker compose -f docker-compose.e5.yml logs --tail 100 workflow-worker
```

A started container does not certify worker liveness or external-effect
recovery. Verify the shared queue and one explicitly approved controlled
workflow before accepting the deployment. Persist and back up the named
volume together with independently protected operational configuration and
evidence. This Compose configuration is an **engineering candidate**;
real Docker service, restart, recovery, secrets and backup/restore acceptance
are still outstanding.

### Offline E5 operator-state snapshot and restoration

Stop **both** web and workflow-worker services before taking an offline backup;
the utility cannot determine whether another process is modifying the state.
The standalone tool includes the complete operator-state file tree (such as
scope, configuration and evidence), makes a consistent SQLite backup,
rejects symbolic links/nonregular files and generates per-file SHA-256 checks.
It does not back up secrets or host configuration outside `WHAXON_DATA`.

```sh
python -m whaxon.core.state_snapshot backup /var/lib/whaxon/data /secure/whaxon-e5-snapshot
python -m whaxon.core.state_snapshot verify /secure/whaxon-e5-snapshot --expected-manifest-sha256 "<independently-retained-64-character-sha256>"
python -m whaxon.core.state_snapshot restore /secure/whaxon-e5-snapshot /secure/whaxon-restored --expected-manifest-sha256 "<independently-retained-64-character-sha256>"
```

The destination must **not exist**. Restore into a separate location, inspect
its integrity and ownership, and only then coordinate a deliberate cutover
while both services remain stopped. The snapshot's internal checksums detect
accidental changes but are **not independently trusted**: retain its manifest
hash or copy in protected external storage with operator-controlled identity.
Use restrictive permissions and encrypted off-host retention for sensitive
evidence. This is an offline engineering recovery mechanism; real supervised
host restoration and sign-off remain mandatory E5 deployment gates.

The backup command outputs `manifest_sha256`; retain that value outside
WHAXON storage using an operator-protected witness before allowing a later
restore. Verification without `--expected-manifest-sha256` detects file drift
against the internal manifest but **does not** protect against an attacker who
changes the manifest itself. The external expected digest provides comparison
only; its authenticity depends on how the operator retained it.

### E5 dedicated-worker mode

The systemd web unit and opt-in paired Docker web container set
`WHAXON_V2_EXTERNAL_WORKER=1`. In this mode the web API durably enqueues V2
run requests but **does not create an additional process-local queue drainer**.
Only the separately supervised `workflow-worker` executes V2 queue work.
When it is down, accepted requests remain queued, never falsely completed.
Existing web-only users without this flag retain the prior wakeup behavior.
This flag does not disable unrelated legacy tool/AI execution endpoints;
those remain a separate authorization and migration obligation.

### E5 containerized offline recovery test

The E5 GitHub Actions deployment smoke now stops both Compose services,
uses an isolated one-shot `workflow-worker` image to snapshot the existing
state volume to a **separate** `e5-backups` volume, verifies an independently
recorded manifest digest, restores into a new directory and checks that the
persisted test mission remains readable. The auxiliary `/e5-backups` mount
point is writable by the container's non-root user; it is not mounted by
normal running web and worker services. CI demonstrates an isolated
container recovery path only. An operator must still verify off-host backup
retention, service credentials, host-specific failure injection, ownership,
real environment recovery and external audit anchoring before production
acceptance.

### Durable E5 run submission from headless CLI

Use `whaxon workflow --data-dir /var/lib/whaxon/data plan run
--id <existing-plan-id>` or `plan submit-run` to persist a bounded request
for the supervised worker without launching a second execution loop. The
`whaxon run --v2-plan <existing-plan-id>` bridge uses the same queue. Optional
`--max-tasks`,
`--max-attempts` and `--max-concurrency` have the same values and validation
as the V2 run API. Repeating the same plan and limits returns the same active
request ID; differing limits fail closed. Inspect with `plan run-request` or
`plan run-snapshot` using the returned ID. `plan run` and `--v2-plan` now submit
requests; direct legacy dispatch remains separately gated behind `--legacy`.


---

## Part 4 — troubleshooting.md

# Troubleshooting

This guide applies to the current `main` checkout. Package wheels may lag behind main; use `whaxon --help` and each command's `--help` to confirm the installed version's command surface.

## Installation and Python environment

### `ModuleNotFoundError: No module named 'whaxon'`

Activate the virtual environment used for installation and install the project into that interpreter:

```bash
source .venv/bin/activate
python -m pip install -e ".[tui,web]"
python -c "import whaxon; print(whaxon.__file__)"
```

On PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[tui,web]"
```

### `externally-managed-environment`

Do not use system pip. Create and activate a virtual environment, then use `python -m pip` from that environment.

### Optional interface dependency is missing

Install only the extra you need:

```bash
python -m pip install -e ".[tui]"   # terminal interface
python -m pip install -e ".[web]"   # browser interface
python -m pip install -e ".[gui]"   # desktop interface
```

PySide6 wheel availability depends on the Python version and platform. WHAXON requires Python 3.11+; if a GUI dependency has no compatible wheel for your interpreter, use a supported Python release or install the TUI/web extras instead. Do not change Python versions without recreating the virtual environment.

## Dependency diagnostics and installation

### A dependency is MISSING, INCOMPATIBLE or BROKEN

Run:

```bash
whaxon doctor
whaxon doctor --json
```

Check which interpreter is active, whether the dependency is required or optional, and whether a packaged resource is missing. A BLOCKED result concerns a required runtime/package/resource; DEGRADED can mean an optional integration or external tool is unavailable.

### An external tool is DETECTED but not READY

Run `whaxon doctor --verify` to perform only the curated, bounded version probes. Review multiple PATH candidates and the resolved executable path. A catalog entry does not mean the executable is installed, licensed or compatible.

### A remediation plan cannot be approved

Generate a fresh profile plan with `whaxon setup --profile core`, or a single-dependency plan with `whaxon doctor --plan --check DEPENDENCY_ID`. Approve only the exact current plan ID using the matching setup/doctor command. Approval is bound to the environment and manifest; a changed plan must be reviewed again. Python-package automation requires an active virtual environment and manifest allowlisting. OS-tool installation has a separate limited apt/Homebrew allowlist and requires explicit system-change consent; unsupported platforms remain manual.

### An installation failed or was interrupted

Rerun `whaxon doctor` and inspect the operation/audit record. A failed pip operation may have partially changed the virtual environment; WHAXON does not promise rollback. If the environment is inconsistent, recreate the virtual environment and reinstall the required approved extras. See [Dependency readiness](#part-2--dependency-readinessmd).

## Tool execution and scope

### `binary not found` or a tool is unavailable

Run `whaxon doctor` and `whaxon doctor --verify`, then check the tool's entry in [the packaged catalog](APPLICATION_ARCHITECTURE_MASTER.md). Install external tools separately using the documented supported method for your OS. The catalog's package hint is not an installation command or permission.

### A target is rejected

Inspect the active configuration with `whaxon scope --show` and check the exact target with `whaxon scope --check <target>`. The default scope is restrictive (loopback and private ranges); it is not authorization to test every address in those ranges. Do not disable scope to work around an unexpected denial. Review [Scope and authorization](APPLICATION_ARCHITECTURE_MASTER.md).

### A tool appears to run but no findings are produced

Not every catalog tool has a finding parser, and parser coverage differs by tool and output version. First inspect the persisted job output and exit status:

```bash
whaxon jobs --help
whaxon findings --help
whaxon report --help
```

Check [Tools](APPLICATION_ARCHITECTURE_MASTER.md) and [Adapters](APPLICATION_ARCHITECTURE_MASTER.md) for the current catalog and registered parser inventory. An empty finding list is not proof that the target is free of vulnerabilities. Preserve raw output and report unsupported or unparsed output as a coverage limitation.

### A scan hangs or cancellation does not complete

Use the cancellation control in the active interface or the supported job-cancel API. The runner uses process-group handling for subprocess termination on POSIX; behavior can vary by platform and by external tool. Check the job state and operating-system process list before starting a duplicate scan.

### A follow-up tool did not run

The CLI `whaxon run` drains Automator follow-up jobs queued by that invocation's initial findings. It deliberately leaves jobs that were already pending before the invocation untouched. Inspect `whaxon jobs` and the persisted job history if a follow-up is missing or failed.

## Web interface and authentication

### The browser interface is unavailable

Start the foreground server with `whaxon web` and use the address printed at startup (default `http://127.0.0.1:5001`). The root route redirects to `/ui-v2`; `/ui` is the legacy/reference interface.

### Authentication fails

Loopback requests use the local-peer shortcut after Host and cross-origin checks. Remote requests require explicit non-default Basic-auth credentials. Review `WHAXON_AUTH_USER`, `WHAXON_AUTH_PASS` or `WHAXON_AUTH_PASS_HASH`, restart the service after changing environment variables, and clear cached browser Basic-auth credentials if necessary. Never expose the loopback demo defaults remotely. See [Deployment](#part-3--deploymentmd).

### A remote deployment rejects startup

Set a non-default username and strong unique password or a supported bcrypt password hash. Install the web extra and review trusted-proxy and allowed-host configuration before exposing the service. Keep the application bound to loopback behind a reverse proxy where practical.

## Docker and persistence

### Container exits during startup

Run the container in the foreground and inspect its logs. Confirm the mounted data directory is writable by the container process and that `WHAXON_DATA` points to that mount. The hardened image uses a read-only root filesystem; provide the documented writable tmpfs and persistent data volume.

### Jobs or history appear to disappear

Confirm all workers use the same `WHAXON_DATA` path and SQLite database. Check file ownership, permissions, and the database/WAL files before restarting or deleting anything. Do not remove the database as a first troubleshooting step.

## Database inspection and reset

Inspect the local database read-only where possible:

```bash
sqlite3 data/whaxon.db
sqlite> .tables
sqlite> SELECT id, tool, target, status FROM jobs ORDER BY started_at DESC LIMIT 10;
sqlite> .quit
```

Deleting `whaxon.db`, its WAL/SHM files or the configured data directory destroys local history and evidence references. Back up the complete data directory first and only reset it when loss of that data is intended.

## Getting help

Open an issue in the active repository: https://github.com/andreipath26/WHAXON-AI-Forensics/issues. Include the operating system, Python version, WHAXON package/source revision, exact command, relevant diagnostic output and job ID. Redact credentials, tokens, private target data and other sensitive evidence before sharing.


---

## Part 5 — first-run-installation-redesign.md

# Dependency readiness and guided installation

**Status reviewed 2026-11-02:** implementation exists on `main`; this is an implementation/acceptance record, not the primary operator guide. Use [dependency-readiness.md](#part-2--dependency-readinessmd) for the maintained installation instructions. The acceptance requirements below remain open unless the master roadmap records closure with evidence. CI run #41313223574 is a specific passing run from 2026-11-01, not a guarantee that every later commit or current HEAD passed. Deployment gates below remain open unless the master roadmap records closure with evidence.

## Scope and status

This implementation adds dependency diagnostics, deterministic remediation planning, a tightly allowlisted Python-package installer, durable operation tracking, readiness history, authenticated web APIs, and the first UI integration in the existing Diagnostics page.

The Diagnostics page is the canonical entry point. Its profile planner (Core, Standard, Full and Custom) expands the selected capabilities against the live dependency inventory and requests a read-only remediation plan. Each action is listed with its automation eligibility. The operator can explicitly approve the exact complete plan and queue a sequential batch of eligible Python-package installs; the shared operation panel displays progress, cancellation and verification. Individual remediation review remains available.

The batch endpoint revalidates the exact plan ID, manifest policy, active virtual environment and every action before queueing. It acquires per-dependency locks, runs packages sequentially through the existing bounded installer, stops at the first failure or cancellation, and records the result. Completed packages are not rolled back. External-tool OS packages use a separate exact-plan-approved CLI path with a deliberately narrow apt/Homebrew package allowlist; unsupported tools and hosts remain manual.

The Diagnostics page has these states:
1. Environment overview.
2. Dependency inventory.
3. Guided fix / plan review.
4. Installation progress and post-install verification.

The implementation reuses the existing `/ui-v2/diagnostics` page shell and design tokens. It does not add navigation or a replacement design system.

## Diagnostics

Run:

```bash
whaxon doctor
whaxon doctor --json
whaxon doctor --core-only
whaxon doctor --check python
whaxon doctor --verify
whaxon doctor --snapshot
whaxon doctor --drift
```

The versioned JSON report includes runtime details, active interpreter and virtual-environment state, required Python package metadata/import checks, optional extras, and external executable discovery from the packaged tool catalog. It also checks that packaged validation payloads are present, reports distinct PATH candidates for external executables, and records a local filesystem-metadata identity fingerprint. That fingerprint is not a content hash, publisher signature or supply-chain attestation.

`--verify` runs only manifest-curated, bounded external-tool version probes. It does not run arbitrary tool commands or target scans.

### Status meanings

- `READY`: the declared Python minimum is met and the package import specification is resolvable, or the runtime meets the Python minimum.
- `MISSING`: a distribution or executable could not be found.
- `INCOMPATIBLE`: an installed package or Python runtime is below the declared minimum.
- `BROKEN`: package metadata/import or a required packaged resource could not be read.
- `DETECTED`: an external executable resolves on PATH but has not passed a trusted version probe.

An overall `BLOCKED` result means a required runtime/package/resource is not READY. `DEGRADED` means optional integrations or external tools are missing or unverified. Optional tools do not block unrelated core functionality.

Diagnostics themselves do not install software, invoke package managers, access the network, use privilege escalation, or change PATH. Explicit external verification is a separate action.

## Manifest and policy

The packaged source of truth is `src/whaxon/data/dependencies.json`. It records the Python runtime, core packages, optional extras, profiles, curated external-tool probes and installation policy.

Python automatic installation is enabled only for manifest-listed `python-package` dependencies. External-tool installation is a separate CLI workflow using fixed package IDs, exact-plan approval, explicit system-change consent, separate non-interactive elevation consent, shell-free package-manager invocation and trusted version probes. The initial allowlist covers apt/Homebrew packages for Nmap, Gobuster, SQLmap and ffuf, plus Nuclei through Homebrew. The UI cannot override the Python installer policy.

## Remediation preview

Generate a read-only plan:

```bash
whaxon doctor --plan
whaxon doctor --plan --check textual
```

A plan includes a deterministic plan ID, selected dependency, exact proposed argument array and display command, package source, network/privilege impact, virtual-environment requirement, and whether automation is enabled. A plan is not authorization. No command is run while preparing it.

The plan ID is bound to the current environment, manifest and action details. If those change, the previous approval is rejected.

## Explicitly approved Python-package installation

For an eligible package, first review the complete plan, then run:

```bash
whaxon doctor --install --check textual --approve PLAN_ID
```

Replace `PLAN_ID` with the exact ID from the reviewed plan.

The installer:
- Requires an activated Python virtual environment; it will not modify a system Python installation.
- Installs only a Python distribution declared in the packaged dependency manifest.
- Enforces the manifest's `automatic_installation_enabled` and allowed-kind policy.
- Uses the active interpreter's pip with isolated pip configuration and a fixed official PyPI index.
- Accepts binary wheels only; it does not execute source build scripts.
- Does not use a shell, sudo/admin elevation, or user-supplied executable/arguments.
- Has a 15-minute timeout and supports cancellation.
- Re-checks the installed distribution version and import after installation. A pip exit code of zero is not sufficient.
- Writes a local JSONL audit record under `~/.whaxon/audit/dependency-install.jsonl` with restrictive file permissions where supported.

**Important package impact:** pip may install or update transitive dependencies required by the approved package. The plan identifies this behavior, the configured PyPI source, and the exact command before approval. The operation is not a fully hash-pinned, offline-reproducible deployment. Do not use it where a locked, hash-verified software supply chain is mandatory.

## Web API and operation lifecycle

The authenticated API exposes:
- `GET /api/dependencies` — read-only diagnostics.
- `POST /api/dependencies/verify` — explicit curated version probes.
- `POST /api/dependencies/plan` — read-only plan preview.
- `POST /api/dependencies/install` — queues an exact plan-ID-approved single-package operation and returns an operation ID.
- `POST /api/dependencies/install-batch` — queues an exact plan-ID-approved profile batch, limited to manifest-allowlisted Python packages, and returns an operation ID.
- `GET /api/dependencies/install/<operation-id>` — operation state, progress and verification result.
- `POST /api/dependencies/install/<operation-id>/cancel` — request cancellation.
- `POST /api/dependencies/snapshots` and `GET /api/dependencies/history` — local readiness history.
- `GET /api/dependencies/drift` — compare current readiness with the latest snapshot.

Operation state is stored under `<data-dir>/.whaxon/dependency-operations/` with restrictive permissions where supported. Per-dependency locks prevent concurrent installs, including conflicts between single-package and profile-batch operations; periodic progress updates support stale-worker detection. Cancellation terminates the package-manager process where possible.

The worker currently runs as a background thread in the web process. A process crash can interrupt an install; the persisted operation will be marked interrupted after its heartbeat expires. This is not a distributed job queue and does not guarantee survival across process restarts.

## Readiness snapshots and drift

The CLI supports `--snapshot` and `--drift`. History is bounded to 100 snapshots and stored under `<data-dir>/.whaxon/dependency-readiness.json`. Snapshots omit the current working directory and raw executable paths; paths are represented by one-way fingerprints so drift can be detected without persisting personal directory names.

## Failure recovery

A failed, timed-out or interrupted pip operation may have partially changed the active virtual environment. WHAXON does not claim rollback. Re-run `whaxon doctor`; if the environment is inconsistent, recreate the virtual environment and reinstall the approved dependency set. Audit and operation records include outcome and recovery guidance.

## Remaining deployment gates

**Recorded implementation and CI evidence (not full deployment acceptance):**
- CI run [#41313223574](https://github.com/andreipath26/WHAXON-AI-Forensics/actions/runs/41313223574) passed Ruff, mypy, 1,322 tests (14 skipped) and wheel/sdist metadata checks on Python 3.11, 3.12 and 3.13. Its clean Python 3.12 wheel smoke test exercised `whaxon doctor --json`, the packaged catalog/resources, scope policy and a local HTTP observation.
- Setup preview and virtual-environment smoke checks run on Ubuntu, macOS and Windows CI runners. Actual curated package installation is exercised on Ubuntu/apt and Apple Silicon macOS/Homebrew for Nmap, Gobuster, SQLmap, ffuf and Nuclei, followed by trusted version probes and selected loopback functional checks.
- Restricted-host tests cover no supported package manager, no sudo for apt, and missing elevation consent. These are policy tests, not proof of physical offline-host provisioning.
- Read-only diagnostics cover packaged payload presence, executable filesystem identity, PATH ambiguity and curated manager/OS/architecture support.

**Still open; do not advertise as accepted or production-deployable:**
- Broader package mappings and clean-machine acceptance across explicitly supported Linux distributions, native Windows and WSL2 (which must be treated as a separate Linux environment).
- Physical offline-host acceptance, writable destination validation, resource integrity hashes, and a complete artifact/transitive-dependency integrity and pinning strategy.
- Complete functional verification for every advertised external tool; current loopback checks cover selected tools and scenarios only.
- Durable worker restart/recovery. Installation work runs in a background thread in the web process; a crash can interrupt an operation. Persisted state detects interruption but does not guarantee execution survives process restarts.
- Complete browser acceptance on supported desktop targets for keyboard navigation, screen-reader announcements, cancellation races, empty/error/loading states and every UI-to-API flow.
- Independent audit trust anchoring and realistic failure/recovery acceptance.

These are roadmap/release gates, not an instruction to keep a pull request in draft. The repository currently has no open pull request for this work. Do not publish dependency readiness as a finished production feature until the outstanding gates are closed with evidence.


## Evidence principle and audit lifecycle (mandatory)

WHAXON follows five mandatory operating principles: deterministic plans, explicit informed consent, bounded execution, independent verification, and **leave evidence**. Evidence is the accountability layer that makes the first four independently enforceable.

For dependency readiness, the audit lifecycle must cover:
- Plan created or regenerated: plan ID, canonical digest, manifest/policy version, environment binding, exact proposed action and impact disclosure.
- Approval or rejection: actor, decision, timestamp, exact plan digest, approval context and expiry/revocation where applicable. A submitted plan ID alone is not proof that an informed approval occurred.
- Action lifecycle: queued, started, parameters actually passed, process identity where available, progress/state transitions, cancellation, timeout, exit/result and finish time.
- Verification: verifier identity/version, inputs, checks performed, observed distribution/version/import state, evidence digest and explicit pass/fail/inconclusive outcome.
- Recovery: trigger, diagnosis, actions recommended or taken, operator decision, resulting state and follow-up verification.
- Exceptional paths: denied approval, stale/changed plan, audit failure, worker crash/interruption, lock recovery and partial installation.

Events must share stable plan, approval, operation and dependency identifiers so an auditor can reconstruct the complete sequence. Store append-only records with restrictive access, secret redaction and minimal personal data. Add a verifiable integrity mechanism (for example, a hash chain with a documented trust anchor); append-only JSONL and filesystem permissions alone do not prove tamper-evidence. Provide an integrity-check/export path. Never report a consequential operation as fully successful when required evidence could not be persisted or verified.

**Current implementation boundary:** the installer now records plan creation, plan-ID approval submission, action start and terminal outcomes in a sequenced SHA-256-linked local JSONL chain. The chain is checked before appending and can be verified through `GET /api/dependencies/audit`; corruption fails closed. This is tamper-evident against partial modification or reordering, not immutable against an attacker who can rewrite the complete file. The current web/CLI interface does not provide a verified human identity or cryptographic proof that the plan was displayed and understood. The chain has no independently stored trust anchor, and writers are serialized with a cross-process file lock. The lack of an independently stored trust anchor remains a deployment blocker for stronger audit assurance; do not describe the ledger as tamper-proof or complete.


## First-run installation redesign (v1.0)

The current `doctor` command is a diagnostic, not a first-run installer. A clean-machine user must not be expected to interpret dependency IDs, create a virtual environment manually, or translate generic remediation advice into package-manager commands.

### Product behaviour

The first-run entry point is `whaxon setup`. It must be usable by a non-expert and must never silently elevate privileges or run a scanner against a target.

1. **Preflight:** identify OS family/version, CPU architecture, Python runtime, active environment, writable locations, available package managers, network reachability (only after consent), and whether WHAXON is installed in an isolated environment.
2. **Capability selection:** offer Core, Standard, Full and Custom profiles. Explain each capability in plain language. Core must launch without optional scanners; missing optional tools degrade only their own capabilities.
3. **Plan:** produce one reviewable installation plan, grouped by runtime, Python packages, external tools, wordlists/resources and optional integrations. Show exact package IDs, sources, commands, expected disk/network impact, privilege requirements and unsupported items. Plan generation is read-only and deterministic.
4. **Approval:** require explicit approval for each privilege boundary. Never accept arbitrary shell commands from the UI, catalog, or user input. Do not use `sudo`, UAC elevation, or administrator access without a separate clear consent step.
5. **Execution:** run only allowlisted platform-specific package-manager operations, without a shell, with bounded timeouts, cancellation, captured/redacted output, and per-operation audit records. Never execute scanner commands or contact assessment targets during installation.
6. **Verification:** check executable resolution, version, expected resources and safe local smoke tests. A package-manager exit code alone is not success.
7. **Recovery:** identify partial changes, offer precise repair guidance, and never claim rollback unless it was actually performed and verified. Persist the installation report.

### Platform policy

- **Linux:** support explicitly tested distributions and package-manager adapters (initially Debian/Ubuntu and Kali where package IDs are confirmed). Detect apt/dpkg; do not assume every Linux distribution is apt-based.
- **macOS:** use Homebrew only when installed and supported; otherwise provide the official project installation route. Never install Homebrew implicitly without consent.
- **Windows:** winget/Chocolatey/Scoop may be detected, but no native Windows package IDs are currently enabled for automatic installation; the current path is manual guidance. WSL2 is a separate Linux environment and must be detected/reported as such; do not pretend native Windows executables and WSL executables are interchangeable.
- Unsupported OS/package-manager combinations remain diagnosable and receive a precise manual route. No guessed package IDs.

### Dependency classes

- **Runtime blockers:** Python and WHAXON's mandatory runtime resources. Resolve these before installation of WHAXON itself where possible.
- **Core Python requirements:** installed by the package installer from the published wheel metadata; doctor verifies them and should explain how to repair a broken environment.
- **External security tools:** catalogued individually with platform package IDs, official source, supported architectures, version probes and safe functional verification. An unknown package mapping is never auto-installed.
- **Optional integrations:** install only when selected. They must not block core use.
- **Resources:** wordlists, templates and other data assets must have explicit source, licence, integrity hash, destination and verification. Never silently download arbitrary lists.

### Non-negotiable acceptance tests

- Fresh supported Linux, Windows and macOS environments with no optional tools installed.
- Core install, Standard install, Full install and Custom install, including cancellation and rerun.
- No-root/no-admin and unsupported-package-manager paths.
- Offline mode and interrupted/failed package-manager operations.
- No command execution during diagnostics or plan preview.
- Exact plan-to-execution binding; changed manifest, host or package selection invalidates approval.
- Audit integrity and secret redaction on success, failure, timeout and cancellation.
- Post-install verification catches missing binaries, wrong versions, broken PATH and missing resources.
- Wheel and sdist contain all manifests, adapters and required resources.
- Browser and CLI setup flows share the same backend policy and operation model.

### Current boundary and implementation sequence

This document defines the full v1.0 target; it is not a claim that every target capability is implemented. The current branch has the canonical dependency/capability manifest, read-only platform detection, deterministic profile planning, an approval-bound sequential Python-package batch engine, CLI setup command, Diagnostics profile planner and explicit profile-batch UI approval. In addition, `whaxon setup` has a separate exact-plan-approved external-tool installation path using a conservative curated package-ID allowlist on supported Linux package managers and Homebrew. This is a limited supported-platform slice, not broad cross-platform coverage. `whaxon doctor --install` remains a narrow Python-package installer and `whaxon install` remains an apt-only legacy command.

Remaining work is not the initial creation of package-manager adapters: it is extending and validating the curated mappings and sources, adding integrity and functional verification coverage, consent-bound network/offline and recovery handling, full clean-machine acceptance across explicitly supported Linux distributions/Windows/WSL2/macOS, independent audit trust anchoring, worker-restart recovery, and packaging/accessibility/end-to-end regression gates. Do not infer platform support from package-manager detection alone. Each capability requires clean-machine evidence before it is advertised as deployment-ready.


### Current `whaxon setup` command implementation

The current branch adds a read-only host detector, deterministic profile planner, approval-bound Python-package batch installation and an explicit virtual-environment bootstrap. Package-manager executables are detected read-only. A separate, exact-plan-approved CLI path now installs a conservative allowlist of external tools from curated package IDs on supported Linux managers and Homebrew; unsupported combinations remain manual. External-tool plan previews only resolve executable paths and do not run version-probe subprocesses. An already-detected executable is not treated as missing or reinstalled; trusted version probes run only after explicit submission of the reviewed plan or through `whaxon doctor --verify`.

```bash
# Create a new .venv without overwriting an existing directory
whaxon setup --create-venv

# Or choose another destination
whaxon setup --create-venv --venv-path .venvs/whaxon

# Activate the environment using the command printed by setup, then:
whaxon doctor
whaxon setup --profile core
whaxon setup --profile standard
whaxon setup --profile full
whaxon setup --profile custom --capability core --capability tui
```

After activating the newly created environment, install WHAXON into that environment with `python -m pip install --upgrade whaxon`, then run `whaxon doctor`. The setup preview prints an approval ID bound to the selected dependency set, manifest and observed environment. The current explicit installation path is:

```bash
whaxon setup --profile core
# Review the plan and its network/transitive-dependency impact.
whaxon setup --profile core --install --approve PLAN_ID
```

The Python-package batch path executes only missing, manifest-allowlisted Python packages. It requires the active virtual environment, uses the bounded pip transaction, verifies installed versions/imports and records audit events. The separate external-tool path is restricted to its curated package IDs and supported package managers. Cancellation or failure stops the batch; already completed package operations are not rolled back. A failed batch must be followed by `whaxon doctor`.

**Still open:** broad package coverage for the full tool catalog; native Windows package-manager mappings; consent-bound network preflight and offline recovery; independent audit trust anchoring; durable worker recovery across process restarts; and full clean-machine acceptance beyond the currently recorded selected Linux/macOS/Windows wheel-and-venv and package-manager smoke checks. Package-manager detection alone does not imply that an operating system is supported. The master roadmap §38 controls release acceptance; no draft-PR status is implied by this document.


### Headless Linux server acceptance

The CLI setup and doctor paths do not require a TTY, X11, Wayland, Qt, or a desktop session. The production WSGI entry point is `whaxon serve` (Waitress); the headless CI gate installs the web extra, removes display/session variables, runs setup preview and doctor, then starts Waitress and performs an HTTP request against loopback. This verifies a no-GUI/no-TTY server process, not a hardened public deployment. Remote deployments must configure explicit non-default authentication credentials and a protected data directory; do not expose the development `whaxon web` server or default credentials.


---

## Part 6 — demo.md

# Demo Script

A scripted walkthrough for a controlled lab. Use a Metasploitable2 VM or another target you own and have explicitly authorized. The example address below is illustrative; substitute the actual lab address and add it to the active scope before running any tool.

## 0:00 - Setup

```bash
cd WHAXON-AI-Forensics
source .venv/bin/activate
whaxon web
```

Open [http://127.0.0.1:5001/](http://127.0.0.1:5001/). The root route redirects to the canonical `/ui-v2` interface. Loopback requests use the local-peer authentication shortcut; if prompted, use locally configured credentials. Never expose default credentials remotely.

## 0:10 - Scope check

```bash
whaxon scope --show
whaxon scope --check 10.0.0.42
```

Confirm that the target is explicitly listed and authorized. Private addressing is not proof of authorization; scope checks are application-level preflight controls, not a network firewall.

## 0:20 - Run a tool

In the browser, select nmap, enter the explicitly authorized lab target, and submit the job. Review streamed output, persisted findings and evidence. Do not assume every nmap line becomes a finding; parser coverage and tool output determine what is recorded.

## 0:35 - Review findings

Open the job's findings and inspect the raw evidence and coverage. Correlation is data-dependent: only describe a correlated finding if the actual run produced one. Do not stage or imply a finding that was not observed.

## 0:45 - AI planner

AI planning is optional and provider-dependent. If enabled, use a lab target and review the proposed plan. A proposal is not authorization or execution evidence; only supported, approved actions can be executed.

## 1:05 - Reports

Export a report for the selected job. Review the coverage, verification state and limitations before presenting it as a client deliverable. Reports contain only the data actually persisted by the selected workflow.

## 1:20 - Cleanup

Stop the foreground server with Ctrl+C. If you deliberately started it as a daemon, use the PID file documented by the installed version and confirm the PID belongs to WHAXON before terminating it.

## Recording notes

- Use a lab target and show the active scope before execution.
- Do not fabricate findings or claim planner proposals were executed.
- Keep credentials, customer data and sensitive evidence out of screenshots and recordings.


---

## Part 7 — screenshots.md

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
    xdg-open http://127.0.0.1:5001/

Run nmap against your target from the UI. Wait for findings to appear, expand one finding, then capture.

- File: docs/assets/web-ui.png
- Alt text: WHAXON web interface showing a live nmap job and expanded findings.

## Desktop capture

    whaxon gui

Wait for the embedded web view to load, then capture the whole window.

- File: docs/assets/gui.png
- Alt text: WHAXON desktop application rendering the same web UI.

## PDF report capture

    # Loopback requests use the local-peer shortcut; configure credentials for remote access.
    JID=$(curl -fsS http://127.0.0.1:5001/api/history | python3 -c "import sys,json;print(json.load(sys.stdin)[0][chr(39)+chr(105)+chr(100)+chr(39)])")
    whaxon report "$JID" --format pdf --out /tmp/report.pdf
    xdg-open /tmp/report.pdf

Capture the executive summary page. Confirm that the report contains real data from the selected authorized lab run.

- File: docs/assets/report-pdf.png
- Alt text: Exported WHAXON PDF report showing the executive summary.

## Pivot chain capture

Requires at least one pivot edge in the store. Run an exploit through MSF, add a port forward, then open the Chains page in the `/ui-v2` interface.

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

