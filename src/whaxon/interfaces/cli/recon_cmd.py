"""whaxon recon <target> — passive recon pass (DNS, SSL, headers, tech, etc.)."""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

from whaxon.core import Core
from whaxon.core.dns_full_v2 import CAPABILITY_ID as DNS_FULL_CAPABILITY_ID
from whaxon.core.headers_v2 import CAPABILITY_ID as HEADERS_RECON_CAPABILITY_ID
from whaxon.core.http_recon_v2 import CAPABILITY_ID as HTTPS_RECON_CAPABILITY_ID
from whaxon.core.recon_v2 import CAPABILITY_ID
from whaxon.core.redirect_recon_v2 import CAPABILITY_ID as REDIRECT_RECON_CAPABILITY_ID
from whaxon.core.robots_recon_v2 import CAPABILITY_ID as ROBOTS_RECON_CAPABILITY_ID
from whaxon.core.security_txt_v2 import CAPABILITY_ID as SECURITY_TXT_RECON_CAPABILITY_ID
from whaxon.core.tls_cert_v2 import CAPABILITY_ID as TLS_CERT_CAPABILITY_ID

EXIT_OK = 0
EXIT_OUT_OF_SCOPE = 1
EXIT_USAGE = 2
EXIT_ERROR = 3
EXIT_V2_WORKFLOW_REQUIRED = 5


def main(args: list[str] | None = None) -> int:
    args = list(args or [])
    data_dir = Path("data")
    checks: list[str] | None = None
    verbose = False
    engine = "v2"
    legacy_selected = False
    mission_id: str | None = None
    plan_id: str | None = None
    positional: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif a == "--checks" and i + 1 < len(args):
            checks = [c.strip() for c in args[i + 1].split(",") if c.strip()]
            i += 2
        elif a == "--engine" and i + 1 < len(args):
            engine = args[i + 1]; i += 2
        elif a == "--plan-id" and i + 1 < len(args):
            plan_id = args[i + 1]; i += 2
        elif a == "--mission-id" and i + 1 < len(args):
            mission_id = args[i + 1]; i += 2
        elif a == "--legacy":
            legacy_selected = True; engine = "legacy"; i += 1
        elif a in ("-v", "--verbose"):
            verbose = True; i += 1
        elif a in ("-h", "--help"):
            _usage()
            return EXIT_OK
        else:
            positional.append(a); i += 1

    if len(positional) != 1 or engine not in {"legacy", "v2"}:
        _usage()
        return EXIT_USAGE
    if (engine == "v2" and legacy_selected) or (
        engine == "legacy" and (plan_id is not None or mission_id is not None)
    ):
        _usage()
        return EXIT_USAGE

    target = positional[0]
    core = Core(data_dir)

    if verbose:
        print(f"[recon] target={target}", file=sys.stderr)
        print(f"[recon] data_dir={data_dir}", file=sys.stderr)
        print(f"[recon] checks={checks or 'all'}", file=sys.stderr)
        print(f"[recon] engine={engine}", file=sys.stderr)

    if engine == "v2":
        if plan_id and mission_id is None:
            if checks is not None:
                _usage()
                return EXIT_USAGE
            return _run_v2(core, target, plan_id, verbose=verbose)
        return _propose_v2(
            core, target, checks=checks, mission_id=mission_id,
            plan_id=plan_id, verbose=verbose,
        )

    legacy_enabled = os.environ.get(
        "WHAXON_LEGACY_RECON_ENABLED", "false",
    ).strip().lower() in {"1", "true", "yes"}
    if not legacy_selected or not legacy_enabled:
        print(
            "Legacy direct reconnaissance is disabled. The default creates a "
            "reviewable Engine V2 plan without dispatch; set "
            "WHAXON_LEGACY_RECON_ENABLED=true and pass --legacy only for the "
            "compatibility path.",
            file=sys.stderr,
        )
        return EXIT_V2_WORKFLOW_REQUIRED

    asyncio.run(core.initialize(drain=False))
    match = core.scope.check(target)
    if verbose:
        print(f"[recon] scope: allowed={match.allowed} reason={match.reason} rule={match.matched_rule}", file=sys.stderr)
    if not match.allowed:
        print(f"Out of scope: {target} ({match.reason})", file=sys.stderr)
        return EXIT_OUT_OF_SCOPE

    if verbose:
        print("[recon] running checks...", file=sys.stderr)
    job_id = core.recon.run(target, checks=checks)
    if verbose:
        print(f"[recon] job_id={job_id}", file=sys.stderr)
    if job_id is None:
        print(f"No findings for {target}", file=sys.stderr)
        return EXIT_OK

    findings = core.store.get_findings(job_id)
    print(f"recon: {target}  (job {job_id}, {len(findings)} findings)")
    for f in findings:
        print(f"  [{f['severity']:8s}] {f['kind']:28s} {f['raw_line'][:90]}")
        if verbose:
            print(f"    data: {f.get('data')}", file=sys.stderr)
            print(f"    remediation: {f.get('remediation', '')[:120]}", file=sys.stderr)
            print(f"    impact: {f.get('impact', '')[:120]}", file=sys.stderr)
    return EXIT_OK


def _propose_v2(
    core: Core,
    target: str,
    *,
    checks: list[str] | None,
    mission_id: str | None,
    plan_id: str | None,
    verbose: bool,
) -> int:
    """Persist a fixed recon proposal; approval and dispatch stay separate."""
    from whaxon.core.workflow import WorkflowPlan
    from whaxon.core.workflow_proposals import propose_passive_recon_plan

    mission_id = mission_id or f"recon-mission-{uuid.uuid4().hex[:12]}"
    plan_id = plan_id or f"recon-plan-{uuid.uuid4().hex[:12]}"
    try:
        asyncio.run(core.initialize(drain=False))
        scope = core.scope.check(target)
        if not scope.allowed:
            print(f"Out of scope: {target} ({scope.reason})", file=sys.stderr)
            return EXIT_OUT_OF_SCOPE
        if core.store.get_mission(mission_id) is None:
            core.create_mission(mission_id, f"Passive reconnaissance of {target}")
        proposal = propose_passive_recon_plan(
            core, mission_id=mission_id, plan_id=plan_id,
            target=target, checks=checks,
        )
        if proposal.get("status") != "proposed":
            print(
                f"V2 recon proposal blocked: {proposal.get('reason', 'unknown reason')}",
                file=sys.stderr,
            )
            return EXIT_V2_WORKFLOW_REQUIRED
        saved = core.save_workflow_plan(
            plan_id, WorkflowPlan.from_dict(proposal["plan"]),
        )
        if not saved:
            print("V2 recon plan was not saved; no action was dispatched", file=sys.stderr)
            return EXIT_ERROR
    except (OSError, ValueError, TypeError, RuntimeError, KeyError) as exc:
        print(f"V2 recon proposal failed: {exc}; no action was dispatched", file=sys.stderr)
        return EXIT_ERROR

    plan = proposal["plan"]
    tasks = plan.get("tasks", []) if isinstance(plan, dict) else []
    print(
        f"recon plan: {target}  (mission {mission_id}, plan {plan_id}, "
        f"{len(tasks)} tasks; proposed, not approved or dispatched)"
    )
    print(f"  digest: {proposal['digest']}")
    print("  included: " + ", ".join(proposal.get("included_checks", [])))
    for omitted in proposal.get("omitted_checks", []):
        print(f"  omitted {omitted.get('check')}: {omitted.get('reason')}")
    print(f"  review: whaxon workflow plan show --id {plan_id}")
    for task in tasks:
        task_id = task.get("id") if isinstance(task, dict) else None
        if isinstance(task_id, str):
            print(
                f"  approve {task_id}: whaxon workflow plan approval grant "
                f"--id {plan_id} --task {task_id} --approval-id <unique-id> "
                "--actor <operator> --expires-at <unix-time>"
            )
    print(
        "  after reviewing and granting the listed approvals, submit with: "
        f"whaxon workflow plan submit-run --id {plan_id}"
    )
    if verbose:
        print(f"V2 plan digest={proposal['digest']}", file=sys.stderr)
    return EXIT_OK


def _run_v2(core: Core, target: str, plan_id: str, *, verbose: bool) -> int:
    """Submit one matching persisted fixed recon plan to the V2 worker queue."""
    try:
        details = core.workflow_plan_details(plan_id)
    except (ValueError, TypeError, RuntimeError) as exc:
        print(f"V2 recon plan rejected: {exc}", file=sys.stderr)
        return EXIT_USAGE

    plan = details.get("plan")
    tasks = plan.get("tasks") if isinstance(plan, dict) else None
    if not isinstance(tasks, list) or not tasks or any(not isinstance(task, dict) for task in tasks):
        print("V2 recon requires a persisted plan with one or more fixed tasks", file=sys.stderr)
        return EXIT_USAGE

    allowed_capabilities = {
            CAPABILITY_ID, DNS_FULL_CAPABILITY_ID, TLS_CERT_CAPABILITY_ID,
            HTTPS_RECON_CAPABILITY_ID,
            REDIRECT_RECON_CAPABILITY_ID,
            ROBOTS_RECON_CAPABILITY_ID, SECURITY_TXT_RECON_CAPABILITY_ID,
            HEADERS_RECON_CAPABILITY_ID,
        }
    task_bindings: set[tuple[str, str]] = set()
    invalid_task = False
    for task in tasks:
        capability_id = task.get("capability_id")
        task_target = task.get("target")
        if (
            not isinstance(capability_id, str)
            or capability_id not in allowed_capabilities
            or task_target != target
            or task.get("inputs") != {}
            or task.get("depends_on", []) != []
        ):
            invalid_task = True
            break
        binding = (capability_id, task_target)
        if binding in task_bindings:
            invalid_task = True
            break
        task_bindings.add(binding)
    if invalid_task:
        print(
            "V2 recon plan must contain only fixed DNS, TLS, HTTPS, headers, redirects, robots, or security.txt tasks matching the target",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        async def submit():
            await core.initialize(drain=False)
            return core.enqueue_workflow_run(plan_id)

        request = asyncio.run(submit())
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        print(f"V2 recon request failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not isinstance(request, dict) or not isinstance(request.get("id"), str):
        print("V2 recon request was not persisted; no action was dispatched", file=sys.stderr)
        return EXIT_ERROR
    request_status = request.get("status", "unknown")
    print(
        f"recon: {target}  (plan {plan_id}, request {request['id']}, "
        f"{request_status}; queued for the supervised V2 worker)"
    )
    print(f"  inspect: whaxon workflow plan run-snapshot --id {request['id']}")
    print("  worker: whaxon workflow plan serve-requests")
    if verbose:
        print(f"V2 run request status={request_status}", file=sys.stderr)
    return EXIT_OK


def _usage() -> None:
    print(
        "Usage: whaxon recon <target> [--data DIR] [--checks a,b,c] [--mission-id ID] [--plan-id ID]\n"
        "       whaxon recon <target> --engine v2 --plan-id ID [--data DIR]\n"
        "       whaxon recon <target> --legacy [--checks a,b,c] [--data DIR]\n"
        "\n"
        "  Default: create a persisted, reviewable V2 plan from ready fixed providers; never approve or dispatch it.\n"
        "  --checks may select dns, dns_full, ssl, https, headers, redirects, robots, or security_txt.\n"
        "  Legacy-only tech, cookies, and waf checks are omitted from a default plan and block an explicit V2 selection.\n"
        "  --legacy preserves the compatibility runner only when WHAXON_LEGACY_RECON_ENABLED=true.\n"
        "  V2 execution requires a persisted plan with exact approval.\n"
        "\n"
        "  V2 proposal checks:\n"
        "    dns        A/AAAA/MX/NS/TXT/SOA records\n"
        "    ssl        TLS certificate, SANs, expiry\n"
        "    headers    missing security headers\n"
        "    https      fixed root-response observation\n"
        "    robots     /robots.txt and /sitemap.xml\n"
        "    security_txt  /.well-known/security.txt (RFC 9116)\n"
        "    redirects  one HTTPS first hop; never follows Location\n"
        "    dns_full   CAA, DMARC, SPF records\n"
        "\n"
        "  Default: propose ready V2 checks and list omissions. Legacy-only checks are tech, cookies, and waf.",
        file=sys.stderr,
    )
