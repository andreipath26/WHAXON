"""Headless Engine v2 workflow commands."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import threading
from pathlib import Path

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan


def _run_async(coroutine):
    """Run an async command from both ordinary and event-loop-hosted callers."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)

    result = []
    failure = []

    def _runner():
        try:
            result.append(asyncio.run(coroutine))
        except BaseException as exc:
            failure.append(exc)

    thread = threading.Thread(target=_runner, name="whaxon-workflow-cli")
    thread.start()
    thread.join()
    if failure:
        raise failure[0]
    return result[0]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="whaxon workflow")
    parser.add_argument(
        "--data-dir", default=os.environ.get("WHAXON_DATA", "data"),
        help="WHAXON state directory (default: WHAXON_DATA or ./data)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("capabilities", help="list registered Engine v2 capabilities")
    commands.add_parser("providers", help="inspect live provider readiness")
    commands.add_parser("portfolio-audit", help="reconcile catalog and adapters (read-only)")

    mission = commands.add_parser("mission", help="manage missions")
    mission_commands = mission.add_subparsers(dest="mission_command", required=True)
    mission_cost = mission_commands.add_parser(
        "cost-limit", help="configure cumulative provider-reported mission cost cap (micro-USD)",
    )
    mission_cost.add_argument("--id", required=True)
    mission_cost.add_argument("--max-cost-microusd", type=int, required=True)
    cost_summary = mission_commands.add_parser(
        "cost", help="inspect measured cost and incomplete reporting",
    )
    cost_summary.add_argument("--id", required=True)
    mission_rate = mission_commands.add_parser(
        "rate-limit", help="set mission-wide claim spacing across all plans",
    )
    mission_rate.add_argument("--id", required=True)
    mission_rate.add_argument("--min-spacing-s", type=float, required=True)
    mission_rate_status = mission_commands.add_parser(
        "rate", help="inspect the persisted mission-wide claim spacing",
    )
    mission_rate_status.add_argument("--id", required=True)
    mission_deadline = mission_commands.add_parser(
        "deadline", help="set a mission-wide absolute execution cutoff",
    )
    mission_deadline.add_argument("--id", required=True)
    mission_deadline.add_argument("--unix-time", type=float, required=True)
    mission_limits = mission_commands.add_parser(
        "limits", help="configure mission-wide cumulative and concurrent attempt limits",
    )
    mission_limits.add_argument("--id", required=True)
    mission_limits.add_argument("--max-total-attempts", type=int, required=True)
    mission_limits.add_argument("--max-concurrency", type=int, required=True)
    mission_status = mission_commands.add_parser(
        "budget", help="show mission-wide usage and configured limits",
    )
    mission_status.add_argument("--id", required=True)
    mission_list = mission_commands.add_parser("list", help="list durable missions")
    mission_list.add_argument("--limit", type=int, default=100)
    mission_list.add_argument("--after-created", type=float, default=0.0)
    create = mission_commands.add_parser("create", help="create a mission")
    create.add_argument("--id", required=True)
    create.add_argument("--objective", required=True)
    mission_plans = mission_commands.add_parser(
        "plans", help="list persisted plans for a mission",
    )
    mission_plans.add_argument("--id", required=True)
    mission_report = mission_commands.add_parser(
        "report", help="aggregate a sequenced release chain from persisted plan evidence",
    )
    mission_report.add_argument("--id", required=True)
    mission_report.add_argument(
        "--plan-id", action="append", dest="plan_ids",
        help="plan ID in chain order; repeat once per stage (default: recorded mission plans)",
    )
    mission_report.add_argument("--limit", type=int, default=100)

    plan = commands.add_parser("plan", help="manage persisted workflow plans")
    plan_commands = plan.add_subparsers(dest="plan_command", required=True)
    attempt_cost = plan_commands.add_parser(
        "record-cost", help="record evidence-backed final attempt cost",
    )
    attempt_cost.add_argument("--attempt-id", required=True)
    attempt_cost.add_argument("--cost-microusd", required=True, type=int)
    attempt_cost.add_argument("--source", required=True)
    approval = plan_commands.add_parser(
        "approval", help="inspect and manage attributable task approvals",
    )
    approval_commands = approval.add_subparsers(dest="approval_command", required=True)
    approval_list = approval_commands.add_parser("list", help="list approvals")
    approval_list.add_argument("--id", required=True, help="plan identifier")
    approval_grant = approval_commands.add_parser("grant", help="persist bounded consent")
    approval_grant.add_argument("--id", required=True)
    approval_grant.add_argument("--task", required=True)
    approval_grant.add_argument("--approval-id", required=True)
    approval_grant.add_argument("--actor", required=True)
    approval_grant.add_argument("--expires-at", type=float, required=True)
    approval_revoke = approval_commands.add_parser("revoke", help="revoke task consent")
    approval_revoke.add_argument("--id", required=True)
    approval_revoke.add_argument("--approval-id", required=True)
    approval_revoke.add_argument("--actor", required=True)
    save = plan_commands.add_parser("save", help="validate and persist a JSON workflow plan")
    save.add_argument("--id", required=True, help="immutable persisted plan identifier")
    save.add_argument("--file", required=True, type=Path, help="JSON file containing a WorkflowPlan")
    followups = plan_commands.add_parser(
        "followups", help="propose tasks from verified workflow evidence",
    )
    followups.add_argument("--source-id", required=True)
    followups.add_argument("--max-tasks", type=int, default=16)
    followups.add_argument("--save", action="store_true",
                           help="persist but never approve or run the proposal")
    ai_propose = plan_commands.add_parser(
        "ai-propose", help="convert one AI action into a reviewable V2 plan",
    )
    ai_propose.add_argument("--mission-id", required=True)
    ai_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    ai_propose.add_argument("--goal", required=True)
    ai_propose.add_argument("--target", required=True,
                            help="exact operator-authorized target for this proposal")
    ai_propose.add_argument("--step", type=int, default=1)
    ai_propose.add_argument("--history-file", type=Path,
                            help="JSON array of prior AI action results")
    ai_propose.add_argument("--save", action="store_true",
                            help="persist the proposal; approval and execution remain separate")
    tool_propose = plan_commands.add_parser(
        "propose-tool", help="prepare a fixed-argument catalog tool plan for review",
    )
    tool_propose.add_argument("--mission-id", required=True)
    tool_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    tool_propose.add_argument("--tool", required=True, help="catalog tool ID")
    tool_propose.add_argument("--target", required=True, help="exact in-scope target")
    tool_propose.add_argument("--save", action="store_true",
                              help="persist only; approval and execution remain separate")
    dns_propose = plan_commands.add_parser(
        "propose-dns-recon", help="prepare a fixed passive-DNS V2 plan for review",
    )
    dns_propose.add_argument("--mission-id", required=True)
    dns_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    dns_propose.add_argument("--target", required=True, help="exact hostname in DNS-query scope")
    dns_propose.add_argument("--save", action="store_true",
                             help="persist only; approval and execution remain separate")
    dns_full_propose = plan_commands.add_parser(
        "propose-dns-full",
        help="prepare a fixed CAA/DMARC/SPF V2 DNS posture plan for review",
    )
    dns_full_propose.add_argument("--mission-id", required=True)
    dns_full_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    dns_full_propose.add_argument(
        "--target", required=True,
        help="hostname and _dmarc subdomain in DNS-query scope",
    )
    dns_full_propose.add_argument("--save", action="store_true",
                                  help="persist only; approval and execution remain separate")
    tls_propose = plan_commands.add_parser(
        "propose-tls-recon",
        help="prepare a fixed-port pinned TLS certificate plan for operator review",
    )
    tls_propose.add_argument("--mission-id", required=True)
    tls_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    tls_propose.add_argument("--target", required=True, help="hostname in pinned network scope")
    tls_propose.add_argument("--save", action="store_true",
                             help="persist only; exact approval is required before execution")
    https_propose = plan_commands.add_parser(
        "propose-https-recon",
        help="prepare a fixed scope-pinned HTTPS header reconnaissance plan for review",
    )
    https_propose.add_argument("--mission-id", required=True)
    https_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    https_propose.add_argument("--target", required=True, help="bare hostname or IP in pinned scope")
    https_propose.add_argument(
        "--save", action="store_true",
        help="persist only; approval and execution remain separate",
    )
    security_txt_propose = plan_commands.add_parser(
        "propose-security-txt-recon",
        help="prepare one fixed scope-pinned security.txt HTTPS request for review",
    )
    security_txt_propose.add_argument("--mission-id", required=True)
    security_txt_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    security_txt_propose.add_argument("--target", required=True, help="bare hostname or IP in pinned scope")
    security_txt_propose.add_argument(
        "--save", action="store_true",
        help="persist only; approval and execution remain separate",
    )
    headers_propose = plan_commands.add_parser(
        "propose-headers-recon",
        help="prepare one fixed scope-pinned security-header HTTPS request for review",
    )
    headers_propose.add_argument("--mission-id", required=True)
    headers_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    headers_propose.add_argument("--target", required=True, help="bare hostname or IP in pinned scope")
    headers_propose.add_argument(
        "--save", action="store_true",
        help="persist only; approval and execution remain separate",
    )
    robots_propose = plan_commands.add_parser(
        "propose-robots-recon",
        help="prepare fixed scope-pinned robots.txt/sitemap HTTPS requests for review",
    )
    robots_propose.add_argument("--mission-id", required=True)
    robots_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    robots_propose.add_argument("--target", required=True, help="bare hostname or IP in pinned scope")
    robots_propose.add_argument(
        "--save", action="store_true",
        help="persist only; approval and execution remain separate",
    )
    redirects_propose = plan_commands.add_parser(
        "propose-redirect-recon",
        help="prepare one first-hop HTTPS redirect observation for review; never follow Location",
    )
    redirects_propose.add_argument("--mission-id", required=True)
    redirects_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    redirects_propose.add_argument("--target", required=True, help="bare hostname or IP in pinned scope")
    redirects_propose.add_argument(
        "--save", action="store_true",
        help="persist only; approval and execution remain separate",
    )
    verify_propose = plan_commands.add_parser(
        "propose-verification", help="prepare a sealed-finding V2 verification or retest plan",
    )
    verify_propose.add_argument("--mission-id", required=True)
    verify_propose.add_argument("--id", required=True, help="immutable workflow plan ID")
    verify_propose.add_argument("--source-job-id", required=True)
    verify_propose.add_argument("--finding-seq", required=True, type=int)
    verify_propose.add_argument("--mode", required=True, choices=("verify", "retest"))
    verify_propose.add_argument("--save", action="store_true",
                                help="persist only; approval and execution remain separate")
    show = plan_commands.add_parser("show", help="show a plan and its durable task states")
    show.add_argument("--id", required=True)
    reconcile_report = plan_commands.add_parser(
        "reconciliation-report", help="show attempts requiring external effect reconciliation",
    )
    reconcile_report.add_argument("--id", required=True)
    readiness = plan_commands.add_parser(
        "readiness", help="check durable workflow completion and reconciliation gates",
    )
    readiness.add_argument("--id", required=True)
    evidence = plan_commands.add_parser(
        "evidence", help="inspect persisted tool evidence linked to workflow attempts",
    )
    evidence.add_argument("--id", required=True)
    evidence.add_argument("--limit", type=int, default=100)
    report = plan_commands.add_parser(
        "report", help="render only persisted evidence linked to a workflow plan",
    )
    report.add_argument("--id", required=True)
    report.add_argument("--limit", type=int, default=100)
    resources = plan_commands.add_parser(
        "resources", help="show measured workflow utilization and unavailable metrics",
    )
    resources.add_argument("--id", required=True)
    audit = plan_commands.add_parser("audit", help="verify persisted attempt/event consistency")
    audit.add_argument("--id", required=True)
    audit_snapshot = plan_commands.add_parser(
        "audit-snapshot", help="print read-only lifecycle digest for external retention",
    )
    audit_snapshot.add_argument("--id", required=True)
    audit_verify = plan_commands.add_parser(
        "audit-verify", help="compare lifecycle state to externally retained SHA-256",
    )
    audit_verify.add_argument("--id", required=True)
    audit_verify.add_argument("--expected-digest", required=True)
    attempts = plan_commands.add_parser("attempts", help="inspect durable task attempts")
    attempts.add_argument("--id", required=True)
    attempts.add_argument("--after-started", type=float, default=0.0)
    attempts.add_argument("--limit", type=int, default=100)
    progress = plan_commands.add_parser("progress", help="show persisted workflow progress")
    progress.add_argument("--id", required=True)
    events = plan_commands.add_parser("events", help="read durable lifecycle events")
    events.add_argument("--id", required=True)
    events.add_argument("--after-id", type=int, default=0)
    events.add_argument("--limit", type=int, default=100)
    inbox = plan_commands.add_parser("event-inbox", help="read consumer-specific unacknowledged events")
    inbox.add_argument("--id", required=True)
    inbox.add_argument("--consumer", required=True)
    inbox.add_argument("--limit", type=int, default=100)
    ack = plan_commands.add_parser("event-ack", help="persist processed event checkpoint")
    ack.add_argument("--id", required=True)
    ack.add_argument("--consumer", required=True)
    ack.add_argument("--event-id", type=int, required=True)
    cancel = plan_commands.add_parser("cancel", help="persist workflow stop intent")
    cancel.add_argument("--id", required=True)
    recover = plan_commands.add_parser(
        "reconcile", help="mark expired workflow attempts uncertain without replay",
    )
    recover.add_argument("--id", required=True)
    recover.add_argument("--stale-after-seconds", type=float, default=60.0)
    resolve_attempt = plan_commands.add_parser(
        "resolve-attempt",
        help="record an operator outcome for an uncertain provider effect; never replay automatically",
    )
    resolve_attempt.add_argument("--id", required=True)
    resolve_attempt.add_argument("--attempt-id", required=True)
    resolve_attempt.add_argument(
        "--disposition", required=True,
        choices=("no_effect_verified", "effect_observed", "unresolved"),
    )
    resolve_attempt.add_argument("--actor", required=True)
    resolve_attempt.add_argument("--evidence-ref", required=True)
    resolve_attempt.add_argument("--note", required=True)
    rate = plan_commands.add_parser("rate-limit", help="set a durable minimum claim interval")
    rate.add_argument("--id", required=True)
    rate.add_argument("--min-spacing-seconds", type=float, required=True)
    deadline = plan_commands.add_parser("deadline", help="set a durable absolute cutoff")
    deadline.add_argument("--id", required=True)
    deadline.add_argument("--unix-time", type=float, required=True)
    limits = plan_commands.add_parser("limits", help="tighten durable plan limits")
    limits.add_argument("--id", required=True)
    limits.add_argument("--max-total-attempts", type=int, required=True)
    limits.add_argument("--max-concurrency", type=int, required=True)

    submit = plan_commands.add_parser(
        "submit-run", help="persist a bounded V2 run intent for the durable worker",
    )
    submit.add_argument("--id", required=True)
    submit.add_argument("--max-tasks", type=int, default=100)
    submit.add_argument("--max-attempts", type=int, default=2)
    submit.add_argument("--max-concurrency", type=int, default=4)
    service = plan_commands.add_parser(
        "serve-requests", help="continuously process durable V2 run requests",
    )
    service.add_argument("--poll-interval", type=float, default=1.0)
    service.add_argument("--max-runs-per-batch", type=int, default=20)
    drain = plan_commands.add_parser(
        "drain-requests", help="claim queued V2 workflow requests after restart",
    )
    drain.add_argument("--max-runs", type=int, default=20)
    plan_commands.add_parser(
        "queue-summary", help="inspect durable run queue and reconciliation risks",
    )
    request_status = plan_commands.add_parser(
        "run-request", help="inspect persisted V2 execution request status",
    )
    request_status.add_argument("--id", required=True)
    snapshot = plan_commands.add_parser(
        "run-snapshot", help="inspect persisted request and workflow progress",
    )
    snapshot.add_argument("--id", required=True)
    cancel_request = plan_commands.add_parser(
        "cancel-request", help="persist cancellation for a durable run request",
    )
    cancel_request.add_argument("--id", required=True)
    run = plan_commands.add_parser(
        "run", help="persist a run request for the supervised V2 worker",
    )
    run.add_argument("--id", required=True)
    run.add_argument("--max-tasks", type=int, default=100)
    run.add_argument("--max-attempts", type=int, default=2)
    run.add_argument("--max-concurrency", type=int, default=4,
                     help="maximum independent workflow tasks running at once")
    return parser


def main(args: list[str] | None = None) -> int:
    options = _parser().parse_args(args)
    core = Core(data_dir=Path(options.data_dir))
    try:
        if options.command == "capabilities":
            capability_result = [manifest.to_dict() for manifest in core.capabilities.list()]
            print(json.dumps(capability_result, indent=2, sort_keys=True))
            return 0
        if options.command == "providers":
            print(json.dumps(core.capability_inventory(), indent=2, sort_keys=True))
            return 0
        if options.command == "portfolio-audit":
            print(json.dumps(core.capability_portfolio_audit(), indent=2, sort_keys=True))
            return 0
        if options.command == "mission" and options.mission_command == "cost-limit":
            core.configure_mission_cost_limit(
                options.id, max_cost_microusd=options.max_cost_microusd,
            )
            print(json.dumps(core.mission_cost_summary(options.id), sort_keys=True))
            return 0
        if options.command == "mission" and options.mission_command == "cost":
            print(json.dumps(core.mission_cost_summary(options.id), sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "record-cost":
            amount = core.record_workflow_attempt_cost(
                options.attempt_id,
                cost_microusd=options.cost_microusd, source=options.source,
            )
            print(json.dumps({"attempt_id": options.attempt_id, "cost_microusd": amount}))
            return 0
        if options.command == "mission" and options.mission_command == "rate-limit":
            core.configure_mission_rate_limit(options.id, min_spacing_s=options.min_spacing_s)
            print(json.dumps(core.mission_rate_limit(options.id), sort_keys=True))
            return 0
        if options.command == "mission" and options.mission_command == "rate":
            print(json.dumps(core.mission_rate_limit(options.id), sort_keys=True))
            return 0
        if options.command == "mission" and options.mission_command == "deadline":
            core.configure_mission_deadline(options.id, deadline_at=options.unix_time)
            print(json.dumps({
                "mission_id": options.id, "deadline_at": core.mission_deadline(options.id),
            }, sort_keys=True))
            return 0
        if options.command == "mission" and options.mission_command == "limits":
            core.configure_mission_execution_limits(
                options.id, max_total_attempts=options.max_total_attempts,
                max_concurrency=options.max_concurrency,
            )
            print(json.dumps(core.mission_execution_limits(options.id), sort_keys=True))
            return 0
        if options.command == "mission" and options.mission_command == "budget":
            print(json.dumps(core.mission_execution_limits(options.id), sort_keys=True))
            return 0
        if options.command == "mission" and options.mission_command == "list":
            print(json.dumps(core.missions(
                limit=options.limit, after_created=options.after_created,
            ), indent=2, sort_keys=True))
            return 0
        if options.command == "mission" and options.mission_command == "create":
            created = core.create_mission(options.id, options.objective)
            print(json.dumps({"mission_id": options.id, "created": bool(created)}))
            return 0
        if options.command == "mission" and options.mission_command == "plans":
            print(json.dumps(
                core.mission_workflow_plans(options.id), indent=2, sort_keys=True,
            ))
            return 0
        if options.command == "mission" and options.mission_command == "report":
            report = core.workflow_mission_report(
                options.id, plan_ids=options.plan_ids, limit=options.limit,
            )
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["status"] == "complete" else 1
        if options.command == "plan" and options.plan_command == "approval":
            if options.approval_command == "list":
                print(json.dumps(
                    core.workflow_approvals(options.id), indent=2, sort_keys=True,
                ))
                return 0
            if options.approval_command == "grant":
                created = core.grant_workflow_approval(
                    options.id, options.task, options.approval_id, options.actor,
                    expires_at=options.expires_at,
                )
                print(json.dumps({"approval_id": options.approval_id, "created": created}))
                return 0
            if options.approval_command == "revoke":
                revoked = core.revoke_workflow_approval(
                    options.id, options.approval_id, actor=options.actor,
                )
                print(json.dumps({"approval_id": options.approval_id, "revoked": revoked}))
                return 0
        if options.command == "plan" and options.plan_command == "followups":
            proposal = core.propose_workflow_followups(
                options.source_id, max_tasks=options.max_tasks,
            )
            created = False
            if options.save and proposal.plan is not None:
                created = core.save_workflow_plan(proposal.plan_id, proposal.plan)
            print(json.dumps({**proposal.to_dict(), "created": bool(created)},
                             indent=2, sort_keys=True))
            return 0 if proposal.plan is not None else 1
        if options.command == "plan" and options.plan_command == "ai-propose":
            from whaxon.core.ai_bridge import propose_v2_workflow_plan

            history = []
            if options.history_file is not None:
                history = json.loads(options.history_file.read_text(encoding="utf-8"))
            proposal = propose_v2_workflow_plan(
                core,
                mission_id=options.mission_id,
                plan_id=options.id,
                goal=options.goal,
                target=options.target,
                history=history,
                step=options.step,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    options.id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            print(json.dumps({**proposal, "created": bool(created)},
                             indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "propose-tool":
            from whaxon.core.workflow_proposals import propose_tool_workflow_plan

            proposal = propose_tool_workflow_plan(
                core,
                mission_id=options.mission_id,
                plan_id=options.id,
                tool_id=options.tool,
                target=options.target,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    options.id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            print(json.dumps({**proposal, "created": bool(created)},
                             indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "propose-dns-recon":
            from whaxon.core.workflow_proposals import propose_passive_dns_plan

            proposal = propose_passive_dns_plan(
                core,
                mission_id=options.mission_id,
                plan_id=options.id,
                target=options.target,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    options.id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            print(json.dumps({**proposal, "created": bool(created)},
                             indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "propose-dns-full":
            from whaxon.core.workflow_proposals import propose_dns_full_posture_plan

            proposal = propose_dns_full_posture_plan(
                core,
                mission_id=options.mission_id,
                plan_id=options.id,
                target=options.target,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    options.id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            print(json.dumps({**proposal, "created": bool(created)},
                             indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "propose-tls-recon":
            from whaxon.core.workflow_proposals import propose_tls_certificate_plan

            proposal = propose_tls_certificate_plan(
                core,
                mission_id=options.mission_id,
                plan_id=options.id,
                target=options.target,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    options.id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            print(json.dumps({**proposal, "created": bool(created)},
                             indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "propose-https-recon":
            from whaxon.core.workflow_proposals import propose_passive_https_recon_plan

            proposal = propose_passive_https_recon_plan(
                core,
                mission_id=options.mission_id,
                plan_id=options.id,
                target=options.target,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    options.id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            print(json.dumps({**proposal, "created": bool(created)},
                             indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "propose-security-txt-recon":
            from whaxon.core.workflow_proposals import propose_passive_security_txt_recon_plan

            proposal = propose_passive_security_txt_recon_plan(
                core, mission_id=options.mission_id, plan_id=options.id, target=options.target,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(options.id, WorkflowPlan.from_dict(proposal["plan"]))
            print(json.dumps({**proposal, "created": bool(created)}, indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "propose-headers-recon":
            from whaxon.core.workflow_proposals import propose_passive_headers_recon_plan

            proposal = propose_passive_headers_recon_plan(
                core, mission_id=options.mission_id, plan_id=options.id, target=options.target,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(options.id, WorkflowPlan.from_dict(proposal["plan"]))
            print(json.dumps({**proposal, "created": bool(created)}, indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "propose-robots-recon":
            from whaxon.core.workflow_proposals import propose_passive_robots_recon_plan

            proposal = propose_passive_robots_recon_plan(
                core,
                mission_id=options.mission_id,
                plan_id=options.id,
                target=options.target,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    options.id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            print(json.dumps({**proposal, "created": bool(created)},
                             indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "propose-redirect-recon":
            from whaxon.core.workflow_proposals import propose_passive_redirect_observation_plan

            proposal = propose_passive_redirect_observation_plan(
                core,
                mission_id=options.mission_id,
                plan_id=options.id,
                target=options.target,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    options.id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            print(json.dumps({**proposal, "created": bool(created)},
                             indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "propose-verification":
            from whaxon.core.workflow_proposals import propose_finding_verification_plan

            proposal = propose_finding_verification_plan(
                core,
                mission_id=options.mission_id,
                plan_id=options.id,
                source_job_id=options.source_job_id,
                finding_seq=options.finding_seq,
                mode=options.mode,
            )
            created = False
            if options.save and proposal.get("status") == "proposed":
                created = core.save_workflow_plan(
                    options.id, WorkflowPlan.from_dict(proposal["plan"]),
                )
            print(json.dumps({**proposal, "created": bool(created)},
                             indent=2, sort_keys=True))
            return 0 if proposal.get("status") == "proposed" else 1
        if options.command == "plan" and options.plan_command == "save":
            raw = json.loads(options.file.read_text(encoding="utf-8"))
            workflow = WorkflowPlan.from_dict(raw)
            created = core.save_workflow_plan(options.id, workflow)
            print(json.dumps({
                "plan_id": options.id, "mission_id": workflow.mission_id,
                "digest": workflow.digest, "created": bool(created),
            }, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "show":
            print(json.dumps(
                core.workflow_plan_details(options.id), indent=2, sort_keys=True,
            ))
            return 0
        if options.command == "plan" and options.plan_command == "reconciliation-report":
            print(json.dumps(
                core.workflow_dispatch_reconciliation(options.id),
                indent=2, sort_keys=True,
            ))
            return 0
        if options.command == "plan" and options.plan_command == "readiness":
            readiness = core.workflow_readiness(options.id)
            print(json.dumps(readiness, indent=2, sort_keys=True))
            return 0 if readiness["ready_to_report_success"] else 1
        if options.command == "plan" and options.plan_command == "evidence":
            print(json.dumps(
                core.workflow_evidence(options.id, limit=options.limit),
                indent=2, sort_keys=True,
            ))
            return 0
        if options.command == "plan" and options.plan_command == "report":
            report = core.workflow_report(options.id, limit=options.limit)
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["status"] == "complete" else 1
        if options.command == "plan" and options.plan_command == "resources":
            print(json.dumps(
                core.workflow_resource_summary(options.id), indent=2, sort_keys=True,
            ))
            return 0
        if options.command == "plan" and options.plan_command == "audit":
            audit = core.workflow_audit_integrity(options.id)
            print(json.dumps(audit, indent=2, sort_keys=True))
            return 0 if audit["consistent"] else 1
        if options.command == "plan" and options.plan_command == "audit-snapshot":
            print(json.dumps(
                core.workflow_audit_snapshot(options.id), indent=2, sort_keys=True,
            ))
            return 0
        if options.command == "plan" and options.plan_command == "audit-verify":
            matches = core.verify_workflow_audit_snapshot(
                options.id, options.expected_digest,
            )
            print(json.dumps({
                "plan_id": options.id, "digest_matches_reference": matches,
                "independent_anchor_verified": False,
            }, sort_keys=True))
            return 0 if matches else 1
        if options.command == "plan" and options.plan_command == "attempts":
            print(json.dumps(
                core.workflow_attempts(
                    options.id, after_started=options.after_started, limit=options.limit,
                ),
                indent=2, sort_keys=True,
            ))
            return 0
        if options.command == "plan" and options.plan_command == "progress":
            print(json.dumps(core.workflow_progress(options.id), indent=2, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "events":
            print(json.dumps(
                core.workflow_events(options.id, after_id=options.after_id, limit=options.limit),
                indent=2, sort_keys=True,
            ))
            return 0
        if options.command == "plan" and options.plan_command == "event-inbox":
            print(json.dumps(
                core.workflow_event_inbox(
                    options.id, options.consumer, limit=options.limit,
                ), indent=2, sort_keys=True,
            ))
            return 0
        if options.command == "plan" and options.plan_command == "event-ack":
            checkpoint = core.acknowledge_workflow_event(
                options.id, options.consumer, options.event_id,
            )
            print(json.dumps({
                "plan_id": options.id, "consumer_id": options.consumer,
                "last_event_id": checkpoint,
            }, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "cancel":
            cancelled = core.cancel_workflow_plan(options.id)
            print(json.dumps({
                "plan_id": options.id, "cancellation_requested": True,
                "tasks_cancelled": cancelled,
            }, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "reconcile":
            changed = core.reconcile_workflow_plan(
                options.id, stale_after_s=options.stale_after_seconds,
            )
            print(json.dumps({
                "plan_id": options.id, "attempts_marked_uncertain": changed,
            }, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "resolve-attempt":
            result = core.reconcile_workflow_attempt(
                options.id, options.attempt_id,
                disposition=options.disposition, actor=options.actor,
                evidence_ref=options.evidence_ref, note=options.note,
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "rate-limit":
            core.configure_workflow_rate_limit(
                options.id, min_spacing_s=options.min_spacing_seconds,
            )
            print(json.dumps({
                "plan_id": options.id, "min_spacing_s": options.min_spacing_seconds,
            }, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "deadline":
            core.configure_workflow_deadline(options.id, deadline_at=options.unix_time)
            print(json.dumps({
                "plan_id": options.id, "deadline_at": options.unix_time,
            }, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "limits":
            core.configure_workflow_limits(
                options.id, max_total_attempts=options.max_total_attempts,
                max_concurrency=options.max_concurrency,
            )
            print(json.dumps({
                "plan_id": options.id, "max_total_attempts": options.max_total_attempts,
                "max_concurrency": options.max_concurrency,
            }, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "submit-run":
            queued = core.enqueue_workflow_run(
                options.id, max_tasks=options.max_tasks,
                max_attempts=options.max_attempts,
                max_concurrency=options.max_concurrency,
            )
            print(json.dumps({
                "plan_id": queued["plan_id"],
                "run_request_id": queued["id"],
                "request_status": queued["status"],
                "execution_completed": False,
                "automatic_uncertain_replay": False,
            }, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "queue-summary":
            print(json.dumps(core.workflow_run_queue_summary(), indent=2, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "run-request":
            state = core.workflow_run_request(options.id)
            if state is None:
                print("unknown workflow run request", file=sys.stderr)
                return 1
            print(json.dumps(state, indent=2, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "cancel-request":
            try:
                state = core.cancel_workflow_run_request(options.id)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 1
            print(json.dumps(state, indent=2, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "run-snapshot":
            state = core.workflow_run_snapshot(options.id)
            if state is None:
                print("unknown workflow run request", file=sys.stderr)
                return 1
            print(json.dumps(state, indent=2, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "serve-requests":
            import signal

            stop = threading.Event()
            previous = {}
            def _stop(_signum, _frame):
                stop.set()

            try:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    previous[sig] = signal.getsignal(sig)
                    signal.signal(sig, _stop)
                total = _run_async(core.serve_workflow_run_requests(
                    stop,
                    poll_interval_s=options.poll_interval,
                    max_runs_per_batch=options.max_runs_per_batch,
                ))
                print(json.dumps({"processed_requests": total, "stopped": True},
                                 sort_keys=True))
                return 0
            finally:
                for sig, old in previous.items():
                    signal.signal(sig, old)
        if options.command == "plan" and options.plan_command == "drain-requests":
            count = _run_async(core.drain_workflow_run_requests(max_runs=options.max_runs))
            print(json.dumps({"processed_requests": count}, sort_keys=True))
            return 0
        if options.command == "plan" and options.plan_command == "run":
            if options.max_tasks < 1 or options.max_attempts < 1 or options.max_concurrency < 1:
                print("--max-tasks, --max-attempts and --max-concurrency must be positive", file=sys.stderr)
                return 2

            awaitable = core.initialize(drain=False)
            _run_async(awaitable)
            request = core.enqueue_workflow_run(
                options.id, max_tasks=options.max_tasks,
                max_attempts=options.max_attempts,
                max_concurrency=options.max_concurrency,
            )
            command_prefix = (
                f"whaxon workflow --data-dir {options.data_dir} plan"
            )
            print(json.dumps({
                "status": "queued",
                "execution_started": False,
                "worker_required": True,
                "run_request": request,
                "next": [
                    f"{command_prefix} run-snapshot --id {request['id']}",
                    f"{command_prefix} serve-requests",
                ],
            }, indent=2, sort_keys=True))
            return 0
        return 2
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        print(f"workflow command failed: {exc}", file=sys.stderr)
        return 2
