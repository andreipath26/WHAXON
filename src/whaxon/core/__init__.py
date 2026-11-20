"""WHAXON core — headless, UI-agnostic."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from .catalog import ToolCatalog
from .events import (
    CoverageSkipped,
    EventBus,
    JobFailed,
    JobFindings,
    JobFinished,
    JobOutput,
    JobStarted,
)
from .msf import MSFClient
from .msf_tracker import MSFTracker
from .runner import ToolRunner
from .scope import ScopeManager
from .store import JobStore


class Core:
    """Single entry point for every interface. Holds no UI state."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.bus = EventBus()
        self.catalog = ToolCatalog(self.bus, self.data_dir / "tools.json")
        self.scope = ScopeManager(self.data_dir / "scope.json")
        from .settings import Settings
        self.settings = Settings(self.data_dir / "settings.json")
        # Phase E.2: a resolver that queries live portfwd state on demand.
        # Returns None on any MSF failure, so the runner behaves normally
        # when Metasploit is not running.
        from .routes import live_resolver
        _route_resolver = live_resolver()
        # Local vulnerability database (CVSS / EPSS / CISA KEV). Used by the
        # severity resolver to set finding severity from CVSS when a CVE is
        # present. See docs/report-redesign.md section 1e.
        from .vulndb import VulnDB
        self.vulndb = VulnDB(self.data_dir / "vulndb.db")
        self.runner = ToolRunner(self.bus, self.catalog, self.scope,
                                 route_resolver=_route_resolver,
                                 vulndb=self.vulndb)
        # SQLite-backed persistence for all UIs
        state_path = self.data_dir / "whaxon.db"
        self.store = JobStore(state_path)
        from .workflow_requests import WorkflowRunQueue
        self.workflow_requests = WorkflowRunQueue(self.store)
        self.runner.bind_session_lookup(self.store.get_session)
        # Subscribe the persister FIRST so every other JobFindings consumer
        # (correlator, suggester, automator) sees findings already in the store.
        self._wire_store()
        # Cross-finding correlation (deterministic, no AI).
        from .correlator import Correlator
        self.correlator = Correlator(self.bus, self.store)
        self.correlator.attach()

        # Attach next-step suggestions from adapters to findings.
        from .suggester import Suggester
        def _adapter_lookup(tool_id):
            try:
                from ..adapters import get_adapter
                return get_adapter(tool_id)
            except Exception:
                return None
        self.suggester = Suggester(self.bus, self.store, _adapter_lookup)
        self.suggester.attach()

        # Deterministic auto-chain rules (nmap -> nikto per web port).
        from .automation import Automator
        self.automator = Automator(self.bus, self.store, self.runner)
        self.automator.attach()
        # Recon: passive checks that flow through the same event pipeline.
        from . import recon_checks as _rc
        from .recon import ReconRunner
        self.recon = ReconRunner(
            scope=self.scope,
            bus=self.bus,
            resolver=self.runner._resolve_findings,
        )
        self.recon.register("dns", _rc.check_dns)
        self.recon.register("ssl", _rc.check_ssl)
        self.recon.register("headers", _rc.check_headers)
        self.recon.register("tech", _rc.check_tech)
        self.recon.register("robots", _rc.check_robots)
        self.recon.register("security_txt", _rc.check_security_txt)
        self.recon.register("cookies", _rc.check_cookies)
        self.recon.register("redirects", _rc.check_redirects)
        self.recon.register("waf", _rc.check_waf)
        self.recon.register("dns_full", _rc.check_dns_full)
        # Metasploit RPC + session tracker
        self.msf = MSFClient()
        self.msf_tracker = MSFTracker(self.bus, self.store, self.msf)
        # A PyPI installation must work from an arbitrary working directory.
        # Seed the user data directory from the packaged catalog on first run;
        # never overwrite an operator's existing tools.json.
        if not self.catalog.path.exists():
            packaged_catalog = Path(__file__).parent.parent / "data" / "tools.json"
            if packaged_catalog.is_file():
                self.data_dir.mkdir(parents=True, exist_ok=True)
                try:
                    self.catalog.path.write_text(
                        packaged_catalog.read_text(encoding="utf-8"),
                        encoding="utf-8",
                    )
                except OSError as exc:
                    raise RuntimeError(
                        f"cannot initialize tool catalog at {self.catalog.path}: {exc}"
                    ) from exc

        # Scope enforcement
        if self.catalog.path.exists():
            self.catalog.load()

        # Engine v2 uses the same catalog, runner, adapter parser and event store
        # as the existing interfaces. Bounded verification and the opt-in,
        # fixed-target lab provider have separate approval-bound contracts.
        from .capabilities import CapabilityRegistry
        from .dns_full_v2 import DnsFullPostureProvider
        from .headers_v2 import HeadersReconProvider
        from .http_recon_v2 import PassiveHttpsReconProvider
        from .lab_access import MetasploitableLabAccessProvider
        from .providers import (
            BoundProviderRouter,
            CatalogAdapterProvider,
            FindingVerificationProvider,
            SemanticOperationProvider,
        )
        from .recon_v2 import PassiveDnsReconProvider
        from .redirect_recon_v2 import RedirectObservationProvider
        from .robots_recon_v2 import RobotsReconProvider
        from .security_txt_v2 import SecurityTxtReconProvider
        from .tls_cert_v2 import TlsCertificateProvider
        self.capabilities = CapabilityRegistry(self.store)
        catalog_provider = CatalogAdapterProvider(
            catalog=self.catalog,
            runner=self.runner,
            store=self.store,
            registry=self.capabilities,
            suppress_legacy_followup=self.automator.suppress_legacy_followup,
        )
        verification_provider = FindingVerificationProvider(
            store=self.store, registry=self.capabilities, scope=self.scope,
        )
        lab_access_provider = MetasploitableLabAccessProvider(
            store=self.store, registry=self.capabilities, scope=self.scope, msf=self.msf,
        )
        passive_dns_provider = PassiveDnsReconProvider(
            store=self.store, registry=self.capabilities, scope=self.scope,
        )
        redirect_observation_provider = RedirectObservationProvider(
            store=self.store, registry=self.capabilities, scope=self.scope,
        )
        dns_full_provider = DnsFullPostureProvider(
            store=self.store, registry=self.capabilities, scope=self.scope,
        )
        headers_recon_provider = HeadersReconProvider(
            store=self.store, registry=self.capabilities, scope=self.scope,
        )
        https_recon_provider = PassiveHttpsReconProvider(
            store=self.store, registry=self.capabilities, scope=self.scope,
        )
        robots_recon_provider = RobotsReconProvider(
            store=self.store, registry=self.capabilities, scope=self.scope,
        )
        security_txt_provider = SecurityTxtReconProvider(
            store=self.store, registry=self.capabilities, scope=self.scope,
        )
        tls_certificate_provider = TlsCertificateProvider(
            store=self.store, registry=self.capabilities, scope=self.scope,
        )
        self.providers = BoundProviderRouter((
            catalog_provider,
            SemanticOperationProvider(catalog_provider, self.capabilities),
            verification_provider,
            lab_access_provider,
            passive_dns_provider,
            redirect_observation_provider,
            dns_full_provider,
            headers_recon_provider,
            https_recon_provider,
            robots_recon_provider,
            security_txt_provider,
            tls_certificate_provider,
        ))

    def _wire_store(self) -> None:
        """Subscribe the store to every job event so history persists."""
        def _on_started(e):
            self.store.create(e.job_id)
            self.store.set_started(e.job_id, e.tool_id, e.target, lease_token=e.lease_token)
        def _on_output(e):
            if self.store.owns_lease(e.job_id, e.lease_token):
                self.store.append_line(e.job_id, e.stream, e.line)
        def _on_finished(e):
            self.store.set_finished(e.job_id, e.exit_code, e.duration_s, lease_token=e.lease_token)
        def _on_failed(e):
            self.store.set_failed(e.job_id, e.error, lease_token=e.lease_token)
        def _on_findings(e):
            if not self.store.owns_lease(e.job_id, e.lease_token):
                return
            for i, f in enumerate(e.findings):
                self.store.append_finding(e.job_id, f, i)
        self.bus.subscribe(JobStarted, _on_started)
        self.bus.subscribe(JobOutput, _on_output)
        self.bus.subscribe(JobFinished, _on_finished)
        self.bus.subscribe(JobFailed, _on_failed)
        self.bus.subscribe(JobFindings, _on_findings)
        def _on_coverage(e):
            self.store.record_coverage(e.job_id, e.tool_id, e.target, e.kind, e.detail, getattr(e, "phase", ""))
        self.bus.subscribe(CoverageSkipped, _on_coverage)

    def create_mission(self, mission_id: str, objective: str, metadata=None):
        """Create a durable Engine v2 mission through the shared Core service."""
        return self.store.create_mission(mission_id, objective, metadata)

    def grant_workflow_approval(
        self, plan_id: str, task_key: str, approval_id: str, actor: str,
        *, expires_at: float, policy_version: str = "policy.v1",
    ):
        return self.store.grant_workflow_approval(
            plan_id, task_key, approval_id, actor,
            expires_at=expires_at, policy_version=policy_version,
        )

    def revoke_workflow_approval(self, plan_id: str, approval_id: str, *, actor: str):
        return self.store.revoke_workflow_approval(plan_id, approval_id, actor=actor)

    def workflow_approvals(self, plan_id: str):
        return self.store.list_workflow_approvals(plan_id)

    def workflow_approval_queue(self, *, limit: int = 100):
        """Return bounded persisted V2 tasks and their exact approval state."""
        candidates = self.store.list_workflow_approval_candidates(limit=limit)
        approvals_by_plan = {}
        for item in candidates:
            plan_id = item["plan_id"]
            if plan_id not in approvals_by_plan:
                try:
                    approvals_by_plan[plan_id] = self.store.list_workflow_approvals(plan_id)
                except Exception:
                    # Corrupt approval bindings must not hide other review
                    # candidates or be presented as valid consent.
                    approvals_by_plan[plan_id] = []
            approvals = approvals_by_plan[plan_id]
            task_approvals = [
                row for row in approvals if row["task_key"] == item["task_key"]
            ]
            item["current_approval"] = task_approvals[-1] if task_approvals else None
            try:
                item["approval_valid"] = self.store.has_valid_workflow_approval(
                    plan_id, item["task_key"],
                ) is True
            except Exception:
                # Malformed plan or approval data remains visible for review,
                # but cannot be treated as an authorization.
                item["approval_valid"] = False
        return candidates

    def configure_workflow_rate_limit(self, plan_id: str, *, min_spacing_s: float):
        return self.store.set_workflow_rate_limit(plan_id, min_spacing_s=min_spacing_s)

    def configure_workflow_deadline(self, plan_id: str, *, deadline_at: float):
        return self.store.set_workflow_deadline(plan_id, deadline_at=deadline_at)

    def configure_workflow_limits(
        self, plan_id: str, *, max_total_attempts: int, max_concurrency: int,
    ):
        return self.store.set_workflow_limits(
            plan_id, max_total_attempts=max_total_attempts,
            max_concurrency=max_concurrency,
        )

    def reconcile_workflow_plan(self, plan_id: str, *, stale_after_s: float = 60.0):
        """Reconcile expired worker leases without repeating external effects."""
        return self.store.reconcile_workflow_plan(plan_id, stale_after_s=stale_after_s)

    def reconcile_workflow_attempt(
        self, plan_id: str, attempt_id: str, *, disposition: str,
        actor: str, evidence_ref: str, note: str,
    ):
        """Record a manual effect decision without certifying success or replaying."""
        return self.store.record_workflow_attempt_reconciliation(
            plan_id, attempt_id, disposition=disposition, actor=actor,
            evidence_ref=evidence_ref, note=note,
        )

    def workflow_event_cursor(self, plan_id: str, consumer_id: str):
        return self.store.get_workflow_event_cursor(plan_id, consumer_id)

    def deliver_workflow_outbox_events(
        self, plan_id: str, consumer_id: str, publish, *, limit: int = 100,
    ):
        """At-least-once event delivery with post-publish durable acknowledgement."""
        from .outbox import WorkflowEventOutbox

        return WorkflowEventOutbox(self.store).deliver(
            plan_id, consumer_id, publish, limit=limit,
        )

    def workflow_event_inbox(self, plan_id: str, consumer_id: str, *, limit: int = 100):
        return self.store.list_unacknowledged_workflow_events(
            plan_id, consumer_id, limit=limit,
        )

    def acknowledge_workflow_event(self, plan_id: str, consumer_id: str, event_id: int):
        return self.store.acknowledge_workflow_events(plan_id, consumer_id, event_id)

    def workflow_events(self, plan_id: str, *, after_id: int = 0, limit: int = 100):
        return self.store.list_workflow_events(plan_id, after_id, limit)

    def configure_mission_cost_limit(self, mission_id: str, *, max_cost_microusd: int):
        return self.store.set_mission_cost_limit(
            mission_id, max_cost_microusd=max_cost_microusd,
        )

    def record_workflow_attempt_cost(
        self, attempt_id: str, *, cost_microusd: int, source: str,
    ):
        return self.store.record_workflow_attempt_cost(
            attempt_id, cost_microusd=cost_microusd, source=source,
        )

    def mission_cost_summary(self, mission_id: str):
        return self.store.get_mission_cost_summary(mission_id)

    def configure_mission_rate_limit(self, mission_id: str, *, min_spacing_s: float):
        return self.store.set_mission_rate_limit(
            mission_id, min_spacing_s=min_spacing_s,
        )

    def mission_rate_limit(self, mission_id: str):
        return self.store.get_mission_rate_limit(mission_id)

    def configure_mission_deadline(self, mission_id: str, *, deadline_at: float):
        return self.store.set_mission_deadline(mission_id, deadline_at=deadline_at)

    def mission_deadline(self, mission_id: str):
        """Read the authoritative persisted mission cutoff for every interface."""
        return self.store.get_mission_deadline(mission_id)

    def mission_execution_limits(self, mission_id: str):
        return self.store.get_mission_execution_limits(mission_id)

    def configure_mission_execution_limits(
        self, mission_id: str, *, max_total_attempts: int, max_concurrency: int,
    ):
        return self.store.set_mission_execution_limits(
            mission_id, max_total_attempts=max_total_attempts,
            max_concurrency=max_concurrency,
        )

    def missions(self, *, limit: int = 100, after_created: float = 0.0):
        return self.store.list_missions(limit=limit, after_created=after_created)

    def mission_workflow_plans(self, mission_id: str):
        return self.store.list_workflow_mission_plans(mission_id)

    def workflow_dispatch_reconciliation(self, plan_id: str):
        return self.store.get_workflow_dispatch_reconciliation(plan_id)

    def workflow_readiness(self, plan_id: str):
        return self.store.get_workflow_readiness(plan_id)

    def workflow_evidence(self, plan_id: str, *, limit: int = 100):
        """Return real, cross-checked workflow-to-tool evidence for reporting."""
        return self.store.get_workflow_evidence(plan_id, limit=limit)

    def workflow_report(self, plan_id: str, *, limit: int = 100):
        """Build a read-only report exclusively from one plan's persisted evidence.

        Partial, failed, missing, or unsealed attempts remain visible but can
        never receive a complete/success status.
        """
        evidence = self.workflow_evidence(plan_id, limit=limit)
        readiness = self.workflow_readiness(plan_id)
        progress = self.workflow_progress(plan_id)
        attempts = evidence["attempts"]
        truncated = len(attempts) < progress["attempts"]
        complete = bool(
            readiness["ready_to_report_success"]
            and evidence["all_evidence_recorded"]
            and evidence["all_evidence_integrity_verified"]
            and attempts
            and not truncated
        )
        findings = [
            {**finding, "task_key": attempt["task_key"],
             "target": attempt["target"], "job_id": attempt["job_id"]}
            for attempt in attempts
            if attempt["evidence_status"] == "recorded"
            and attempt["integrity_status"] == "verified"
            for finding in attempt["findings"]
        ]
        return {
            "schema_version": "whaxon.workflow-report.v1",
            "plan_id": evidence["plan_id"],
            "mission_id": evidence["mission_id"],
            "plan_digest": evidence["plan_digest"],
            "status": "complete" if complete else "partial",
            "readiness": readiness,
            "truncated": truncated,
            "evidence": evidence,
            "summary": {
                "task_attempts": len(attempts),
                "recorded_attempts": sum(
                    attempt["evidence_status"] == "recorded" for attempt in attempts
                ),
                "verified_seals": sum(
                    attempt["integrity_status"] == "verified" for attempt in attempts
                ),
                "findings": len(findings),
            },
            "findings": findings,
            "limitations": [
                "This report contains only evidence linked to the named workflow plan.",
                "A partial report is not a successful completion or a release acceptance record.",
            ],
        }

    def workflow_mission_report(
        self, mission_id: str, *, plan_ids: list[str] | None = None, limit: int = 100,
    ):
        """Aggregate a sequenced release chain from plan-scoped sealed reports.

        Each immutable plan declares ``metadata.release_stage``. Scope is
        checked for every plan against its exact persisted tasks; the mission
        report supplies the report stage and never accepts job IDs or invents
        evidence.
        """
        plan_stages = ("recon", "enumeration", "initial_access", "verification", "retest")
        stages = ("scope", *plan_stages[:4], "report", "retest")
        recorded = self.mission_workflow_plans(mission_id)
        recorded_ids = [row["id"] for row in recorded]
        selected_ids = recorded_ids if plan_ids is None else list(plan_ids)
        if not selected_ids or len(selected_ids) != len(set(selected_ids)):
            raise ValueError("mission report requires unique plan IDs")
        unknown = set(selected_ids) - set(recorded_ids)
        if unknown:
            raise ValueError("mission report plan IDs must belong to the named mission")

        stage_reports = []
        stage_positions = []
        scope_plans = []
        bound_target = None
        target_binding_ok = True
        mismatched_target_plans = []
        stage_capabilities = {
            "recon": {"tool.nmap", "network.services.discover"},
            "enumeration": {
                "tool.gobuster", "tool.ffuf", "web.directories.enumerate",
                "web.paths.fuzz",
            },
            "initial_access": {"lab.initial_access.samba_usermap"},
            "verification": {"tool.verify_sqli", "tool.verify_xss"},
            "retest": {"tool.retest_sqli", "tool.retest_xss"},
        }
        for plan_id in selected_ids:
            details = self.workflow_plan_details(plan_id)
            plan = details["plan"]
            if plan.get("mission_id") != mission_id:
                raise ValueError("mission report plan belongs to a different mission")
            from .workflow import WorkflowPlan

            try:
                canonical_plan = WorkflowPlan.from_dict(plan)
                task_targets = {
                    self._workflow_target_identity(task.target)
                    for task in canonical_plan.tasks
                }
            except (KeyError, TypeError, ValueError):
                task_targets = {None}
            if len(task_targets) != 1 or None in task_targets:
                target_binding_ok = False
                mismatched_target_plans.append({
                    "plan_id": plan_id,
                    "targets": sorted(str(target) for target in task_targets),
                })
            else:
                plan_target = next(iter(task_targets))
                if bound_target is None:
                    bound_target = plan_target
                elif plan_target != bound_target:
                    target_binding_ok = False
                    mismatched_target_plans.append({
                        "plan_id": plan_id, "targets": [plan_target],
                    })
            stage = (plan.get("metadata") or {}).get("release_stage")
            if stage not in plan_stages:
                stage_reports.append({
                    "plan_id": plan_id, "stage": stage, "status": "partial",
                    "reason": "missing or unsupported release_stage metadata",
                })
                stage_positions.append(-1)
                continue
            stage_positions.append(plan_stages.index(stage))
            report = self.workflow_report(plan_id, limit=limit)
            attempts = report.get("evidence", {}).get("attempts", [])
            findings = report.get("findings", [])
            capabilities = {item.get("capability_id") for item in attempts}
            stage_evidence_ok = bool(capabilities & stage_capabilities[stage])
            if stage == "initial_access":
                stage_evidence_ok = stage_evidence_ok and any(
                    finding.get("kind") == "msf_session" for finding in findings
                )
            elif stage in {"verification", "retest"}:
                # Workflow report findings intentionally omit raw data. Read
                # the full persisted rows from the same sealed jobs instead of
                # interpreting the privacy-limited report projection.
                persisted_findings = []
                for attempt in attempts:
                    job_id = attempt.get("job_id")
                    if not isinstance(job_id, str) or not job_id:
                        continue
                    try:
                        rows = self.store.get_findings(job_id) or []
                    except (AttributeError, TypeError, ValueError, RuntimeError):
                        rows = []
                    for finding in rows:
                        if isinstance(finding, dict):
                            persisted_findings.append((attempt, finding))

                if stage == "verification":
                    accepted_statuses = {"verified"}
                    accepted_capabilities = {"tool.verify_sqli", "tool.verify_xss"}
                else:
                    accepted_statuses = {"still_vulnerable", "fixed"}
                    accepted_capabilities = {"tool.retest_sqli", "tool.retest_xss"}
                stage_evidence_ok = stage_evidence_ok and any(
                    attempt.get("capability_id") in accepted_capabilities
                    and finding.get("source") == "engine-v2-verifier"
                    and finding.get("kind") in {"sqli", "sql_injection", "xss"}
                    and finding.get("verification_status") in accepted_statuses
                    and finding.get("verified_by") == "engine-v2"
                    and isinstance(finding.get("data"), dict)
                    and finding["data"].get("operation") == attempt.get("capability_id")
                    and finding["data"].get("status") in accepted_statuses
                    and isinstance(finding["data"].get("source_job_id"), str)
                    and bool(finding["data"].get("source_job_id"))
                    and type(finding["data"].get("source_finding_seq")) is int
                    and finding["data"].get("source_finding_seq") >= 0
                    for attempt, finding in persisted_findings
                )
            # Re-evaluate scope and exact plan-bound authorization at report
            # time. This is fail-closed if scope, provider binding, plan digest,
            # or a required approval has changed since the attempt.
            try:
                task_authorization = [
                    {
                        "task_id": task.id,
                        "authorized": self.authorize_workflow_task_for_plan(
                            plan_id, task,
                        ) is True,
                    }
                    for task in canonical_plan.tasks
                ]
            except (KeyError, TypeError, ValueError):
                task_authorization = []
            authorized = bool(task_authorization) and all(
                item["authorized"] for item in task_authorization
            )
            readiness = report.get("readiness", {})
            ready = readiness.get("ready_to_report_success") is True
            sealed = bool(
                attempts
                and report.get("evidence", {}).get("all_evidence_recorded") is True
                and report.get("evidence", {}).get("all_evidence_integrity_verified") is True
                and all(
                    item.get("evidence_status") == "recorded"
                    and item.get("integrity_status") == "verified"
                    for item in attempts
                )
                and not report.get("truncated", False)
            )
            plan_scope_complete = authorized and ready and sealed
            scope_plans.append({
                "plan_id": plan_id,
                "plan_digest": report.get("plan_digest"),
                "plan_bound_authorization": authorized,
                "task_authorization": task_authorization,
                "readiness": readiness,
                "sealed_attempts": sealed,
            })
            stage_reports.append({
                "plan_id": plan_id, "stage": stage,
                "status": "complete" if report["status"] == "complete"
                and stage_evidence_ok and plan_scope_complete
                else "partial",
                "evidence_contract_satisfied": stage_evidence_ok,
                "plan_bound_authorization": authorized,
                "readiness": readiness,
                "sealed_attempts": sealed,
                "report": report,
            })

        from itertools import pairwise

        ordered = all(left < right for left, right in pairwise(stage_positions))
        scope_complete = bool(scope_plans) and all(
            item["plan_bound_authorization"]
            and item["readiness"].get("ready_to_report_success") is True
            and item["sealed_attempts"] for item in scope_plans
        )
        plan_stage_present = [item.get("stage") for item in stage_reports]
        plan_stages_ordered = plan_stage_present == list(plan_stages)
        plan_stage_complete = plan_stages_ordered and all(
            item["status"] == "complete" for item in stage_reports
        )
        report_complete = bool(
            ordered and scope_complete
            and all(
                item["status"] == "complete"
                for item in stage_reports if item.get("stage") != "retest"
            )
        )
        synthesized_stages: list[dict[str, Any]] = [
            {
                "stage": "scope",
                "status": "complete" if scope_complete else "partial",
                "plan_evidence": scope_plans,
            },
            *[item for item in stage_reports if item.get("stage") != "retest"],
            {
                "stage": "report",
                "status": "complete" if report_complete else "partial",
                "source": "this mission aggregate",
                "sealed_source_plans": [
                    item["plan_id"] for item in stage_reports
                    if item.get("stage") in plan_stages[:4]
                    and item.get("status") == "complete"
                ],
            },
            *[item for item in stage_reports if item.get("stage") == "retest"],
        ]
        complete = bool(
            ordered and scope_complete and plan_stage_complete and report_complete
            and target_binding_ok
            and all(item["status"] == "complete" for item in synthesized_stages)
        )
        return {
            "schema_version": "whaxon.workflow-mission-report.v1",
            "mission_id": mission_id,
            "status": "complete" if complete else "partial",
            "required_stages": list(stages),
            "stage_order_valid": ordered and plan_stages_ordered,
            "target_binding": {
                "status": "complete" if target_binding_ok else "partial",
                "target": bound_target,
                "mismatched_plans": mismatched_target_plans,
                "rule": "every task in every plan must resolve to the same single target",
            },
            "missing_stages": [
                stage for stage in stages
                if stage not in {item.get("stage") for item in synthesized_stages}
            ],
            "stages": synthesized_stages,
            "limitations": [
                "Only plans persisted under the named mission are eligible.",
                "Each stage report is derived from that plan's sealed persisted evidence.",
                "A complete mission report is not production deployment approval.",
            ],
        }

    @staticmethod
    def _workflow_target_identity(target: str) -> str | None:
        """Normalize an IP, URL or host:port to its mission-chain target."""
        import ipaddress
        from urllib.parse import urlsplit

        value = str(target or "").strip()
        if not value:
            return None
        if "://" not in value and "/" in value:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return None
            return network.network_address.compressed if network.num_addresses == 1 else None
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = parsed.hostname
        if host is None:
            return None
        try:
            return ipaddress.ip_address(host).compressed
        except ValueError:
            return host.rstrip(".").lower()

    def workflow_resource_summary(self, plan_id: str):
        return self.store.get_workflow_resource_summary(plan_id)

    def workflow_audit_integrity(self, plan_id: str):
        return self.store.get_workflow_audit_integrity(plan_id)

    def workflow_audit_snapshot(self, plan_id: str):
        """Read-only lifecycle digest; external anchoring is operator-owned."""
        return self.store.get_workflow_audit_snapshot(plan_id)

    def verify_workflow_audit_snapshot(self, plan_id: str, expected_digest: str):
        """Compare current lifecycle state against an externally retained digest."""
        return self.store.verify_workflow_audit_snapshot(plan_id, expected_digest)

    def workflow_attempts(
        self, plan_id: str, *, after_started: float = 0.0, limit: int = 100,
    ):
        """Expose read-only attempt diagnostics through the shared Core service."""
        return self.store.list_workflow_attempts(
            plan_id, after_started=after_started, limit=limit,
        )

    def workflow_progress(self, plan_id: str):
        """Expose durable task/attempt progress to CLI, API and headless clients."""
        return self.store.get_workflow_progress(plan_id)

    def cancel_workflow_plan(self, plan_id: str) -> int:
        """Stop future task claims and close queued (not running) run intents."""
        cancelled = self.store.request_workflow_cancellation(plan_id)
        self.workflow_requests.cancel_queued(plan_id)
        return cancelled

    def save_workflow_plan(self, plan_id: str, plan):
        """Validate and persist a versioned mission DAG."""
        return self.store.save_workflow_plan(plan_id, plan)

    def workflow_plan_details(self, plan_id: str):
        """Return the same persisted plan/task snapshot to CLI and API."""
        plan = self.store.get_workflow_plan(plan_id)
        if plan is None:
            raise ValueError(f"unknown workflow plan: {plan_id}")
        return {
            "plan": plan["plan"],
            "tasks": self.store.list_workflow_tasks(plan_id),
        }

    def enqueue_workflow_run(self, plan_id: str, *, max_tasks: int = 100,
                             max_attempts: int = 2, max_concurrency: int = 4):
        """Persist an execution request before acknowledging any client."""
        return self.workflow_requests.enqueue(plan_id, limits={
            "max_tasks": max_tasks, "max_attempts": max_attempts,
            "max_concurrency": max_concurrency,
        })

    def workflow_run_queue_summary(self):
        """Shared read-only queue diagnostics for API, CLI and headless."""
        return self.workflow_requests.summary()

    def workflow_run_request(self, request_id: str):
        return self.workflow_requests.get(request_id)

    def cancel_workflow_run_request(self, request_id: str):
        """Request cancellation through the existing durable plan stop barrier.

        A running external effect is not asserted to have stopped. Unknown
        requests never cancel an unrelated plan.
        """
        row = self.workflow_run_request(request_id)
        if row is None:
            raise ValueError("unknown workflow run request")
        cancelled = self.cancel_workflow_plan(row["plan_id"])
        return {
            "run_request_id": request_id,
            "plan_id": row["plan_id"],
            "cancellation_requested": True,
            "tasks_cancelled": cancelled,
            "external_effects_stopped": False,
            "request": self.workflow_run_request(request_id),
        }

    def workflow_run_snapshot(self, request_id: str):
        """Reconnect-safe persisted run and task progress, without lease secrets.

        The request and task views are individually persisted snapshots, not
        a claim that external effects completed or that a worker is alive.
        """
        row = self.workflow_run_request(request_id)
        if row is None:
            return None
        return {
            "schema_version": "whaxon.workflow-run-snapshot.v1",
            "request": row,
            "progress": self.workflow_progress(row["plan_id"]),
            "worker_liveness_verified": False,
            "automatic_uncertain_replay": False,
        }

    async def drain_workflow_run_requests(self, *, max_runs: int = 20,
                                          initialized: bool = False,
                                          stop_event=None) -> int:
        """Claim persistent V2 run requests; never replay uncertain executions.

        A CLI, headless daemon or web service can call this after restart.
        The scheduler continues to own task leases, policy and evidence.
        """
        import asyncio
        import uuid

        if type(max_runs) is not int or not 1 <= max_runs <= 100:
            raise ValueError("max_runs must be between 1 and 100")
        if stop_event is not None and not callable(getattr(stop_event, "is_set", None)):
            raise TypeError("stop_event must expose is_set()")
        if not initialized:
            await self.initialize(drain=False)
        # Reconcile the full bounded backlog before claiming fresh work.
        # Each pass holds a short transaction (at most 128 lost leases).
        # A single pass would leave older lost leases indefinitely if the
        # service exits after draining all newly queued work.
        while self.workflow_requests.reconcile_stale():
            if stop_event is not None and stop_event.is_set():
                return 0
        owner = "workflow-run-worker-" + uuid.uuid4().hex
        processed = 0
        for _ in range(max_runs):
            # Stop admits no additional request after a graceful shutdown
            # signal, even inside a multi-request batch. An already claimed
            # external effect is allowed to finish or become uncertain.
            if stop_event is not None and stop_event.is_set():
                break
            # Claim quarantines at most 64 poisoned heads per transaction.
            # One-shot CLI drains must not mistake that bounded yield for
            # an empty queue and strand valid work behind corrupted heads.
            # Cap retries to prevent a continuously poisoned producer from
            # monopolizing the worker forever.
            request = None
            for _claim_pass in range(16):
                if stop_event is not None and stop_event.is_set():
                    break
                request = self.workflow_requests.claim(owner)
                if request is not None:
                    break
                if self.workflow_requests.queued_count() == 0:
                    break
            if request is None:
                break
            token = request["lease_token"]
            request_id = request["id"]
            async def heartbeat(active_id=request_id, active_token=token):
                while True:
                    await asyncio.sleep(5)
                    if not self.workflow_requests.heartbeat(active_id, active_token):
                        return

            pulse = asyncio.create_task(heartbeat())
            status = "uncertain"
            error = ""
            try:
                result = await self.run_workflow_plan(
                    request["plan_id"], worker_id=owner, **request["limits"],
                )
                status = "completed" if result["complete"] else "incomplete"
            except Exception as exc:
                # Dispatch may have produced an external effect before failure.
                # Never automatically retry this request.
                error = f"worker error after claim: {type(exc).__name__}"
            finally:
                pulse.cancel()
                try:
                    await pulse
                except asyncio.CancelledError:
                    pass
                self.workflow_requests.finish(
                    request_id, token, status=status, error=error,
                )
            processed += 1
        return processed

    async def serve_workflow_run_requests(
        self, stop_event, *, poll_interval_s: float = 1.0,
        max_runs_per_batch: int = 20,
    ) -> int:
        """Continuously service durable V2 intents until graceful stop.

        stop_event is a threading.Event, so foreground services can handle
        SIGTERM/SIGINT without assuming they own the asyncio event loop.
        A stop signal prevents new claims within the current batch, without
        falsely claiming that an in-flight external operation stopped.
        """
        import asyncio
        import math
        import uuid

        if isinstance(poll_interval_s, bool) or not isinstance(
            poll_interval_s, (int, float)
        ) or not math.isfinite(poll_interval_s) or not 0.05 <= poll_interval_s <= 3600:
            raise ValueError("poll interval must be finite and in [0.05, 3600]")
        if type(max_runs_per_batch) is not int or not 1 <= max_runs_per_batch <= 100:
            raise ValueError("max_runs_per_batch must be in range 1..100")
        if not callable(getattr(stop_event, "is_set", None)):
            raise TypeError("stop_event must expose is_set()")
        worker_id = "workflow-run-worker-" + uuid.uuid4().hex
        self.workflow_requests.set_worker_status("starting", worker_id=worker_id)
        try:
            await self.initialize(drain=False)
            # Queue lease recovery is a prerequisite for advertising an
            # externally supervised worker as ready. Do the bounded passes
            # before readiness so health probes cannot route work to a worker
            # that has not yet quarantined lost run requests.
            while self.workflow_requests.reconcile_stale():
                if stop_event.is_set():
                    break
        except Exception:
            self.workflow_requests.set_worker_status("stopped", worker_id=worker_id)
            raise
        if stop_event.is_set():
            self.workflow_requests.set_worker_status("stopped", worker_id=worker_id)
            return 0
        self.workflow_requests.set_worker_status("ready", worker_id=worker_id)
        total = 0
        loop = asyncio.get_running_loop()

        async def refresh_worker_heartbeat():
            while not stop_event.is_set():
                await asyncio.sleep(2.0)
                if not stop_event.is_set():
                    self.workflow_requests.set_worker_status("ready", worker_id=worker_id)

        heartbeat = asyncio.create_task(refresh_worker_heartbeat())
        try:
            while not stop_event.is_set():
                total += await self.drain_workflow_run_requests(
                    max_runs=max_runs_per_batch, initialized=True,
                    stop_event=stop_event,
                )
                # Poll deadlines use a monotonic clock: repeated fractional
                # subtraction can drift under scheduler pauses and postpone new
                # durable requests. A stop signal remains responsive.
                deadline = loop.time() + float(poll_interval_s)
                while not stop_event.is_set():
                    now = loop.time()
                    remaining = deadline - now
                    if remaining <= 0:
                        break
                    await asyncio.sleep(min(remaining, 0.25))
        finally:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass
            self.workflow_requests.set_worker_status("stopped", worker_id=worker_id)
        return total

    def propose_workflow_followups(self, source_plan_id: str, *, max_tasks: int = 16):
        """Compile reviewable follow-ups from sealed, persisted evidence."""
        from .followups import EvidenceFollowupPlanner

        return EvidenceFollowupPlanner(
            store=self.store, providers=self.providers, scope=self.scope,
        ).propose(source_plan_id, max_tasks=max_tasks)

    def capability_portfolio_audit(self):
        """Expose catalog/adapter gaps without registering execution routes."""
        return self.providers.portfolio_audit()

    def capability_inventory(self):
        """Return truthful live provider readiness without changing manifests."""
        return self.providers.inventory()

    def authorize_workflow_task(self, task) -> bool:
        """Fail-closed policy for scoped capabilities with exact plan approval."""
        import os

        from .capabilities import CapabilityUnavailable

        try:
            from .capabilities import CapabilityRequirements
            from .providers import _target_type

            bound = getattr(self, "providers", None)
            if bound is not None:
                # The production policy and execution must bind the same
                # in-process adapter manifest, not a persisted-only claim.
                manifest = bound.resolve_task(
                    task, require_installed=True,
                ).manifest
            else:
                # Small policy-only tests instantiate Core without providers.
                candidates = self.capabilities.list(task.capability_id)
                target_type = _target_type(task.target) if any(
                    item.target_types for item in candidates
                ) else ""
                manifest = self.capabilities.resolve(
                    task.capability_id,
                    CapabilityRequirements(
                        target_type=target_type,
                        required_permissions=tuple(task.permissions),
                        transport="local_process",
                        allowed_versions=("catalog-v1",) if task.capability_id.startswith("tool.") else (),
                    ),
                ).manifest
        except (CapabilityUnavailable, ValueError, TypeError, RuntimeError):
            return False
        impact_rank = {
            "read_only": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4,
        }
        if task.impact not in impact_rank or manifest.impact not in impact_rank:
            return False
        if task.impact != manifest.impact or set(task.permissions) != set(manifest.permissions):
            return False
        if impact_rank[task.impact] > impact_rank["moderate"]:
            # A single narrowly bound critical exception exists for the
            # explicitly enabled repository Metasploitable2 lab. Provider
            # resolution has already checked its fixed IP/module/input
            # contract; plan authorization below still requires exact consent.
            if not (
                task.capability_id == "lab.initial_access.samba_usermap"
                and task.impact == "critical"
                and os.environ.get("WHAXON_ENABLE_V2_LAB_INITIAL_ACCESS") == "1"
                and task.target == "172.28.0.10"
            ):
                return False
        # Network execution uses the stricter DNS-rebinding gate. The one
        # passive DNS-query operation has a narrower scope path because it
        # does not connect to the hostname's resolved address.
        try:
            # Scope may be revoked by another CLI/server process. Refresh the
            # persisted policy at each decision; malformed updates fail closed.
            reload_scope = getattr(self.scope, "load", None)
            if callable(reload_scope):
                reload_scope()
            scope_mode = getattr(manifest, "scope_mode", "network")
            if scope_mode == "dns_query":
                # DNS query providers authorize the query name without
                # connecting to its resolved address. Providers repeat query
                # name checks inside their bounded child process.
                return self.scope.check_for_dns_query(task.target).allowed is True
            if scope_mode == "pinned_network":
                pinned_check = getattr(self.scope, "check_for_pinned_execution", None)
                if not callable(pinned_check):
                    return False
                return pinned_check(task.target).allowed is True
            if scope_mode != "network":
                return False
            execution_check = getattr(self.scope, "check_for_execution", None)
            if not callable(execution_check):
                execution_check = self.scope.check
            return execution_check(task.target).allowed is True
        except Exception:
            return False

    def authorize_workflow_task_for_plan(self, plan_id: str, task) -> bool:
        """Require exact consent for moderate-impact or network-effect tasks.

        An approval is never a substitute for scope/provider policy. Revocation,
        expiry, changed task bindings and missing approval all fail closed.
        """
        from .capabilities import CapabilityManifest, requires_network_approval
        from .workflow import WorkflowPlan, WorkflowTask

        # Never authorize an unpersisted or modified task using approval/scope
        # from a different plan. This applies to low-impact nodes too.
        if not isinstance(task, WorkflowTask):
            return False
        try:
            row = self.store.get_workflow_plan(plan_id)
            if row is None or row["status"] == "cancel_requested":
                return False
            plan = WorkflowPlan.from_dict(row["plan"])
            if plan.digest != row["digest"] or plan.mission_id != row["mission_id"]:
                return False
            if not any(candidate == task for candidate in plan.tasks):
                return False
            self.store.verify_workflow_plan_integrity(plan_id)
            provider = getattr(self, "providers", None)
            check_binding = getattr(provider, "plan_binding_valid", None)
            if callable(check_binding) and check_binding(task, plan.metadata) is not True:
                return False
            if not self.authorize_workflow_task(task):
                return False
            manifest_lookup = getattr(provider, "manifest_for", None)
            manifests: tuple[CapabilityManifest, ...]
            if callable(manifest_lookup):
                manifest = manifest_lookup(task.capability_id)
                if not isinstance(manifest, CapabilityManifest):
                    return False
                manifests = (manifest,)
            else:
                manifests = tuple(self.capabilities.list(task.capability_id))
            if not manifests or any(
                manifest.capability_id != task.capability_id for manifest in manifests
            ):
                return False
            network_effect = requires_network_approval(
                task.permissions,
                (
                    effect
                    for manifest in manifests
                    for effect in manifest.side_effects
                ),
            )
            approval_required = (
                task.impact in ("moderate", "high", "critical")
                or network_effect
            )
            if approval_required:
                return self.store.has_valid_workflow_approval(plan_id, task.id) is True
            return True
        except (ValueError, TypeError, RuntimeError, KeyError):
            return False

    def workflow_scheduler(
        self, *, plan_id: str | None = None, authorize=None, dispatch=None,
        worker_id: str = "workflow-worker",
    ):
        """Default to plan-bound authorization, never unbound scope approval.

        Custom callbacks are explicit injection hooks for controlled callers;
        production callers should use run_workflow_plan instead.
        """
        from .scheduler import WorkflowScheduler

        if authorize is None:
            if not plan_id:
                raise ValueError("plan_id required for default workflow authorization")

            def authorize(task):
                return self.authorize_workflow_task_for_plan(plan_id, task)

        return WorkflowScheduler(
            self.store, authorize=authorize,
            dispatch=dispatch if dispatch is not None else self.providers.dispatch,
            worker_id=worker_id,
        )

    async def run_workflow_plan(
        self, plan_id: str, *, authorize=None, dispatch=None,
        worker_id: str = "workflow-worker", max_tasks: int = 100, max_attempts: int = 2,
        max_concurrency: int = 4,
    ):
        """Run a persisted plan; all authorization and dispatch stay injected."""
        discover_followups = authorize is None and dispatch is None
        if authorize is None:
            def authorize(task):
                return self.authorize_workflow_task_for_plan(plan_id, task)
        scheduler = self.workflow_scheduler(
            plan_id=plan_id, authorize=authorize, dispatch=dispatch, worker_id=worker_id,
        )
        result = await scheduler.run(
            plan_id, max_tasks=max_tasks, max_attempts=max_attempts,
            max_concurrency=max_concurrency,
        )
        # E4 only proposes and persists a NEW plan from sealed evidence. It
        # cannot approve or execute it. Existing E3 scheduling stays unchanged.
        if (
            discover_followups
            and result.get("complete")
            and any(item["status"] == "succeeded" for item in result["tasks"])
        ):
            try:
                proposal = self.propose_workflow_followups(plan_id)
                if proposal.plan is not None:
                    self.save_workflow_plan(proposal.plan_id, proposal.plan)
                result["followup"] = proposal.to_dict()
            except Exception as exc:
                # Follow-up discovery is a secondary, review-only activity.
                # A planner failure cannot reclassify a completed source
                # workflow as an uncertain external execution.
                result["followup_error"] = type(exc).__name__
        return result

    async def initialize(self, drain: bool = True) -> None:
        """Called once by any interface. Awaitable inside a splash screen.

        drain=True (default): long-lived hosts reconcile stale rows. Legacy
        JobStore rows are drained only when
        WHAXON_LEGACY_QUEUE_DRAIN_ENABLED=true is explicitly configured.
        Engine V2 requests are serviced by their dedicated durable worker.
        drain=False: one-shot CLI commands never drain prior legacy jobs.
        """
        self.bus.bind_loop(asyncio.get_running_loop())
        if self.catalog.path.exists():
            self.catalog.load()
        # Reconcile work left by a prior process before the host reports ready.
        try:
            self.store.reconcile_stale()
            # Do not steal a live worker's attempt when another CLI/daemon
            # process starts. Workflow workers renew this lease while executing.
            self.store.reconcile_workflow_attempts(stale_after_s=60.0)
        except Exception as exc:
            # Recovery is part of the durable execution boundary. Starting
            # after silently skipping it can strand claims or report false
            # readiness, so fail closed and let the supervisor retry.
            raise RuntimeError("workflow recovery failed; execution is not ready") from exc
        legacy_drain_enabled = os.environ.get(
            "WHAXON_LEGACY_QUEUE_DRAIN_ENABLED", "false",
        ).strip().lower() in {"1", "true", "yes"}
        if drain and legacy_drain_enabled:
            try:
                from .worker import drain_async
                await drain_async(self.store, self.runner)
            except Exception:
                pass
