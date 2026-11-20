"""E4 evidence-driven follow-up compilation; no execution or authorization."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass

from .providers import SEMANTIC_OPERATION_IDS
from .workflow import WorkflowPlan, WorkflowTask


@dataclass(frozen=True)
class FollowupRule:
    id: str
    sources: tuple[str, ...]
    finding_kind: str
    capability_id: str
    target_mode: str
    ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()

    def __post_init__(self):
        if not all(
            isinstance(value, str) and value.strip()
            for value in (self.id, self.finding_kind, self.capability_id)
        ):
            raise ValueError("follow-up rule requires explicit identity and sources")
        if (
            not isinstance(self.sources, tuple) or not self.sources
            or any(not isinstance(source, str) or not source.strip()
                   for source in self.sources)
        ):
            raise ValueError("follow-up rule requires non-empty source identities")
        if self.target_mode not in ("source", "http_origin"):
            raise ValueError("unsupported follow-up target mode")
        if (
            not isinstance(self.ports, tuple)
            or any(type(n) is not int or not 1 <= n <= 65535
                   for n in self.ports)
        ):
            raise ValueError("invalid follow-up port")
        if (
            not isinstance(self.services, tuple)
            or any(not isinstance(value, str) or not value.strip()
                   for value in self.services)
        ):
            raise ValueError("invalid follow-up service names")

    def match(self, source: str, finding: dict) -> bool:
        if source not in self.sources or finding.get("kind") != self.finding_kind:
            return False
        if self.target_mode == "source":
            return True
        data = finding.get("data")
        if not isinstance(data, dict) or type(data.get("port")) is not int:
            return False
        port = data["port"]
        service = data.get("service")
        return 1 <= port <= 65535 and (
            port in self.ports or (
                isinstance(service, str) and service.lower() in self.services
            )
        )

    def make_target(self, source_target: str, finding: dict) -> str:
        from .providers import _target_type

        kind = _target_type(source_target)
        if self.target_mode == "source":
            return source_target
        if kind not in ("hostname", "ip"):
            raise ValueError("HTTP follow-up requires a host/IP source")
        port = finding["data"]["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid observed port")
        host = source_target
        if kind == "ip":
            ip = ipaddress.ip_address(source_target.strip("[]"))
            host = f"[{ip}]" if ip.version == 6 else str(ip)
        service = str(finding["data"].get("service") or "").lower()
        scheme = "https" if port in (443, 8443) or service in (
            "https", "ssl", "https-alt",
        ) else "http"
        return f"{scheme}://{host}:{port}"


DEFAULT_RULES = (
    FollowupRule(
        "web-service.v1", ("tool.nmap",), "open_port", "tool.nikto",
        "http_origin", (80, 443, 8000, 8080, 8180, 8188, 8443, 8888, 9000),
        ("http", "http-alt", "http-proxy", "https", "https-alt", "ssl"),
    ),
    FollowupRule(
        "web-service-semantic.v1", ("network.services.discover",),
        "open_port", "web.server.audit", "http_origin",
        (80, 443, 8000, 8080, 8180, 8188, 8443, 8888, 9000),
        ("http", "http-alt", "http-proxy", "https", "https-alt", "ssl"),
    ),
)


@dataclass(frozen=True)
class FollowupProposal:
    source_plan_id: str
    plan_id: str | None
    plan: WorkflowPlan | None
    blocked: tuple[dict, ...]

    def to_dict(self) -> dict:
        return {
            "source_plan_id": self.source_plan_id,
            "plan_id": self.plan_id,
            "plan": self.plan.to_dict() if self.plan else None,
            "digest": self.plan.digest if self.plan else None,
            "blocked": list(self.blocked),
            "execution_started": False,
            "approval_granted": False,
        }


class EvidenceFollowupPlanner:
    """Resolve rules against verified durable evidence and trusted providers."""

    def __init__(self, *, store, providers, scope, rules=DEFAULT_RULES):
        self.store = store
        self.providers = providers
        self.scope = scope
        self.rules = tuple(rules)
        if len(set(rule.id for rule in self.rules)) != len(self.rules):
            raise ValueError("follow-up rule ids must be unique")

    def propose(self, source_plan_id: str, *, max_tasks: int = 16) -> FollowupProposal:
        if type(max_tasks) is not int or not 1 <= max_tasks <= 100:
            raise ValueError("max_tasks must be in range 1..100")
        source = self.store.get_workflow_plan(source_plan_id)
        if source is None:
            raise ValueError("unknown source workflow plan")
        if source.get("status") == "cancel_requested":
            raise ValueError("cancelled source plan cannot generate follow-ups")
        verify = getattr(self.store, "verify_workflow_plan_integrity", None)
        if callable(verify):
            verify(source_plan_id)
        tasks: list[WorkflowTask] = []
        provenance: list[dict] = []
        blocked: list[dict] = []
        seen: set[tuple[str, str]] = set()
        evidence = self.store.get_workflow_evidence(source_plan_id, limit=1000)
        # Refuse partial evidence even when an individual attempt looks sealed.
        if (
            not isinstance(evidence, dict)
            or evidence.get("plan_id") != source_plan_id
            or evidence.get("mission_id") != source.get("mission_id")
            or evidence.get("plan_digest") != source.get("digest")
            or evidence.get("all_evidence_recorded") is not True
            or evidence.get("all_evidence_integrity_verified") is not True
        ):
            return FollowupProposal(source_plan_id, None, None, ({
                "source_task": None, "reason": "source_evidence_incomplete",
            },))
        rows = evidence.get("attempts")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            return FollowupProposal(source_plan_id, None, None, ({
                "source_task": None, "reason": "evidence_unavailable",
            },))
        for row in rows:
            if not isinstance(row, dict):
                blocked.append({"source_task": None, "reason": "invalid_evidence_row"})
                continue
            key = row.get("task_key")
            if (row.get("attempt_status") != "succeeded"
                    or row.get("evidence_status") != "recorded"
                    or row.get("integrity_status") != "verified"):
                blocked.append({"source_task": key, "reason": "unverified_source_evidence"})
                continue
            job_id = row.get("job_id")
            job = self.store.get(job_id)
            if (not isinstance(job, dict) or job.get("id") != job_id
                    or job.get("target") != row.get("target")
                    or job.get("status") != "finished" or job.get("exit_code") != 0
                    or row.get("capability_id") not in (
                        "tool." + str(job.get("tool")),
                        SEMANTIC_OPERATION_IDS.get(str(job.get("tool"))),
                    )):
                blocked.append({"source_task": key, "reason": "source_job_mismatch"})
                continue
            findings = self.store.get_findings(job_id)
            if not isinstance(findings, list):
                blocked.append({"source_task": key, "reason": "findings_unavailable"})
                continue
            for finding in findings:
                if not isinstance(finding, dict) or finding.get("source") != job["tool"]:
                    continue
                for rule in self.rules:
                    if not rule.match(row["capability_id"], finding):
                        continue
                    try:
                        target = rule.make_target(row["target"], finding)
                        unique = (rule.capability_id, target)
                        if unique in seen:
                            continue
                        if len(tasks) >= max_tasks:
                            blocked.append({"source_task": key, "reason": "task_limit"})
                            continue
                        load = getattr(self.scope, "load", None)
                        if callable(load):
                            load()
                        if self.scope.check_for_execution(target).allowed is not True:
                            raise ValueError("out_of_scope")
                        # Use the bound provider's real contract, not
                        # scanner-specific permissions or an untrusted
                        # registry-only declaration.
                        manifest = self.providers.manifest_for(rule.capability_id)
                        task = WorkflowTask(
                            id=f"followup-{len(tasks) + 1}",
                            capability_id=rule.capability_id, target=target,
                            permissions=manifest.permissions, impact=manifest.impact,
                            timeout_s=manifest.timeout_s,
                            idempotency_key=hashlib.sha256(
                                json.dumps([source_plan_id, job_id, rule.id, target]).encode()
                            ).hexdigest(),
                        )
                        resolved = self.providers.resolve_task(
                            task, require_installed=True,
                        )
                        selected = resolved.manifest
                        if (
                            selected.capability_id != manifest.capability_id
                            or selected.provider_id != manifest.provider_id
                            or selected.provider_version != manifest.provider_version
                            or selected.fingerprint != manifest.fingerprint
                        ):
                            raise ValueError("provider resolution changed the bound manifest")
                    except (
                        ValueError, TypeError, RuntimeError, LookupError,
                        KeyError, AttributeError,
                    ) as exc:
                        blocked.append({
                            "source_task": key, "rule_id": rule.id,
                            "reason": "provider_or_scope_blocked",
                            "error_type": type(exc).__name__,
                        })
                        continue
                    seen.add(unique)
                    tasks.append(task)
                    provenance.append({
                        "source_task": key, "source_job": job_id,
                        "finding_seq": finding.get("seq"), "rule_id": rule.id,
                        "provider_fingerprint": manifest.fingerprint,
                    })
        if not tasks:
            return FollowupProposal(source_plan_id, None, None, tuple(blocked))
        plan = WorkflowPlan(
            source["mission_id"], tuple(tasks), metadata={
                "source_plan": source_plan_id,
                "source_digest": source["digest"],
                "provenance": provenance,
                "provider_bindings": {
                    task.id: {
                        "provider_id": self.providers.manifest_for(task.capability_id).provider_id,
                        "manifest_fingerprint": self.providers.manifest_for(
                            task.capability_id,
                        ).fingerprint,
                    }
                    for task in tasks
                },
                "followup_schema": "whaxon.followup.v1",
            },
        )
        plan_id = "followup-" + hashlib.sha256(
            (source_plan_id + plan.digest).encode()
        ).hexdigest()[:20]
        return FollowupProposal(source_plan_id, plan_id, plan, tuple(blocked))
