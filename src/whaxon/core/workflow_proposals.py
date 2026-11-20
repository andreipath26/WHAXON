"""Deterministic helpers for preparing operator-reviewable workflow plans."""
from __future__ import annotations

import uuid

from .providers import SEMANTIC_OPERATION_IDS
from .workflow import WorkflowPlan, WorkflowTask


def propose_passive_dns_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    target: str,
) -> dict:
    """Prepare a fixed passive-DNS V2 plan without saving or executing it.

    This operation has no catalog-tool alias. Keep its target authorization
    aligned with Core's DNS-query policy and bind the reviewed plan to the
    currently selected provider manifest.
    """
    from .recon_v2 import CAPABILITY_ID

    for name, value in (("mission_id", mission_id), ("plan_id", plan_id),
                        ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}

    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}

    try:
        reload_scope = getattr(core.scope, "load", None)
        if callable(reload_scope):
            reload_scope()
        scope = core.scope.check_for_dns_query(target)
    except Exception:
        return {"status": "blocked", "reason": "DNS-query scope evaluation failed; no plan was created"}
    if not getattr(scope, "allowed", False):
        return {
            "status": "blocked",
            "reason": f"target is outside current DNS-query scope: {getattr(scope, 'reason', '')}",
        }

    try:
        manifest = core.providers.manifest_for(CAPABILITY_ID)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "no V2 passive-DNS provider is registered"}
    if manifest.capability_id != CAPABILITY_ID:
        return {"status": "blocked", "reason": "provider capability does not match passive DNS"}
    if (
        manifest.impact != "moderate"
        or manifest.target_types != ("hostname",)
        or manifest.input_schema.get("properties") != {}
        or bool(manifest.input_schema.get("required"))
        or manifest.input_schema.get("additionalProperties") is not False
    ):
        return {"status": "blocked", "reason": "passive-DNS provider contract differs from the reviewed fixed operation"}

    readiness = next((
        item for item in core.capability_inventory()
        if isinstance(item, dict)
        and item.get("capability_id") == CAPABILITY_ID
        and item.get("provider_id") == manifest.provider_id
    ), None)
    if not readiness or any(
        readiness.get(key) is not True
        for key in ("selected_for_execution", "installed", "executable")
    ):
        return {"status": "blocked", "reason": "V2 passive-DNS provider is not selected and ready"}

    task_id = "task-1"
    task = WorkflowTask(
        id=task_id,
        capability_id=CAPABILITY_ID,
        target=target,
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
        idempotency_key=uuid.uuid5(
            uuid.NAMESPACE_URL, f"whaxon:passive-dns-proposal:{mission_id}:{plan_id}",
        ).hex,
    )
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "V2 passive-DNS provider or target compatibility check failed"}

    plan = WorkflowPlan(
        mission_id=mission_id,
        metadata={"provider_bindings": {task_id: {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }}},
        tasks=(task,),
    )
    return {
        "status": "proposed", "plan_id": plan_id, "plan": plan.to_dict(),
        "digest": plan.digest, "capability_id": CAPABILITY_ID,
        "provider_id": manifest.provider_id,
        "manifest_fingerprint": manifest.fingerprint,
        "execution_submitted": False, "approval_granted": False,
    }

def propose_tls_certificate_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    target: str,
) -> dict:
    """Prepare one fixed-port pinned TLS certificate observation for approval."""
    from .tls_cert_v2 import CAPABILITY_ID, _valid_hostname

    for name, value in (("mission_id", mission_id), ("plan_id", plan_id), ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}
    normalized = target.lower().rstrip(".")
    if not _valid_hostname(target) or target != normalized:
        return {"status": "blocked", "reason": "target must be a normalized hostname"}
    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}
    try:
        reload_scope = getattr(core.scope, "load", None)
        if not callable(reload_scope):
            return {"status": "blocked", "reason": "scope refresh is unavailable; no plan was created"}
        reload_scope()
        pinned_check = getattr(core.scope, "check_for_pinned_execution", None)
        if not callable(pinned_check):
            return {"status": "blocked", "reason": "pinned scope preflight is unavailable"}
        scope = pinned_check(normalized)
    except Exception:
        return {"status": "blocked", "reason": "pinned scope evaluation failed; no plan was created"}
    if not getattr(scope, "allowed", False):
        return {"status": "blocked", "reason": f"target is outside current scope: {getattr(scope, 'reason', '')}"}
    try:
        manifest = core.providers.manifest_for(CAPABILITY_ID)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "no V2 TLS certificate provider is registered"}
    if (
        manifest.capability_id != CAPABILITY_ID
        or manifest.scope_mode != "pinned_network"
        or manifest.impact != "moderate"
        or manifest.target_types != ("hostname",)
        or manifest.input_schema.get("properties") != {}
        or bool(manifest.input_schema.get("required"))
        or manifest.input_schema.get("additionalProperties") is not False
    ):
        return {"status": "blocked", "reason": "TLS certificate provider contract differs from the reviewed operation"}
    readiness = next((
        item for item in core.capability_inventory()
        if isinstance(item, dict)
        and item.get("capability_id") == CAPABILITY_ID
        and item.get("provider_id") == manifest.provider_id
    ), None)
    if not readiness or any(
        readiness.get(key) is not True
        for key in ("selected_for_execution", "installed", "executable")
    ):
        return {"status": "blocked", "reason": "V2 TLS certificate provider is not selected and ready"}
    task_id = "task-1"
    task = WorkflowTask(
        id=task_id,
        capability_id=CAPABILITY_ID,
        target=normalized,
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
        idempotency_key=uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"whaxon:tls-certificate-proposal:{mission_id}:{plan_id}",
        ).hex,
    )
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "TLS certificate provider or target compatibility check failed"}
    plan = WorkflowPlan(
        mission_id=mission_id,
        metadata={"provider_bindings": {task_id: {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }}},
        tasks=(task,),
    )
    return {
        "status": "proposed", "plan_id": plan_id, "plan": plan.to_dict(),
        "digest": plan.digest, "capability_id": CAPABILITY_ID,
        "provider_id": manifest.provider_id,
        "manifest_fingerprint": manifest.fingerprint,
        "execution_submitted": False, "approval_granted": False,
    }


def propose_passive_https_recon_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    target: str,
) -> dict:
    """Prepare a fixed HTTPS-header reconnaissance plan for operator review.

    The target is a bare hostname or IP literal; scope preflight never resolves
    it. The child resolves once and connects only to addresses returned by the
    scope manager.
    """
    from .http_recon_v2 import CAPABILITY_ID, _valid_target

    for name, value in (("mission_id", mission_id), ("plan_id", plan_id),
                        ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}
    if not _valid_target(target):
        return {"status": "blocked", "reason": "target must be a bare hostname or IP literal"}
    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}

    try:
        reload_scope = getattr(core.scope, "load", None)
        if callable(reload_scope):
            reload_scope()
        scope = core.scope.check_for_pinned_execution(target)
    except Exception:
        return {"status": "blocked", "reason": "pinned HTTPS scope evaluation failed; no plan was created"}
    if not getattr(scope, "allowed", False):
        return {
            "status": "blocked",
            "reason": f"target is outside current pinned-network scope: {getattr(scope, 'reason', '')}",
        }

    try:
        manifest = core.providers.manifest_for(CAPABILITY_ID)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "no V2 HTTPS-recon provider is registered"}
    target_type = "ip" if _is_ip_literal(target) else "hostname"
    if (
        manifest.capability_id != CAPABILITY_ID
        or manifest.scope_mode != "pinned_network"
        or manifest.impact != "moderate"
        or target_type not in manifest.target_types
        or manifest.input_schema.get("properties") != {}
        or bool(manifest.input_schema.get("required"))
        or manifest.input_schema.get("additionalProperties") is not False
    ):
        return {"status": "blocked", "reason": "HTTPS-recon provider contract differs from the reviewed fixed operation"}

    readiness = next((
        item for item in core.capability_inventory()
        if isinstance(item, dict)
        and item.get("capability_id") == CAPABILITY_ID
        and item.get("provider_id") == manifest.provider_id
    ), None)
    if not readiness or any(
        readiness.get(key) is not True
        for key in ("selected_for_execution", "installed", "executable")
    ):
        return {"status": "blocked", "reason": "V2 HTTPS-recon provider is not selected and ready"}

    task_id = "task-1"
    task = WorkflowTask(
        id=task_id,
        capability_id=CAPABILITY_ID,
        target=target,
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
        idempotency_key=uuid.uuid5(
            uuid.NAMESPACE_URL, f"whaxon:passive-https-recon:{mission_id}:{plan_id}",
        ).hex,
    )
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "V2 HTTPS provider or target compatibility check failed"}

    plan = WorkflowPlan(
        mission_id=mission_id,
        metadata={"provider_bindings": {task_id: {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }}},
        tasks=(task,),
    )
    return {
        "status": "proposed", "plan_id": plan_id, "plan": plan.to_dict(),
        "digest": plan.digest, "capability_id": CAPABILITY_ID,
        "provider_id": manifest.provider_id,
        "manifest_fingerprint": manifest.fingerprint,
        "execution_submitted": False, "approval_granted": False,
    }


def _is_ip_literal(target: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def propose_dns_full_posture_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    target: str,
) -> dict:
    """Prepare fixed CAA/DMARC/SPF DNS queries for operator review.

    The DMARC lookup is constructed internally and independently scope-checked.
    An exact host allow does not grant the _dmarc subdomain.
    """
    from .dns_full_v2 import CAPABILITY_ID
    from .recon_v2 import _valid_hostname

    for name, value in (("mission_id", mission_id), ("plan_id", plan_id),
                        ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}
    normalized = target.lower().rstrip(".")
    if (
        not _valid_hostname(target) or target != normalized
        or len(normalized) + 7 > 253
    ):
        return {
            "status": "blocked",
            "reason": "target must be a normalized hostname usable for _dmarc lookup",
        }
    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}

    try:
        reload_scope = getattr(core.scope, "load", None)
        if callable(reload_scope):
            reload_scope()
        for query_name in (normalized, f"_dmarc.{normalized}"):
            scope = core.scope.check_for_dns_query(query_name)
            if not getattr(scope, "allowed", False):
                return {
                    "status": "blocked",
                    "reason": (
                        f"required DNS lookup name is outside current scope: {query_name} "
                        f"({getattr(scope, 'reason', '')})"
                    ),
                }
    except Exception:
        return {"status": "blocked", "reason": "DNS-query scope evaluation failed; no plan was created"}

    try:
        manifest = core.providers.manifest_for(CAPABILITY_ID)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "no V2 DNS-posture provider is registered"}
    if (
        manifest.capability_id != CAPABILITY_ID
        or manifest.impact != "moderate"
        or manifest.target_types != ("hostname",)
        or manifest.input_schema.get("properties") != {}
        or bool(manifest.input_schema.get("required"))
        or manifest.input_schema.get("additionalProperties") is not False
    ):
        return {
            "status": "blocked",
            "reason": "DNS-posture provider contract differs from the reviewed operation",
        }

    readiness = next((
        item for item in core.capability_inventory()
        if isinstance(item, dict)
        and item.get("capability_id") == CAPABILITY_ID
        and item.get("provider_id") == manifest.provider_id
    ), None)
    if not readiness or any(
        readiness.get(key) is not True
        for key in ("selected_for_execution", "installed", "executable")
    ):
        return {"status": "blocked", "reason": "V2 DNS-posture provider is not selected and ready"}

    task_id = "task-1"
    task = WorkflowTask(
        id=task_id,
        capability_id=CAPABILITY_ID,
        target=normalized,
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
        idempotency_key=uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"whaxon:dns-full-proposal:{mission_id}:{plan_id}",
        ).hex,
    )
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {
            "status": "blocked",
            "reason": "DNS-posture provider or target compatibility check failed",
        }

    plan = WorkflowPlan(
        mission_id=mission_id,
        metadata={"provider_bindings": {task_id: {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }}},
        tasks=(task,),
    )
    return {
        "status": "proposed", "plan_id": plan_id, "plan": plan.to_dict(),
        "digest": plan.digest, "capability_id": CAPABILITY_ID,
        "provider_id": manifest.provider_id,
        "manifest_fingerprint": manifest.fingerprint,
        "execution_submitted": False, "approval_granted": False,
    }


def propose_tool_workflow_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    tool_id: str,
    target: str,
) -> dict:
    """Prepare a fixed-argument catalog tool plan without saving or executing it.

    Only installed, selected Engine V2 providers with an empty input contract are
    eligible. Admitted catalog tools use stable semantic operation IDs; other
    tools must have an explicitly bound capability. Scope and provider
    readiness are checked before a proposal is returned. Saving, approval and
    execution remain separate operator actions.
    """
    for name, value in (("mission_id", mission_id), ("plan_id", plan_id),
                        ("tool_id", tool_id), ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}

    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}
    if core.catalog.get(tool_id) is None:
        return {"status": "blocked", "reason": f"unknown catalog tool: {tool_id}"}

    try:
        reload_scope = getattr(core.scope, "load", None)
        if not callable(reload_scope):
            return {
                "status": "blocked",
                "reason": "scope refresh is unavailable; no plan was created",
            }
        reload_scope()
        execution_check = getattr(core.scope, "check_for_execution", None)
        if not callable(execution_check):
            return {
                "status": "blocked",
                "reason": "execution scope check is unavailable; no plan was created",
            }
        scope = execution_check(target)
    except Exception:
        return {"status": "blocked", "reason": "scope evaluation failed; no plan was created"}
    if not getattr(scope, "allowed", False):
        return {
            "status": "blocked",
            "reason": f"target is outside current scope: {getattr(scope, 'reason', '')}",
        }

    capability_id = SEMANTIC_OPERATION_IDS.get(tool_id, f"tool.{tool_id}")
    try:
        manifest = core.providers.manifest_for(capability_id)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "no V2 provider is registered for this tool"}
    if manifest.capability_id != capability_id:
        return {"status": "blocked", "reason": "provider capability does not match the requested tool"}
    if (
        manifest.impact != "moderate"
        or manifest.input_schema.get("properties") != {}
        or bool(manifest.input_schema.get("required"))
        or manifest.input_schema.get("additionalProperties") is not False
    ):
        return {
            "status": "blocked",
            "reason": "V2 plan proposals support only fixed-argument moderate-impact providers",
        }

    readiness = next((
        item for item in core.capability_inventory()
        if isinstance(item, dict)
        and item.get("capability_id") == capability_id
        and item.get("provider_id") == manifest.provider_id
    ), None)
    if not readiness or any(
        readiness.get(key) is not True
        for key in ("selected_for_execution", "installed", "executable")
    ):
        return {"status": "blocked", "reason": "V2 provider is not selected and ready for execution"}

    task_id = "task-1"
    task = WorkflowTask(
        id=task_id,
        capability_id=capability_id,
        target=target,
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
        idempotency_key=uuid.uuid5(
            uuid.NAMESPACE_URL, f"whaxon:tool-proposal:{mission_id}:{plan_id}",
        ).hex,
    )
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "V2 provider or target compatibility check failed"}

    plan = WorkflowPlan(
        mission_id=mission_id,
        metadata={"provider_bindings": {task_id: {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }}},
        tasks=(task,),
    )
    return {
        "status": "proposed",
        "plan_id": plan_id,
        "plan": plan.to_dict(),
        "digest": plan.digest,
        "capability_id": capability_id,
        "provider_id": manifest.provider_id,
        "manifest_fingerprint": manifest.fingerprint,
        "execution_submitted": False,
        "approval_granted": False,
    }


def propose_finding_verification_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    source_job_id: str,
    finding_seq: int,
    mode: str,
) -> dict:
    """Prepare a plan for the bounded V2 SQLi/XSS verifier or retester.

    The source job and finding must already be persisted. Provider resolution
    verifies the V2 evidence seal and exact finding-kind contract; this helper
    never contacts the target, saves the plan, grants approval, or executes it.
    """
    for name, value in (("mission_id", mission_id), ("plan_id", plan_id),
                        ("source_job_id", source_job_id)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}
    if isinstance(finding_seq, bool) or not isinstance(finding_seq, int) or finding_seq < 0:
        return {"status": "blocked", "reason": "finding_seq must be a non-negative integer"}
    if mode not in {"verify", "retest"}:
        return {"status": "blocked", "reason": "mode must be verify or retest"}
    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}

    source_job = core.store.get(source_job_id)
    selected = next((
        row for row in (core.store.get_findings(source_job_id) or [])
        if isinstance(row, dict) and row.get("seq") == finding_seq
    ), None)
    if source_job is None or selected is None:
        return {"status": "blocked", "reason": "source job or finding sequence was not found"}
    kind = selected.get("kind")
    if not isinstance(kind, str):
        return {"status": "blocked", "reason": "finding kind is missing or invalid"}
    capability_by_kind = {
        ("verify", "sqli"): "tool.verify_sqli",
        ("verify", "sql_injection"): "tool.verify_sqli",
        ("verify", "xss"): "tool.verify_xss",
        ("retest", "sqli"): "tool.retest_sqli",
        ("retest", "sql_injection"): "tool.retest_sqli",
        ("retest", "xss"): "tool.retest_xss",
    }
    capability_id = capability_by_kind.get((mode, kind))
    if capability_id is None:
        return {"status": "blocked", "reason": "finding kind is unsupported by the V2 verifier"}
    target = source_job.get("target")
    if not isinstance(target, str) or not target:
        return {"status": "blocked", "reason": "source job has no exact target"}
    try:
        scope = core.scope.check(target)
    except Exception:
        return {"status": "blocked", "reason": "scope evaluation failed; no plan was created"}
    if not getattr(scope, "allowed", False):
        return {
            "status": "blocked",
            "reason": f"target is outside current scope: {getattr(scope, 'reason', '')}",
        }

    try:
        manifest = core.providers.manifest_for(capability_id)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "V2 verification provider is unavailable"}
    task_id = "verification-1"
    task = WorkflowTask(
        id=task_id,
        capability_id=capability_id,
        target=target,
        inputs={"source_job_id": source_job_id, "finding_seq": finding_seq},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
        idempotency_key=uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"whaxon:verification-proposal:{mission_id}:{plan_id}",
        ).hex,
    )
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {
            "status": "blocked",
            "reason": "source evidence, provider, target, or verification contract is not valid",
        }

    plan = WorkflowPlan(
        mission_id=mission_id,
        metadata={"provider_bindings": {task_id: {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }}},
        tasks=(task,),
    )
    return {
        "status": "proposed",
        "plan_id": plan_id,
        "plan": plan.to_dict(),
        "digest": plan.digest,
        "capability_id": capability_id,
        "provider_id": manifest.provider_id,
        "manifest_fingerprint": manifest.fingerprint,
        "execution_submitted": False,
        "approval_granted": False,
    }


def propose_passive_robots_recon_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    target: str,
) -> dict:
    """Prepare the two fixed robots/sitemap HTTPS requests for operator review."""
    from .robots_recon_v2 import CAPABILITY_ID, _valid_target

    for name, value in (("mission_id", mission_id), ("plan_id", plan_id),
                        ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}
    if not _valid_target(target):
        return {"status": "blocked", "reason": "target must be a bare hostname or IP literal"}
    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}

    try:
        reload_scope = getattr(core.scope, "load", None)
        if callable(reload_scope):
            reload_scope()
        scope = core.scope.check_for_pinned_execution(target)
    except Exception:
        return {"status": "blocked", "reason": "pinned robots scope evaluation failed; no plan was created"}
    if not getattr(scope, "allowed", False):
        return {
            "status": "blocked",
            "reason": f"target is outside current pinned-network scope: {getattr(scope, 'reason', '')}",
        }

    try:
        manifest = core.providers.manifest_for(CAPABILITY_ID)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "no V2 robots provider is registered"}
    target_type = "ip" if _is_ip_literal(target) else "hostname"
    if (
        manifest.capability_id != CAPABILITY_ID
        or manifest.scope_mode != "pinned_network"
        or "https" not in manifest.protocols
        or manifest.impact != "moderate"
        or target_type not in manifest.target_types
        or manifest.input_schema.get("properties") != {}
        or bool(manifest.input_schema.get("required"))
        or manifest.input_schema.get("additionalProperties") is not False
    ):
        return {"status": "blocked", "reason": "robots provider contract differs from the fixed HTTPS operation"}

    readiness = next((
        item for item in core.capability_inventory()
        if isinstance(item, dict)
        and item.get("capability_id") == CAPABILITY_ID
        and item.get("provider_id") == manifest.provider_id
    ), None)
    if not readiness or any(
        readiness.get(key) is not True
        for key in ("selected_for_execution", "installed", "executable")
    ):
        return {"status": "blocked", "reason": "V2 robots provider is not selected and ready"}

    task_id = "robots-1"
    task = WorkflowTask(
        id=task_id,
        capability_id=CAPABILITY_ID,
        target=target,
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
        idempotency_key=uuid.uuid5(
            uuid.NAMESPACE_URL, f"whaxon:passive-robots-recon:{mission_id}:{plan_id}",
        ).hex,
    )
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "V2 robots provider or target compatibility check failed"}

    plan = WorkflowPlan(
        mission_id=mission_id,
        metadata={"provider_bindings": {task_id: {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }}},
        tasks=(task,),
    )
    return {
        "status": "proposed",
        "plan_id": plan_id,
        "plan": plan.to_dict(),
        "digest": plan.digest,
        "capability_id": CAPABILITY_ID,
        "provider_id": manifest.provider_id,
        "manifest_fingerprint": manifest.fingerprint,
        "execution_submitted": False,
        "approval_granted": False,
    }


def propose_passive_redirect_observation_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    target: str,
) -> dict:
    """Prepare one fixed HTTPS first-hop observation for operator review."""
    from .redirect_recon_v2 import CAPABILITY_ID, _valid_target

    for name, value in (("mission_id", mission_id), ("plan_id", plan_id),
                        ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}
    if not _valid_target(target):
        return {"status": "blocked", "reason": "target must be a bare hostname or IP literal"}
    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}

    try:
        reload_scope = getattr(core.scope, "load", None)
        if callable(reload_scope):
            reload_scope()
        scope = core.scope.check_for_pinned_execution(target)
    except Exception:
        return {"status": "blocked", "reason": "pinned redirect scope evaluation failed; no plan was created"}
    if not getattr(scope, "allowed", False):
        return {
            "status": "blocked",
            "reason": f"target is outside current pinned-network scope: {getattr(scope, 'reason', '')}",
        }

    try:
        manifest = core.providers.manifest_for(CAPABILITY_ID)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "no V2 redirect observation provider is registered"}
    target_type = "ip" if _is_ip_literal(target) else "hostname"
    if (
        manifest.capability_id != CAPABILITY_ID
        or manifest.scope_mode != "pinned_network"
        or "https" not in manifest.protocols
        or manifest.impact != "moderate"
        or target_type not in manifest.target_types
        or manifest.input_schema.get("properties") != {}
        or bool(manifest.input_schema.get("required"))
        or manifest.input_schema.get("additionalProperties") is not False
    ):
        return {"status": "blocked", "reason": "redirect provider contract differs from the fixed HTTPS operation"}
    readiness = next((
        item for item in core.capability_inventory()
        if isinstance(item, dict)
        and item.get("capability_id") == CAPABILITY_ID
        and item.get("provider_id") == manifest.provider_id
    ), None)
    if not readiness or any(
        readiness.get(key) is not True
        for key in ("selected_for_execution", "installed", "executable")
    ):
        return {"status": "blocked", "reason": "V2 redirect provider is not selected and ready"}

    task_id = "redirect-1"
    task = WorkflowTask(
        id=task_id,
        capability_id=CAPABILITY_ID,
        target=target,
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
        idempotency_key=uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"whaxon:passive-redirect-observation:{mission_id}:{plan_id}",
        ).hex,
    )
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "V2 redirect provider or target compatibility check failed"}

    plan = WorkflowPlan(
        mission_id=mission_id,
        metadata={"provider_bindings": {task_id: {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }}},
        tasks=(task,),
    )
    return {
        "status": "proposed",
        "plan_id": plan_id,
        "plan": plan.to_dict(),
        "digest": plan.digest,
        "capability_id": CAPABILITY_ID,
        "provider_id": manifest.provider_id,
        "manifest_fingerprint": manifest.fingerprint,
        "execution_submitted": False,
        "approval_granted": False,
    }


def propose_passive_security_txt_recon_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    target: str,
) -> dict:
    """Prepare one fixed security.txt HTTPS request for operator review."""
    from .security_txt_v2 import CAPABILITY_ID, _valid_target

    for name, value in (("mission_id", mission_id), ("plan_id", plan_id),
                        ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}
    if not _valid_target(target):
        return {"status": "blocked", "reason": "target must be a bare hostname or IP literal"}
    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}
    try:
        reload_scope = getattr(core.scope, "load", None)
        if callable(reload_scope):
            reload_scope()
        scope = core.scope.check_for_pinned_execution(target)
    except Exception:
        return {"status": "blocked", "reason": "pinned security.txt scope evaluation failed; no plan was created"}
    if not getattr(scope, "allowed", False):
        return {"status": "blocked", "reason": f"target is outside current pinned-network scope: {getattr(scope, 'reason', '')}"}
    try:
        manifest = core.providers.manifest_for(CAPABILITY_ID)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "no V2 security.txt provider is registered"}
    target_type = "ip" if _is_ip_literal(target) else "hostname"
    if (manifest.capability_id != CAPABILITY_ID or manifest.scope_mode != "pinned_network"
            or "https" not in manifest.protocols or manifest.impact != "moderate"
            or target_type not in manifest.target_types
            or manifest.input_schema.get("properties") != {}
            or bool(manifest.input_schema.get("required"))
            or manifest.input_schema.get("additionalProperties") is not False):
        return {"status": "blocked", "reason": "security.txt provider contract differs from the fixed HTTPS operation"}
    readiness = next((item for item in core.capability_inventory()
        if isinstance(item, dict) and item.get("capability_id") == CAPABILITY_ID
        and item.get("provider_id") == manifest.provider_id), None)
    if not readiness or any(readiness.get(key) is not True
            for key in ("selected_for_execution", "installed", "executable")):
        return {"status": "blocked", "reason": "V2 security.txt provider is not selected and ready"}
    task_id = "security-txt-1"
    task = WorkflowTask(id=task_id, capability_id=CAPABILITY_ID, target=target, inputs={},
        permissions=manifest.permissions, impact=manifest.impact, timeout_s=manifest.timeout_s,
        idempotency_key=uuid.uuid5(uuid.NAMESPACE_URL,
            f"whaxon:passive-security-txt-recon:{mission_id}:{plan_id}").hex)
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "V2 security.txt provider or target compatibility check failed"}
    plan = WorkflowPlan(mission_id=mission_id, metadata={"provider_bindings": {task_id: {
        "provider_id": manifest.provider_id, "manifest_fingerprint": manifest.fingerprint,
    }}}, tasks=(task,))
    return {"status": "proposed", "plan_id": plan_id, "plan": plan.to_dict(),
        "digest": plan.digest, "capability_id": CAPABILITY_ID,
        "provider_id": manifest.provider_id, "manifest_fingerprint": manifest.fingerprint,
        "execution_submitted": False, "approval_granted": False}


def propose_passive_headers_recon_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    target: str,
) -> dict:
    """Prepare one fixed root-response security-header request for review."""
    from .headers_v2 import CAPABILITY_ID, _valid_target

    for name, value in (("mission_id", mission_id), ("plan_id", plan_id),
                        ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}
    if not _valid_target(target):
        return {"status": "blocked", "reason": "target must be a bare hostname or IP literal"}
    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}
    try:
        reload_scope = getattr(core.scope, "load", None)
        if callable(reload_scope):
            reload_scope()
        scope = core.scope.check_for_pinned_execution(target)
    except Exception:
        return {"status": "blocked", "reason": "pinned headers scope evaluation failed; no plan was created"}
    if not getattr(scope, "allowed", False):
        return {"status": "blocked", "reason": f"target is outside current pinned-network scope: {getattr(scope, 'reason', '')}"}
    try:
        manifest = core.providers.manifest_for(CAPABILITY_ID)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "no V2 headers provider is registered"}
    target_type = "ip" if _is_ip_literal(target) else "hostname"
    if (manifest.capability_id != CAPABILITY_ID or manifest.scope_mode != "pinned_network"
            or "https" not in manifest.protocols or manifest.impact != "moderate"
            or target_type not in manifest.target_types
            or manifest.input_schema.get("properties") != {}
            or bool(manifest.input_schema.get("required"))
            or manifest.input_schema.get("additionalProperties") is not False):
        return {"status": "blocked", "reason": "headers provider contract differs from the fixed HTTPS operation"}
    readiness = next((item for item in core.capability_inventory()
        if isinstance(item, dict) and item.get("capability_id") == CAPABILITY_ID
        and item.get("provider_id") == manifest.provider_id), None)
    if not readiness or any(readiness.get(key) is not True
            for key in ("selected_for_execution", "installed", "executable")):
        return {"status": "blocked", "reason": "V2 headers provider is not selected and ready"}
    task_id = "headers-1"
    task = WorkflowTask(id=task_id, capability_id=CAPABILITY_ID, target=target, inputs={},
        permissions=manifest.permissions, impact=manifest.impact, timeout_s=manifest.timeout_s,
        idempotency_key=uuid.uuid5(uuid.NAMESPACE_URL,
            f"whaxon:passive-headers-recon:{mission_id}:{plan_id}").hex)
    try:
        core.providers.resolve_task(task, require_installed=True)
    except (LookupError, ValueError, TypeError, RuntimeError):
        return {"status": "blocked", "reason": "V2 headers provider or target compatibility check failed"}
    plan = WorkflowPlan(mission_id=mission_id, metadata={"provider_bindings": {task_id: {
        "provider_id": manifest.provider_id, "manifest_fingerprint": manifest.fingerprint,
    }}}, tasks=(task,))
    return {"status": "proposed", "plan_id": plan_id, "plan": plan.to_dict(),
        "digest": plan.digest, "capability_id": CAPABILITY_ID,
        "provider_id": manifest.provider_id, "manifest_fingerprint": manifest.fingerprint,
        "execution_submitted": False, "approval_granted": False}


def propose_passive_recon_plan(
    core,
    *,
    mission_id: str,
    plan_id: str,
    target: str,
    checks: list[str] | None = None,
) -> dict:
    """Build one reviewable plan from the fixed V2 recon providers available.

    No provider is dispatched. If checks are omitted, unimplemented or
    unavailable checks are reported as omissions. If checks are explicit, any
    unsupported or unavailable check blocks the whole proposal.
    """
    from .workflow import WorkflowPlan, WorkflowTask

    builders = {
        "dns": propose_passive_dns_plan,
        "dns_full": propose_dns_full_posture_plan,
        "ssl": propose_tls_certificate_plan,
        "https": propose_passive_https_recon_plan,
        "headers": propose_passive_headers_recon_plan,
        "redirects": propose_passive_redirect_observation_plan,
        "robots": propose_passive_robots_recon_plan,
        "security_txt": propose_passive_security_txt_recon_plan,
    }
    legacy_only = ("tech", "cookies", "waf")
    for name, value in (("mission_id", mission_id), ("plan_id", plan_id), ("target", target)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            return {"status": "blocked", "reason": f"{name} must be normalized non-empty text"}
    if checks is not None and (
        not isinstance(checks, list)
        or any(not isinstance(name, str) or not name or name != name.strip() for name in checks)
    ):
        return {"status": "blocked", "reason": "recon checks must be normalized strings"}
    requested = tuple(checks) if checks is not None else tuple(builders) + legacy_only
    explicit = checks is not None
    if not requested or len(set(requested)) != len(requested):
        return {"status": "blocked", "reason": "recon checks must be a non-empty unique list"}
    unsupported = [name for name in requested if name not in builders]
    if any(name not in legacy_only for name in unsupported) or (explicit and unsupported):
        return {
            "status": "blocked",
            "reason": f"no V2 recon provider is admitted for checks: {', '.join(unsupported)}",
            "execution_submitted": False,
            "approval_granted": False,
        }
    if core.store.get_mission(mission_id) is None:
        return {"status": "blocked", "reason": f"unknown mission: {mission_id}"}

    tasks: list[WorkflowTask] = []
    provider_bindings: dict[str, dict[str, str]] = {}
    included: list[str] = []
    omitted: list[dict[str, str]] = [
        {"check": name, "reason": "legacy-only; no admitted V2 provider"}
        for name in unsupported
    ]
    for check in requested:
        builder = builders.get(check)
        if builder is None:
            continue
        proposal = builder(
            core, mission_id=mission_id,
            plan_id=f"{plan_id}-{check}", target=target,
        )
        if not isinstance(proposal, dict) or proposal.get("status") != "proposed":
            reason = (
                proposal.get("reason", "provider proposal was malformed")
                if isinstance(proposal, dict) else "provider proposal was malformed"
            )
            if explicit:
                return {
                    "status": "blocked",
                    "reason": f"requested {check} check is unavailable: {reason}",
                    "execution_submitted": False,
                    "approval_granted": False,
                }
            omitted.append({"check": check, "reason": str(reason)[:512]})
            continue
        child_plan = proposal.get("plan")
        child_tasks = child_plan.get("tasks") if isinstance(child_plan, dict) else None
        metadata = child_plan.get("metadata") if isinstance(child_plan, dict) else None
        bindings = metadata.get("provider_bindings") if isinstance(metadata, dict) else None
        if not isinstance(child_tasks, list) or len(child_tasks) != 1 or not isinstance(bindings, dict):
            return {
                "status": "blocked",
                "reason": f"{check} provider returned a malformed fixed plan",
                "execution_submitted": False,
                "approval_granted": False,
            }
        source_task = child_tasks[0]
        source_id = source_task.get("id") if isinstance(source_task, dict) else None
        binding = bindings.get(source_id) if isinstance(source_id, str) else None
        if (
            not isinstance(binding, dict)
            or not isinstance(binding.get("provider_id"), str)
            or not isinstance(binding.get("manifest_fingerprint"), str)
        ):
            return {
                "status": "blocked",
                "reason": f"{check} provider returned an incomplete manifest binding",
                "execution_submitted": False,
                "approval_granted": False,
            }
        task_id = f"task-{check}"
        try:
            task = WorkflowTask.from_dict({**source_task, "id": task_id})
        except (TypeError, ValueError, KeyError) as exc:
            return {
                "status": "blocked",
                "reason": f"{check} provider returned an invalid task: {exc}",
                "execution_submitted": False,
                "approval_granted": False,
            }
        tasks.append(task)
        provider_bindings[task_id] = {
            "provider_id": binding["provider_id"],
            "manifest_fingerprint": binding["manifest_fingerprint"],
        }
        included.append(check)

    if not tasks:
        return {
            "status": "blocked",
            "reason": "no requested recon checks have a ready V2 provider",
            "included_checks": [],
            "omitted_checks": omitted,
            "execution_submitted": False,
            "approval_granted": False,
        }
    plan = WorkflowPlan(
        mission_id=mission_id,
        tasks=tuple(tasks),
        metadata={
            "proposal_type": "passive_recon",
            "provider_bindings": provider_bindings,
            "requested_checks": list(requested),
            "included_checks": included,
            "omitted_checks": omitted,
        },
    )
    return {
        "status": "proposed",
        "plan_id": plan_id,
        "plan": plan.to_dict(),
        "digest": plan.digest,
        "included_checks": included,
        "omitted_checks": omitted,
        "execution_submitted": False,
        "approval_granted": False,
    }
