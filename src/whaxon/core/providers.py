"""Bridge WHAXON's real catalog tools and adapters into Engine v2 capabilities."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import shutil
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from .capabilities import (
    CapabilityManifest,
    CapabilityRegistry,
    CapabilityRequirements,
    CapabilityResolution,
    CapabilityUnavailable,
)
from .workflow import WorkflowTask

# Conservative target formats supported by the actual packaged argv templates.
# These are declarations, not authorization or proof of verified execution.
_CATALOG_TARGETS = {
    "nmap": ("hostname", "ip"),
    "nikto": ("hostname", "ip", "url"),
    "gobuster": ("hostname", "ip"),
    "ffuf": ("url",),
    "nuclei": ("url",),
    "wpscan": ("url",),
    "sqlmap": ("url",),
    "whois": ("hostname", "ip"),
    "dig": ("hostname",),
    "theharvester": ("hostname",),
    "dnsrecon": ("hostname",),
    "arjun": ("url",),
}
# Stable operation identities (not scanner or executable names). These are
# conservative aliases for the currently admitted, fixed-argv local adapters.
# An alias has no permission/validation authority of its own.
SEMANTIC_OPERATION_IDS = {
    "nmap": "network.services.discover",
    "nikto": "web.server.audit",
    "gobuster": "web.directories.enumerate",
    "ffuf": "web.paths.fuzz",
    "nuclei": "web.templates.assess",
    "wpscan": "web.wordpress.audit",
    "sqlmap": "web.sql_injection.assess",
    "whois": "domain.registration.lookup",
    "dig": "dns.records.query",
    "theharvester": "osint.domain.contacts.search",
    "dnsrecon": "dns.records.enumerate",
    "arjun": "web.parameters.discover",
}
if set(SEMANTIC_OPERATION_IDS) != set(_CATALOG_TARGETS):
    raise RuntimeError("semantic operation map and admitted adapter list differ")

_ADAPTER_SERIES = "catalog-v2"
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _valid_host(host: str) -> bool:
    if not isinstance(host, str) or not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if len(host) > 253 or not host.isascii():
        return False
    return all(_HOST_LABEL.fullmatch(label) for label in host.rstrip(".").split("."))


def _target_type(target: str) -> str:
    """Classify a literal network target without DNS lookups or side effects."""
    if not isinstance(target, str) or not target or target != target.strip():
        raise ValueError("target must be a non-empty normalized string")
    if any(ord(char) < 33 or ord(char) == 127 for char in target):
        raise ValueError("target contains control characters or whitespace")
    if "://" in target:
        try:
            parsed = urlsplit(target)
            hostname, port = parsed.hostname, parsed.port
        except ValueError as exc:
            raise ValueError("invalid URL authority") from exc
        if (
            parsed.scheme not in ("http", "https") or not hostname
            or not _valid_host(hostname) or not parsed.netloc
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or (port is not None and port <= 0)
        ):
            raise ValueError("unsupported URL target")
        return "url"
    try:
        ipaddress.ip_address(target.strip("[]"))
        return "ip"
    except ValueError:
        if not _valid_host(target) or ":" in target or any(
            char in target for char in "/?#@\\[]"
        ):
            raise ValueError("invalid hostname target") from None
        return "hostname"


def _catalog_version(tool) -> str:
    """Version the tool identity and argv contract, not its availability."""
    fields = {
        key: getattr(tool, key, "") for key in (
            "id", "binary", "args", "transport", "outfile_flag", "command",
        )
    }
    digest = hashlib.sha256(
        json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    return f"{_ADAPTER_SERIES}.{digest}"


def _tool_available(tool) -> bool:
    """Live binary presence is not equivalent to smoke/lab verification."""
    if tool is None or not bool(getattr(tool, "available", False)):
        return False
    binary = getattr(tool, "binary", "")
    return not binary or shutil.which(binary) is not None


class CatalogAdapterProvider:
    """Resolve approved read-only catalog tools and execute through ToolRunner.

    ToolRunner remains the sole execution path: scope checks, argv construction,
    process isolation, timeout handling, adapter parsing and evidence events
    are therefore shared with the existing CLI and UI.
    """

    def __init__(
        self, *, catalog, runner, store, registry: CapabilityRegistry,
        suppress_legacy_followup=None,
    ):
        self.catalog = catalog
        self.runner = runner
        self.store = store
        self.registry = registry
        self._suppress_legacy_followup = suppress_legacy_followup
        self._tool_by_provider: dict[str, str] = {}
        self._manifest_by_provider: dict[str, CapabilityManifest] = {}
        from ..adapters import get_adapter

        for tool in catalog.list():
            if (
                tool.id not in _CATALOG_TARGETS
                or getattr(tool, "transport", "cli") != "cli"
                or get_adapter(tool.id) is None
            ):
                continue
            provider_id = f"whaxon.adapter.{tool.id}"
            manifest = CapabilityManifest(
                capability_id=f"tool.{tool.id}",
                provider_id=provider_id,
                provider_version=_catalog_version(tool),
                transports=("local_process",),
                target_types=_CATALOG_TARGETS[tool.id],
                permissions=("network.scan",),
                side_effects=("network_traffic", "target_service_logs"),
                impact="moderate",
                readiness="registered",
                timeout_s=300.0,
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                output_schema={"type": "object"},
                limitations=(
                    "Catalog defaults only; dynamic command arguments are unsupported.",
                    "Requires a locally installed binary and explicit scope/approval.",
                    "Zero exit status is not independent vulnerability verification.",
                ),
            )
            registry.register(manifest)
            self._tool_by_provider[provider_id] = tool.id
            self._manifest_by_provider[provider_id] = manifest

    def bindings(self) -> tuple[CapabilityManifest, ...]:
        """Trusted in-process registrations, not arbitrary persisted manifests."""
        return tuple(
            self._manifest_by_provider[key]
            for key in sorted(self._manifest_by_provider)
        )

    def portfolio_inventory(self) -> list[dict]:
        """Account for EVERY catalog entry, including unsupported execution paths.

        This is read-only reconciliation. Presence in the catalog, a working
        adapter, or an installed executable never grants execution permission.
        """
        from ..adapters import get_adapter

        bound_ids = set(self._tool_by_provider.values())
        rows: list[dict[str, Any]] = []
        for tool in sorted(self.catalog.list(), key=lambda entry: entry.id):
            if tool.id in bound_ids:
                continue
            transport = getattr(tool, "transport", "cli")
            if transport != "cli":
                reason = "unsupported_transport"
            elif tool.id not in _CATALOG_TARGETS:
                reason = "not_admitted_for_engine_v2"
            elif get_adapter(tool.id) is None:
                reason = "no_supported_adapter"
            else:
                reason = "catalog_changed_requires_provider_reload"
            rows.append({
                "capability_id": f"tool.{tool.id}",
                "provider_id": None,
                "provider_version": None,
                "manifest_fingerprint": None,
                "transport": transport,
                "target_types": [],
                "registry_digest": self.registry.digest,
                "registered": False,
                "installed": _tool_available(tool) if transport == "cli" else False,
                "executable": False,
                "readiness": "unsupported",
                "reason": reason,
                "authorization_required": True,
                "smoke_tested": False,
                "lab_validated": False,
                "end_to_end_verified": False,
            })
        return rows

    def portfolio_audit(self) -> dict:
        """Read-only crosswalk of all catalog tools AND registered adapters.

        No binary execution, provider registration, approval, or new plugin
        loading is performed by this inspection.
        """
        from ..adapters import list_adapters

        catalog = {tool.id: tool for tool in self.catalog.list()}
        adapters = set(list_adapters())
        bound = set(self._tool_by_provider.values())
        rows: list[dict[str, Any]] = []
        for tool_id in sorted(set(catalog) | adapters):
            tool = catalog.get(tool_id)
            has_adapter = tool_id in adapters
            bound_provider_id = f"whaxon.adapter.{tool_id}"
            expected = self._manifest_by_provider.get(bound_provider_id)
            current = (
                next((
                    item for item in self.registry.list(expected.capability_id)
                    if item.provider_id == expected.provider_id
                    and item.provider_version == expected.provider_version
                ), None)
                if expected is not None else None
            )
            binding_current = (
                tool is not None
                and tool_id in bound
                and has_adapter
                and expected is not None
                and current is not None
                and current.fingerprint == expected.fingerprint
                and _catalog_version(tool) == expected.provider_version
                and getattr(tool, "transport", "cli") == "cli"
            )
            was_bound = tool_id in bound
            if tool is None:
                state = "adapter_only"
                reason = "adapter_not_in_catalog"
            elif was_bound and not binding_current:
                state = "stale_binding"
                reason = (
                    "registered_adapter_disappeared" if not has_adapter
                    else "catalog_contract_changed"
                    if expected is not None and _catalog_version(tool) != expected.provider_version
                    else "manifest_binding_mismatch"
                    if current is None or expected is None
                    or current.fingerprint != expected.fingerprint
                    else "unsupported_transport"
                )
            elif binding_current:
                state = "bound"
                reason = "registered_not_lab_verified"
            elif getattr(tool, "transport", "cli") != "cli":
                state = "unsupported_transport"
                reason = "requires_separate_transport_provider"
            elif tool_id not in _CATALOG_TARGETS:
                state = "not_admitted"
                reason = "no_engine_v2_execution_admission"
            elif not has_adapter:
                state = "catalog_only"
                reason = "no_registered_adapter"
            else:
                state = "unbound"
                reason = "catalog_or_binding_changed"
            rows.append({
                "tool_id": tool_id,
                "catalog_present": tool is not None,
                "adapter_registered": has_adapter,
                "transport": getattr(tool, "transport", None) if tool else None,
                "v2_provider_bound": binding_current,
                "binding_current": binding_current,
                "previously_bound": was_bound,
                "bound_provider_id": expected.provider_id if expected else None,
                "bound_manifest_fingerprint": expected.fingerprint if expected else None,
                "state": state,
                "reason": reason,
                "authorization_required": True,
                "smoke_tested": False,
                "lab_validated": False,
                "end_to_end_verified": False,
            })
        summary = {state: sum(row["state"] == state for row in rows) for state in (
            "bound", "stale_binding", "catalog_only", "adapter_only",
            "not_admitted", "unsupported_transport", "unbound",
        )}
        return {
            "schema_version": "whaxon.portfolio-audit.v1",
            "catalog_count": len(catalog),
            "adapter_count": len(adapters),
            "rows": rows,
            "summary": summary,
            "execution_enabled_by_audit": False,
        }

    def inventory(self) -> list[dict]:
        """Live readiness is observational and never rewrites versioned manifests."""
        inventory = []
        for provider_id, expected in sorted(self._manifest_by_provider.items()):
            tool_id = self._tool_by_provider[provider_id]
            tool = self.catalog.get(tool_id)
            current = next((
                item for item in self.registry.list(expected.capability_id)
                if item.provider_id == provider_id
                and item.provider_version == expected.provider_version
            ), None)
            bound = current is not None and current.fingerprint == expected.fingerprint
            current_catalog = bool(
                tool is not None and _catalog_version(tool) == expected.provider_version
                and getattr(tool, "transport", "cli") == "cli"
            )
            installed = current_catalog and _tool_available(tool)
            inventory.append({
                "capability_id": expected.capability_id,
                "provider_id": provider_id,
                "provider_version": expected.provider_version,
                "manifest_fingerprint": expected.fingerprint,
                "transport": "local_process",
                "target_types": list(expected.target_types),
                "registry_digest": self.registry.digest,
                "registered": bound,
                "installed": installed,
                "executable": bound and installed,
                "readiness": "installed" if bound and installed else "registered" if bound else "blocked",
                "reason": (
                    "ready_for_local_execution" if bound and installed
                    else "manifest_binding_mismatch" if not bound
                    else "catalog_changed_requires_reload" if not current_catalog
                    else "binary_not_installed"
                ),
                "authorization_required": True,
                "smoke_tested": False,
                "lab_validated": False,
                "end_to_end_verified": False,
            })
        return inventory

    def resolve_task(self, task: WorkflowTask, *, require_installed: bool = False):
        """Resolve only the locally bound manifest, never a stored imposter."""
        if not isinstance(task, WorkflowTask):
            raise TypeError("provider task must be a WorkflowTask")
        if task.inputs:
            raise ValueError(
                "catalog adapter providers accept no dynamic inputs; use the approved catalog defaults"
            )
        provider_id = f"whaxon.adapter.{task.capability_id.removeprefix('tool.')}"
        expected = self._manifest_by_provider.get(provider_id)
        if expected is None or expected.capability_id != task.capability_id:
            raise CapabilityUnavailable(task.capability_id, ("no bound local adapter",))
        tool = self.catalog.get(self._tool_by_provider[provider_id])
        if tool is None or _catalog_version(tool) != expected.provider_version:
            raise CapabilityUnavailable(task.capability_id, (
                "catalog executable/argv changed since provider registration",))
        if getattr(tool, "transport", "cli") != "cli":
            raise CapabilityUnavailable(task.capability_id, ("local transport unavailable",))
        from ..adapters import get_adapter

        if get_adapter(tool.id) is None:
            raise CapabilityUnavailable(
                task.capability_id, ("bound tool adapter is no longer registered",),
            )
        target_type = _target_type(task.target)
        if tool.id == "ffuf" and target_type == "url" and urlsplit(task.target).query:
            raise CapabilityUnavailable(task.capability_id, (
                "ffuf target query is incompatible with the /FUZZ template",))
        resolution = self.registry.resolve(
            task.capability_id,
            CapabilityRequirements(
                transport="local_process",
                target_type=target_type,
                required_permissions=tuple(task.permissions),
                maximum_impact=task.impact,
                allowed_providers=(provider_id,),
                allowed_versions=(expected.provider_version,),
                allowed_fingerprints=(expected.fingerprint,),
                allowed_side_effects=expected.side_effects,
            ),
        )
        if resolution.manifest.fingerprint != expected.fingerprint:
            raise CapabilityUnavailable(task.capability_id, ("unbound provider manifest",))
        if require_installed and not _tool_available(tool):
            raise RuntimeError(f"required tool is not installed: {tool.id}")
        return resolution

    async def dispatch(self, task: WorkflowTask) -> dict:
        resolution = self.resolve_task(task, require_installed=True)
        expected = resolution.manifest
        if set(task.permissions) != set(expected.permissions) or task.impact != expected.impact:
            raise CapabilityUnavailable(task.capability_id, (
                "task permission/impact differs from the bound provider contract",))
        tool_id = self._tool_by_provider[expected.provider_id]
        job_id = uuid.uuid4().hex[:12]
        # Fail closed if the old Automator cannot be fenced. The fence must
        # happen before ToolRunner may publish any findings.
        if self._suppress_legacy_followup is not None:
            self._suppress_legacy_followup(job_id)
        timeout_s = min(float(task.timeout_s), expected.timeout_s)
        returned_id = await self.runner.run_tool(
            tool_id=tool_id,
            target=task.target,
            job_id=job_id,
            timeout_s=timeout_s,
            phase="workflow",
        )
        if returned_id != job_id:
            raise RuntimeError("provider runner returned a mismatched execution identity")
        # EventBus persistence is scheduled onto the bound Core event loop.
        await asyncio.sleep(0)
        job = self.store.get(job_id)
        if job is None:
            raise RuntimeError(f"tool execution {job_id} did not persist a job record")
        if (
            job.get("id") != job_id
            or job.get("tool") != tool_id
            or job.get("target") != task.target
        ):
            raise RuntimeError("persisted provider job identity does not match dispatched task")
        if job.get("error") == "timeout":
            raise TimeoutError(f"{tool_id} exceeded {timeout_s:g}s")
        if job.get("status") != "finished" or job.get("exit_code") != 0:
            raise RuntimeError(
                f"{tool_id} failed (status={job.get('status')}, exit_code={job.get('exit_code')})"
            )
        findings = self.store.get_findings(job_id)
        if not isinstance(findings, list):
            raise RuntimeError("provider findings could not be verified in durable store")
        return {
            "job_id": job_id,
            "tool_id": tool_id,
            "target": task.target,
            "exit_code": job["exit_code"],
            "duration_s": job.get("duration_s"),
            "findings": findings,
            "provider_id": expected.provider_id,
            "provider_version": expected.provider_version,
            "manifest_fingerprint": expected.fingerprint,
            "registry_digest": resolution.registry_digest,
            "transport": "local_process",
        }


class SemanticOperationProvider:
    """Trusted V2 operation aliases around the existing local adapter bridge.

    The same ToolRunner, authorization, artifact store and parser still execute
    the task. A versioned semantic manifest is distinct from the legacy alias,
    so approvals can pin an operation independently of a tool's name.
    """

    def __init__(self, bridge: CatalogAdapterProvider, registry: CapabilityRegistry):
        self.bridge = bridge
        self.registry = registry
        self._operations: dict[str, tuple[CapabilityManifest, CapabilityManifest]] = {}
        for legacy in bridge.bindings():
            tool_id = bridge._tool_by_provider[legacy.provider_id]
            operation_id = SEMANTIC_OPERATION_IDS[tool_id]
            semantic = replace(
                legacy, capability_id=operation_id,
                limitations=(
                    *legacy.limitations,
                    "Semantic alias of the admitted catalog adapter; independent lab validation remains required.",
                ),
            )
            registry.register(semantic)
            self._operations[operation_id] = (semantic, legacy)

    def bindings(self) -> tuple[CapabilityManifest, ...]:
        return tuple(
            self._operations[key][0] for key in sorted(self._operations)
        )

    def _legacy_task(self, task: WorkflowTask) -> tuple[WorkflowTask, CapabilityManifest]:
        if not isinstance(task, WorkflowTask):
            raise TypeError("operation task must be a WorkflowTask")
        pair = self._operations.get(task.capability_id)
        if pair is None:
            raise CapabilityUnavailable(task.capability_id, ("unbound semantic operation",))
        semantic, legacy = pair
        return replace(task, capability_id=legacy.capability_id), semantic

    def resolve_task(self, task: WorkflowTask, *, require_installed: bool = False):
        original, expected = self._legacy_task(task)
        legacy_result = self.bridge.resolve_task(
            original, require_installed=require_installed,
        )
        registered = next((
            item for item in self.registry.list(task.capability_id)
            if item.provider_id == expected.provider_id
            and item.provider_version == expected.provider_version
        ), None)
        if registered is None or registered.fingerprint != expected.fingerprint:
            raise CapabilityUnavailable(
                task.capability_id, ("semantic provider manifest changed",),
            )
        if legacy_result.manifest.provider_id != expected.provider_id or (
            legacy_result.manifest.provider_version != expected.provider_version
        ):
            raise RuntimeError("semantic alias provider identity drift")
        return CapabilityResolution(
            manifest=expected, registry_digest=self.registry.digest,
            considered=len(self.registry.list(task.capability_id)),
            rejected=(),
        )

    async def dispatch(self, task: WorkflowTask) -> dict:
        resolved = self.resolve_task(task, require_installed=True)
        original, expected = self._legacy_task(task)
        result = await self.bridge.dispatch(original)
        legacy = self._operations[task.capability_id][1]
        if (
            result.get("provider_id") != legacy.provider_id
            or result.get("provider_version") != legacy.provider_version
            or result.get("manifest_fingerprint") != legacy.fingerprint
        ):
            raise RuntimeError("semantic adapter returned mismatched legacy identity")
        return {
            **result,
            "capability_id": expected.capability_id,
            "legacy_capability_id": legacy.capability_id,
            "manifest_fingerprint": expected.fingerprint,
            "registry_digest": resolved.registry_digest,
        }

    def inventory(self) -> list[dict]:
        legacy_rows = {
            item["capability_id"]: item for item in self.bridge.inventory()
        }
        rows = []
        for operation_id, (semantic, legacy) in sorted(self._operations.items()):
            original = legacy_rows[legacy.capability_id]
            rows.append({
                **original,
                "capability_id": operation_id,
                "provider_id": semantic.provider_id,
                "manifest_fingerprint": semantic.fingerprint,
                "legacy_capability_id": legacy.capability_id,
                "semantic_operation": True,
            })
        return rows


class FindingVerificationProvider:
    """Run bounded SQLi/XSS verification as scheduler-owned V2 tasks.

    Only a stored V2 finding of the exact supported kind can enter its matching
    verifier. Probes reuse the existing bounded validators; each outbound
    request rechecks current scope and the exact URL path. Results are written
    to a separate V2 evidence job so sealed scanner findings remain immutable.
    """

    VERIFY = "tool.verify_sqli"
    RETEST = "tool.retest_sqli"
    VERIFY_XSS = "tool.verify_xss"
    RETEST_XSS = "tool.retest_xss"
    PROVIDER_ID = "whaxon.verifier.http"
    PROVIDER_VERSION = "v2-sqli-xss-verifier.1"
    _KINDS = {
        VERIFY: frozenset({"sqli", "sql_injection"}),
        RETEST: frozenset({"sqli", "sql_injection"}),
        VERIFY_XSS: frozenset({"xss"}),
        RETEST_XSS: frozenset({"xss"}),
    }

    def __init__(self, *, store, registry, scope):
        self.store = store
        self.registry = registry
        self.scope = scope
        self._manifests = {}
        schema = {
            "type": "object",
            "properties": {
                "source_job_id": {"type": "string", "minLength": 12, "maxLength": 32},
                "finding_seq": {"type": "integer", "minimum": 0},
            },
            "required": ["source_job_id", "finding_seq"],
            "additionalProperties": False,
        }
        for capability_id, operation in (
            (self.VERIFY, "independent SQL injection verification"),
            (self.RETEST, "conservative SQL injection remediation retest"),
            (self.VERIFY_XSS, "independent reflected XSS verification"),
            (self.RETEST_XSS, "conservative reflected XSS remediation retest"),
        ):
            manifest = CapabilityManifest(
                capability_id=capability_id,
                provider_id=self.PROVIDER_ID,
                provider_version=self.PROVIDER_VERSION,
                transports=("in_process_http",),
                target_types=("url",),
                permissions=("network.verify",),
                side_effects=("bounded_http_probe", "target_service_logs"),
                impact="moderate",
                readiness="registered",
                timeout_s=75.0,
                input_schema=schema,
                output_schema={
                    "type": "object",
                    "required": ["job_id", "tool_id", "target", "exit_code", "status", "reason"],
                },
                limitations=(
                    f"Supports {operation} for sealed stored findings of its exact vulnerability kind only.",
                    "Uses bounded non-destructive probes with three baseline and three injected samples.",
                    "Accepts IP-literal targets only; hostname targets require a future pinned-address transport.",
                    "No payload supplied by the caller; redirects are blocked.",
                    "Retest may return still_vulnerable or inconclusive; it never infers fixed from missing proof.",
                ),
            )
            registry.register(manifest)
            self._manifests[capability_id] = manifest

    def bindings(self) -> tuple[CapabilityManifest, ...]:
        return tuple(self._manifests[key] for key in sorted(self._manifests))

    def resolve_task(self, task: WorkflowTask, *, require_installed: bool = False):
        import ipaddress
        from urllib.parse import urlsplit

        if not isinstance(task, WorkflowTask):
            raise TypeError("verification task must be a WorkflowTask")
        expected = self._manifests.get(task.capability_id)
        if expected is None:
            raise CapabilityUnavailable(task.capability_id, ("unsupported verification operation",))
        if _target_type(task.target) != "url":
            raise ValueError("verification requires an absolute HTTP(S) URL")
        try:
            target_url = urlsplit(task.target)
            if target_url.scheme.lower() not in {"http", "https"}:
                raise ValueError
            if target_url.username is not None or target_url.password is not None:
                raise ValueError
            if not target_url.hostname or "%" in target_url.hostname:
                raise ValueError
            ipaddress.ip_address(target_url.hostname)
            _ = target_url.port
        except (ValueError, TypeError):
            raise ValueError(
                "verification requires an HTTP(S) URL with an IP literal; "
                "hostname targets are disabled to prevent DNS rebinding"
            ) from None
        if (
            not isinstance(task.inputs, dict)
            or set(task.inputs) != {"source_job_id", "finding_seq"}
            or not isinstance(task.inputs.get("source_job_id"), str)
            or not re.fullmatch(r"[A-Fa-f0-9-]{12,36}", task.inputs["source_job_id"])
            or type(task.inputs.get("finding_seq")) is not int
            or task.inputs["finding_seq"] < 0
        ):
            raise ValueError("verification inputs must pin a stored job and finding sequence")
        current = next((item for item in self.registry.list(task.capability_id)
                        if item.provider_id == expected.provider_id
                        and item.provider_version == expected.provider_version), None)
        if current is None or current.fingerprint != expected.fingerprint:
            raise CapabilityUnavailable(task.capability_id, ("verification manifest binding changed",))
        self._source_finding(task)
        return self.registry.resolve(
            task.capability_id,
            CapabilityRequirements(
                transport="in_process_http",
                target_type="url",
                required_permissions=tuple(task.permissions),
                maximum_impact=task.impact,
                allowed_providers=(expected.provider_id,),
                allowed_versions=(expected.provider_version,),
                allowed_fingerprints=(expected.fingerprint,),
                allowed_side_effects=expected.side_effects,
            ),
        )

    def _source_finding(self, task: WorkflowTask):
        source_job_id = task.inputs["source_job_id"]
        source_seq = task.inputs["finding_seq"]
        source_job = self.store.get(source_job_id)
        source_findings = self.store.get_findings(source_job_id)
        if (
            source_job is None or source_job.get("status") != "finished"
            or source_job.get("exit_code") != 0 or source_job.get("target") != task.target
            or not self.store.is_engine_v2_execution_job(source_job_id)
            or not self.store.has_valid_workflow_evidence_seal(source_job_id)
            or source_findings is None
        ):
            raise ValueError("verification source must be a successful, same-target V2 job")
        selected = next((item for item in source_findings if item.get("seq") == source_seq), None)
        if selected is None or selected.get("kind") not in self._KINDS[task.capability_id]:
            raise ValueError("verification source kind does not match the selected verifier")
        verify_capability = {
            self.RETEST: self.VERIFY,
            self.RETEST_XSS: self.VERIFY_XSS,
        }.get(task.capability_id)
        if verify_capability and (
            source_job.get("tool") != verify_capability.removeprefix("tool.")
            or selected.get("verification_status") != "verified"
            or selected.get("verified_by") != "engine-v2"
        ):
            raise ValueError("retest requires a prior V2 verified finding")
        return source_job, selected

    async def dispatch(self, task: WorkflowTask) -> dict:
        import time
        from urllib.parse import urlsplit

        resolution = self.resolve_task(task, require_installed=True)
        expected = resolution.manifest
        if task.impact != expected.impact or set(task.permissions) != set(expected.permissions):
            raise CapabilityUnavailable(task.capability_id, ("task permission/impact differs from verifier contract",))
        source_job_id = task.inputs["source_job_id"]
        source_seq = task.inputs["finding_seq"]
        _, selected = self._source_finding(task)

        target_parts = urlsplit(task.target)
        target_host = target_parts.hostname
        if target_host is None:
            raise ValueError("verification requires an absolute HTTP(S) target")
        origin = (target_parts.scheme.lower(), target_host.lower(), target_parts.port, target_parts.path)

        def authorize_probe(url: str) -> bool:
            try:
                parsed = urlsplit(url)
                request_host = parsed.hostname
                if request_host is None:
                    return False
                request_origin = (parsed.scheme.lower(), request_host.lower(), parsed.port, parsed.path)
                if (
                    request_origin != origin or parsed.username is not None
                    or parsed.password is not None or parsed.fragment
                ):
                    return False
                self.scope.load()
                return self.scope.check_for_execution(url).allowed is True
            except (AttributeError, TypeError, ValueError, RuntimeError):
                return False

        from .findings import Finding
        from .validator import Validator

        finding = Finding(
            kind=selected["kind"], severity=selected["severity"],
            source=selected["source"], data=selected["data"],
            raw_line=selected["raw_line"], remediation=selected.get("remediation", ""),
            impact=selected.get("impact", ""), cvss=selected.get("cvss"),
            cwe=selected.get("cwe", ""), references=tuple(selected.get("references") or ()),
            lookup_hint=selected.get("lookup_hint", ""),
            request_context=selected.get("request_context") or {},
        )
        validator = Validator(
            Path(__file__).resolve().parents[1] / "data" / "payloads",
            authorize_request=authorize_probe,
        )
        started = time.monotonic()
        if task.capability_id in {self.VERIFY, self.VERIFY_XSS}:
            status, reason = validator.validate(finding, target_url=task.target)
        else:
            status, reason = validator.revalidate(finding, target_url=task.target)
        reason = str(reason)[:2000]
        evidence_job_id = uuid.uuid4().hex[:12]
        if self.store.get(evidence_job_id) is not None:
            raise RuntimeError("verification evidence id collision")
        self.store.create(evidence_job_id)
        if not self.store.set_started(
            evidence_job_id, task.capability_id.removeprefix("tool."), task.target,
        ):
            raise RuntimeError("could not start verification evidence job")
        self.store.mark_engine_v2_execution_job(evidence_job_id)
        evidence = Finding(
            kind=finding.kind,
            severity=finding.severity,
            source="engine-v2-verifier",
            data={
                "source_job_id": source_job_id,
                "source_finding_seq": source_seq,
                "operation": task.capability_id,
                "status": status,
                "reason": reason,
            },
            raw_line=f"{task.capability_id}: {status}: {reason}",
            request_context={"method": "GET", "url": task.target,
                             "parameter": finding.data.get("parameter", "")},
        )
        self.store.append_line(evidence_job_id, "stdout", evidence.raw_line)
        self.store.append_finding(evidence_job_id, evidence, 0)
        self.store.update_verification(
            evidence_job_id, 0, status, by="engine-v2", reason=reason,
        )
        if not self.store.set_finished(evidence_job_id, 0, time.monotonic() - started):
            raise RuntimeError("could not finish verification evidence job")
        return {
            "job_id": evidence_job_id,
            "tool_id": task.capability_id.removeprefix("tool."),
            "target": task.target,
            "exit_code": 0,
            "status": status,
            "reason": reason,
            "provider_id": expected.provider_id,
            "provider_version": expected.provider_version,
            "manifest_fingerprint": expected.fingerprint,
            "registry_digest": resolution.registry_digest,
            "transport": "in_process_http",
        }

    def inventory(self) -> list[dict]:
        return [
            {
                "capability_id": manifest.capability_id,
                "provider_id": manifest.provider_id,
                "provider_version": manifest.provider_version,
                "manifest_fingerprint": manifest.fingerprint,
                "transport": "in_process_http",
                "target_types": list(manifest.target_types),
                "registry_digest": self.registry.digest,
                "registered": True,
                "installed": True,
                "executable": True,
                "readiness": "registered",
                "reason": "bounded_verifier_requires_scope_and_exact_approval",
                "authorization_required": True,
                "smoke_tested": False,
                "lab_validated": False,
                "end_to_end_verified": False,
            }
            for manifest in self.bindings()
        ]


class ProviderContract(Protocol):
    """Trusted in-process provider interface; manifests alone cannot execute."""

    def bindings(self) -> tuple[CapabilityManifest, ...]: ...

    def resolve_task(
        self, task: WorkflowTask, *, require_installed: bool = False,
    ) -> Any: ...

    async def dispatch(self, task: WorkflowTask) -> dict: ...

    def inventory(self) -> list[dict]: ...


class BoundProviderRouter:
    """Capability-to-provider routing without coupling the scheduler to tools.

    Only explicitly constructed, trusted provider adapters may register.
    Persisted manifests alone never create dispatchable providers. A capability
    must have exactly one bound execution implementation; ambiguity fails closed.
    """

    def __init__(self, providers=(), *, preferred_providers=None):
        # Multiple providers for an operation require an explicit, trusted
        # deployment choice. Never silently switch the implementation after
        # authorization simply because a new provider was registered.
        self._preferred: dict[str, str] = dict(preferred_providers or {})
        if not all(
            isinstance(capability, str) and capability
            and isinstance(provider_id, str) and provider_id
            for capability, provider_id in self._preferred.items()
        ):
            raise ValueError("preferred provider map requires non-empty identities")
        self._routes: dict[str, ProviderContract] = {}
        self._providers: list[ProviderContract] = []
        self._bindings: dict[str, CapabilityManifest] = {}
        self._alternatives: dict[str, set[str]] = {}
        self._contracts: dict[str, CapabilityManifest] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: ProviderContract) -> None:
        if not all(callable(getattr(provider, name, None)) for name in (
            "bindings", "resolve_task", "dispatch", "inventory",
        )):
            raise TypeError("provider must implement the bound provider contract")
        manifests = tuple(provider.bindings())
        # A catalog may contain zero admitted capabilities; still expose its
        # unsupported entries through the inventory without enabling them.
        seen: set[str] = set()
        for manifest in manifests:
            if not isinstance(manifest, CapabilityManifest):
                raise TypeError("provider binding must be a CapabilityManifest")
            capability = manifest.capability_id
            if capability in seen:
                raise ValueError(f"ambiguous bound capability: {capability}")
            existing = self._contracts.get(capability)
            if existing is not None:
                if (
                    capability not in self._preferred
                    or existing.provider_id == manifest.provider_id
                ):
                    raise ValueError(f"ambiguous bound capability: {capability}")
                # Same identity string is not proof of equivalent semantics.
                # Enforce the operation's typed/effect contract at admission,
                # while allowing providers to differ in transport/readiness.
                contract_fields = (
                    "input_schema", "output_schema", "permissions",
                    "side_effects", "impact", "target_types",
                    "protocols", "auth_methods",
                )
                if any(
                    getattr(existing, field) != getattr(manifest, field)
                    for field in contract_fields
                ):
                    raise ValueError(
                        f"incompatible providers for capability: {capability}"
                    )
            seen.add(capability)
        for manifest in manifests:
            capability = manifest.capability_id
            self._contracts.setdefault(capability, manifest)
            self._alternatives.setdefault(capability, set()).add(manifest.provider_id)
            selected = self._preferred.get(capability)
            if selected is None or selected == manifest.provider_id:
                self._routes[capability] = provider
                self._bindings[capability] = manifest
        self._providers.append(provider)

    def manifest_for(self, capability_id: str) -> CapabilityManifest:
        """Select only the explicitly trusted and bound provider manifest."""
        manifest = self._bindings.get(capability_id)
        selected = self._preferred.get(capability_id)
        if manifest is None:
            reason = (
                "preferred execution provider is not registered"
                if selected else "no trusted execution provider"
            )
            raise CapabilityUnavailable(capability_id, (reason,))
        if selected and manifest.provider_id != selected:
            raise CapabilityUnavailable(
                capability_id, ("preferred execution provider is not registered",),
            )
        return manifest

    def plan_binding_valid(self, task: WorkflowTask, metadata: dict) -> bool:
        """Require immutable-plan provider pinning for interchangeable adapters.

        Adding a second implementation later must not change an already
        approved plan's execution identity.
        """
        options = self._alternatives.get(task.capability_id, set())
        if not isinstance(metadata, dict):
            return False
        # Only an absent field means an old plan. An explicit null or
        # malformed binding is not a legitimate legacy-compatibility signal.
        has_bindings = "provider_bindings" in metadata
        bindings = metadata.get("provider_bindings")
        # Historical plans may lack provider pins while a capability has one
        # trusted implementation. New explicitly pinned plans must always
        # retain their exact approved provider identity, even if registration
        # changes leave only one implementation installed.
        if not has_bindings:
            # Newly introduced operation-level identities always need a
            # pinned provider, even when today's registry has one candidate.
            return len(options) == 1 and task.capability_id.startswith("tool.")
        if not isinstance(bindings, dict):
            return False
        expected = bindings.get(task.id)
        if not isinstance(expected, dict):
            return False
        try:
            manifest = self.manifest_for(task.capability_id)
        except CapabilityUnavailable:
            return False
        return (
            expected.get("provider_id") == manifest.provider_id
            and expected.get("manifest_fingerprint") == manifest.fingerprint
        )

    def resolve_task(self, task: WorkflowTask, *, require_installed: bool = False):
        if not isinstance(task, WorkflowTask):
            raise TypeError("provider task must be a WorkflowTask")
        manifest = self.manifest_for(task.capability_id)
        provider = self._routes[task.capability_id]
        resolution = provider.resolve_task(task, require_installed=require_installed)
        if resolution.manifest.fingerprint != manifest.fingerprint:
            raise RuntimeError("selected provider binding changed")
        return resolution

    async def dispatch(self, task: WorkflowTask) -> dict:
        # Resolver rechecks the actual provider readiness and manifest binding.
        resolution = self.resolve_task(task, require_installed=True)
        provider = self._routes[task.capability_id]
        result = await provider.dispatch(task)
        if not isinstance(result, dict):
            raise RuntimeError("provider dispatch must return a typed result object")
        if result.get("provider_id") != resolution.manifest.provider_id or (
            result.get("provider_version") != resolution.manifest.provider_version
            or result.get("manifest_fingerprint") != resolution.manifest.fingerprint
        ):
            raise RuntimeError("provider result identity does not match resolved manifest")
        return result

    def operation_reconciliation(self) -> list[dict]:
        """Inventory trusted capability bindings, including unselected options.

        This is not an admission or execution operation. It distinguishes the
        selected in-process provider from other compatible but unselected
        bindings. A persisted manifest alone is never an execution option.
        """
        rows: list[dict] = []
        for capability_id in sorted(self._alternatives):
            selected = self._bindings.get(capability_id)
            preferred = self._preferred.get(capability_id)
            for provider_id in sorted(self._alternatives[capability_id]):
                is_selected = (
                    selected is not None
                    and selected.provider_id == provider_id
                    and (preferred is None or preferred == provider_id)
                )
                rows.append({
                    "capability_id": capability_id,
                    "provider_id": provider_id,
                    "selected": is_selected,
                    "selection_status": (
                        "selected" if is_selected else "unselected"
                    ),
                    "selection_explicit": preferred is not None,
                    "manifest_fingerprint": (
                        selected.fingerprint if is_selected and selected is not None else None
                    ),
                    "authorization_required": True,
                    "smoke_tested": False,
                    "lab_validated": False,
                    "end_to_end_verified": False,
                })
            if preferred and preferred not in self._alternatives[capability_id]:
                rows.append({
                    "capability_id": capability_id,
                    "provider_id": preferred,
                    "selected": False,
                    "selection_status": "preferred_provider_missing",
                    "selection_explicit": True,
                    "manifest_fingerprint": None,
                    "authorization_required": True,
                    "smoke_tested": False,
                    "lab_validated": False,
                    "end_to_end_verified": False,
                })
        for capability_id, provider_id in sorted(self._preferred.items()):
            if capability_id not in self._alternatives:
                rows.append({
                    "capability_id": capability_id,
                    "provider_id": provider_id,
                    "selected": False,
                    "selection_status": "preferred_provider_missing",
                    "selection_explicit": True,
                    "manifest_fingerprint": None,
                    "authorization_required": True,
                    "smoke_tested": False,
                    "lab_validated": False,
                    "end_to_end_verified": False,
                })
        return rows

    def portfolio_audit(self) -> dict:
        """Aggregate read-only provider inventories without enabling adapters."""
        audits = []
        for provider in self._providers:
            optional_audit = getattr(provider, "portfolio_audit", None)
            if callable(optional_audit):
                audits.append(optional_audit())
        if len(audits) == 1:
            return {
                **audits[0],
                "operation_bindings": self.operation_reconciliation(),
            }
        return {
            "schema_version": "whaxon.portfolio-audit.v1",
            "provider_audits": audits,
            **({"operation_bindings": self.operation_reconciliation()} if audits else {}),
            "execution_enabled_by_audit": False,
        }

    def inventory(self) -> list[dict]:
        """Report deployable routing, not just independently installed providers.

        Multiple trusted providers can individually be installed while only one
        is eligible to execute a capability. Surface that distinction for the
        Core/API/CLI clients, without modifying provider-owned readiness data.
        """
        rows: list[dict] = []
        for provider in self._providers:
            rows.extend(provider.inventory())
            portfolio = getattr(provider, "portfolio_inventory", None)
            if callable(portfolio):
                rows.extend(portfolio())
        result: list[dict] = []
        for item in rows:
            row = dict(item)
            bound = self._bindings.get(row["capability_id"])
            selected = (
                bound is not None
                and row.get("provider_id") == bound.provider_id
            )
            row["selected_for_execution"] = selected
            if not selected and row.get("executable") is True:
                row["executable"] = False
                row["reason"] = "provider_not_selected_for_execution"
            result.append(row)
        return sorted(result, key=lambda item: (
            item["capability_id"], item.get("provider_id") or "",
        ))
