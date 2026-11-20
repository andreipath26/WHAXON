"""Bounded V2 DNS posture provider for fixed CAA, DMARC and SPF observations."""
from __future__ import annotations

import asyncio
import time
import uuid
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

from .capabilities import (
    CapabilityManifest,
    CapabilityRegistry,
    CapabilityRequirements,
    CapabilityResolution,
    CapabilityUnavailable,
)
from .findings import Finding
from .recon_v2 import (
    MAX_FINDINGS,
    MAX_TEXT,
    TRANSPORT,
    _BoundedDnsWorker,
    _send_child_result,
    _valid_hostname,
)
from .scope import ScopeManager
from .workflow import WorkflowTask

CAPABILITY_ID = "dns.recon.full"
PROVIDER_ID = "whaxon.recon.dns_full"
PROVIDER_VERSION = "1.0.1"
PROCESS_TIMEOUT_S = 40.0
_FINDING_KEYS = {
    "kind", "severity", "source", "data", "raw_line", "remediation",
    "impact", "cvss", "cwe", "references", "lookup_hint", "request_context",
}
_KINDS = {
    "dns_caa", "dns_caa_missing", "dns_dmarc", "dns_dmarc_permissive",
    "dns_dmarc_missing", "dns_spf", "dns_spf_missing",
}

_MANIFEST = CapabilityManifest(
    capability_id=CAPABILITY_ID,
    provider_id=PROVIDER_ID,
    provider_version=PROVIDER_VERSION,
    transports=(TRANSPORT,),
    scope_mode="dns_query",
    target_types=("hostname",),
    permissions=("network.scan",),
    side_effects=("dns_queries", "resolver_logs"),
    impact="moderate",
    readiness="registered",
    timeout_s=PROCESS_TIMEOUT_S,
    input_schema={
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    },
    output_schema={
        "type": "object",
        "properties": {
            "job_id": {"type": "string", "minLength": 1},
            "tool_id": {"const": CAPABILITY_ID},
            "target": {"type": "string", "minLength": 1},
            "exit_code": {"type": "integer"},
            "duration_s": {"type": "number", "minimum": 0},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"enum": sorted(_KINDS)},
                        "severity": {"enum": ["info", "low", "medium"]},
                        "source": {"const": "recon:dns_full"},
                        "data": {"type": "object"},
                        "raw_line": {"type": "string", "maxLength": MAX_TEXT},
                        "remediation": {"type": "string", "maxLength": MAX_TEXT},
                        "impact": {"type": "string", "maxLength": MAX_TEXT},
                        "cvss": {"type": ["number", "null"], "minimum": 0, "maximum": 10},
                        "cwe": {"type": "string", "maxLength": MAX_TEXT},
                        "references": {
                            "type": "array",
                            "items": {"type": "string", "maxLength": MAX_TEXT},
                        },
                        "lookup_hint": {"type": "string", "maxLength": MAX_TEXT},
                        "request_context": {"type": "object"},
                    },
                    "required": [
                        "kind", "severity", "source", "data", "raw_line",
                        "remediation", "impact", "cvss", "cwe", "references",
                        "lookup_hint", "request_context",
                    ],
                    "additionalProperties": False,
                },
            },
            "provider_id": {"const": PROVIDER_ID},
            "provider_version": {"const": PROVIDER_VERSION},
            "manifest_fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "registry_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "transport": {"const": TRANSPORT},
        },
        "required": [
            "job_id", "tool_id", "target", "exit_code", "duration_s",
            "findings", "provider_id", "provider_version",
            "manifest_fingerprint", "registry_digest", "transport",
        ],
        "additionalProperties": False,
    },
    limitations=(
        "Only fixed CAA(host), TXT(_dmarc.host), and TXT(host) queries are made.",
        "Host and _dmarc subdomain need DNS-query scope; exact host scope grants no subdomain access.",
        "Resolver work is terminated when the bounded child-process deadline expires.",
        "Child IPC output is capped at 1 MiB; larger result batches fail closed.",
        "DNS posture observations are not proof of domain ownership or email authenticity.",
    ),
)


def _dns_full_worker(conn: Connection, target: str, scope_path: str) -> None:
    """Check fresh scope for every fixed lookup name before querying DNS."""
    try:
        host = target.lower().rstrip(".")
        if not _valid_hostname(target) or target != host or len(host) + 7 > 253:
            _send_child_result(
                conn, {"status": "error", "error": "invalid normalized DNS posture target"},
            )
            return
        scope = ScopeManager(Path(scope_path))
        for query_name in (host, f"_dmarc.{host}"):
            match = scope.check_for_dns_query(query_name)
            if not match.allowed:
                _send_child_result(conn, {
                    "status": "scope_denied",
                    "reason": f"{query_name}: {match.reason or 'scope denied'!s}"[:MAX_TEXT],
                })
                return
        from .recon_checks import check_dns_full

        findings = check_dns_full(host)
        if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
            _send_child_result(
                conn, {"status": "error", "error": "invalid DNS posture finding collection"},
            )
            return
        _send_child_result(conn, {
            "status": "complete",
            "findings": [
                item.to_dict() if isinstance(item, Finding) else item for item in findings
            ],
        })
    except BaseException as exc:
        try:
            _send_child_result(conn, {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}"[:MAX_TEXT],
            })
        except Exception:
            pass
    finally:
        conn.close()


def _decode_findings(value: object, target: str) -> list[Finding]:
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise RuntimeError("DNS posture child returned an invalid finding list")
    decoded = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _FINDING_KEYS:
            raise RuntimeError("DNS posture child returned a malformed finding")
        if (
            item.get("kind") not in _KINDS
            or item.get("source") != "recon:dns_full"
            or item.get("severity") not in {"info", "low", "medium"}
            or not isinstance(item.get("data"), dict)
            or not isinstance(item.get("raw_line"), str)
            or len(item["raw_line"]) > MAX_TEXT
            or not isinstance(item.get("remediation"), str)
            or len(item["remediation"]) > MAX_TEXT
            or not isinstance(item.get("impact"), str)
            or len(item["impact"]) > MAX_TEXT
            or not isinstance(item.get("cwe"), str)
            or len(item["cwe"]) > MAX_TEXT
            or not isinstance(item.get("references"), list)
            or any(not isinstance(ref, str) or len(ref) > MAX_TEXT for ref in item["references"])
            or item.get("lookup_hint") != ""
            or item.get("request_context") != {}
        ):
            raise RuntimeError("DNS posture child returned an invalid finding contract")
        cvss = item.get("cvss")
        if cvss is not None and (
            isinstance(cvss, bool) or not isinstance(cvss, (int, float)) or not 0 <= cvss <= 10
        ):
            raise RuntimeError("DNS posture child returned invalid CVSS")
        data = item["data"]
        kind = item["kind"]
        if data.get("host") != target:
            raise RuntimeError("DNS posture child returned a mismatched finding host")
        if kind == "dns_caa":
            valid = set(data) == {"host", "value"} and isinstance(data.get("value"), str)
            valid = valid and item["raw_line"] == f"{target} CAA {data['value']}"
        elif kind == "dns_caa_missing":
            valid = set(data) == {"host"} and item["raw_line"] == f"{target}: no CAA record"
        elif kind in {"dns_dmarc", "dns_dmarc_permissive"}:
            expected_line = (
                f"_dmarc.{target}: DMARC p=none ({data.get('record')})"
                if kind == "dns_dmarc_permissive"
                else f"_dmarc.{target}: DMARC p={data.get('policy')}"
            )
            valid = (
                set(data) == {"host", "record", "policy"}
                and isinstance(data.get("record"), str)
                and len(data["record"]) <= MAX_TEXT
                and isinstance(data.get("policy"), str)
                and len(data["policy"]) <= MAX_TEXT
                and item["raw_line"] == expected_line
            )
        elif kind == "dns_dmarc_missing":
            valid = (
                set(data) == {"host"}
                and item["raw_line"] == f"_dmarc.{target}: no DMARC record"
            )
        elif kind == "dns_spf":
            valid = (
                set(data) == {"host", "record"}
                and isinstance(data.get("record"), str)
                and len(data["record"]) <= MAX_TEXT
            )
            valid = valid and item["raw_line"] == f"{target} SPF {data['record']}"
        else:
            valid = set(data) == {"host"} and item["raw_line"] == f"{target}: no SPF record"
        if not valid:
            raise RuntimeError("DNS posture child returned an invalid fixed-query observation")
        expected_severity = {
            "dns_caa": "info",
            "dns_caa_missing": "info",
            "dns_dmarc_permissive": "medium",
            "dns_dmarc_missing": "medium",
        }.get(kind)
        if expected_severity is not None and item["severity"] != expected_severity:
            raise RuntimeError("DNS posture child returned an invalid finding severity")
        if kind == "dns_dmarc_permissive" and data["policy"].lower() != "none":
            raise RuntimeError("DNS posture child returned an invalid DMARC policy")
        if kind == "dns_dmarc" and data["policy"].lower() == "none":
            raise RuntimeError("DNS posture child returned an invalid DMARC policy")
        decoded.append(Finding(
            kind=kind, severity=item["severity"], source=item["source"],
            data=data, raw_line=item["raw_line"], remediation=item["remediation"],
            impact=item["impact"], cvss=cvss, cwe=item["cwe"],
            references=tuple(item["references"]), lookup_hint="", request_context={},
        ))
    return decoded


class DnsFullPostureProvider:
    """V2 provider for the fixed CAA, DMARC, and SPF query contract."""

    def __init__(self, *, store, registry: CapabilityRegistry, scope: ScopeManager) -> None:
        self.store = store
        self.registry = registry
        self.scope = scope
        self._manifest = _MANIFEST
        self.registry.register(self._manifest)

    def bindings(self) -> tuple[CapabilityManifest, ...]:
        return (self._manifest,)

    def _readiness(self) -> bool:
        try:
            from importlib.util import find_spec
            return find_spec("dns.resolver") is not None
        except (ImportError, ModuleNotFoundError, ValueError):
            return False

    def resolve_task(
        self, task: WorkflowTask, *, require_installed: bool = False,
    ) -> CapabilityResolution:
        if not isinstance(task, WorkflowTask) or task.capability_id != CAPABILITY_ID:
            raise CapabilityUnavailable(CAPABILITY_ID, ("task capability does not match provider",))
        target = task.target.lower().rstrip(".") if isinstance(task.target, str) else ""
        if (
            not _valid_hostname(task.target) or task.target != target
            or len(target) + 7 > 253
        ):
            raise CapabilityUnavailable(
                CAPABILITY_ID, ("target must be a normalized DNS hostname",),
            )
        if not isinstance(task.inputs, dict) or task.inputs:
            raise CapabilityUnavailable(CAPABILITY_ID, ("DNS posture task inputs must be empty",))
        if (
            task.impact != self._manifest.impact
            or set(task.permissions) != set(self._manifest.permissions)
        ):
            raise CapabilityUnavailable(
                CAPABILITY_ID, ("task permissions/impact differ from manifest",),
            )
        resolution = self.registry.resolve(
            CAPABILITY_ID,
            CapabilityRequirements(
                target_type="hostname", transport=TRANSPORT,
                required_permissions=self._manifest.permissions,
                maximum_impact=self._manifest.impact,
                required_input_schema=self._manifest.input_schema,
                allowed_providers=(PROVIDER_ID,), allowed_versions=(PROVIDER_VERSION,),
                allowed_fingerprints=(self._manifest.fingerprint,),
                allowed_side_effects=self._manifest.side_effects,
            ),
        )
        if resolution.manifest.fingerprint != self._manifest.fingerprint:
            raise CapabilityUnavailable(CAPABILITY_ID, ("provider manifest fingerprint changed",))
        if require_installed and not self._readiness():
            raise CapabilityUnavailable(CAPABILITY_ID, ("dnspython is not installed",))
        return resolution

    async def dispatch(self, task: WorkflowTask) -> dict[str, Any]:
        resolution = self.resolve_task(task, require_installed=True)
        job_id = uuid.uuid4().hex[:12]
        if self.store.get(job_id) is not None:
            raise RuntimeError("DNS posture evidence job id collision")
        self.store.create(job_id)
        if not self.store.set_started(job_id, CAPABILITY_ID, task.target):
            raise RuntimeError("could not start DNS posture evidence job")
        self.store.mark_engine_v2_execution_job(job_id)
        started = time.monotonic()
        child = _BoundedDnsWorker(
            task.target, str(self.scope.path.resolve()),
            min(float(task.timeout_s), self._manifest.timeout_s),
            worker_target=_dns_full_worker,
        )
        try:
            try:
                payload = await asyncio.to_thread(child.run)
            except asyncio.CancelledError:
                child.request_termination()
                raise
            if payload.get("status") == "scope_denied":
                raise PermissionError("current scope denied a DNS posture query")
            if payload.get("status") != "complete" or set(payload) != {"status", "findings"}:
                raise RuntimeError(
                    str(payload.get("error", "invalid DNS posture child status"))[:MAX_TEXT],
                )
            findings = _decode_findings(payload["findings"], task.target)
            for seq, finding in enumerate(findings):
                if finding.raw_line:
                    self.store.append_line(job_id, "stdout", finding.raw_line)
                self.store.append_finding(job_id, finding, seq)
            persisted = self.store.get_findings(job_id)
            if not isinstance(persisted, list) or len(persisted) != len(findings):
                raise RuntimeError("DNS posture evidence findings did not persist completely")
            duration_s = time.monotonic() - started
            if not self.store.set_finished(job_id, 0, duration_s):
                raise RuntimeError("could not finish DNS posture evidence job")
        except asyncio.CancelledError:
            child.request_termination()
            await asyncio.to_thread(
                self._persist_failure, job_id,
                "CancelledError: child termination requested; external DNS outcome not confirmed",
            )
            raise
        except Exception as exc:
            await asyncio.to_thread(
                self._persist_failure, job_id,
                f"{type(exc).__name__}: {exc}"[:MAX_TEXT],
            )
            raise
        return {
            "job_id": job_id, "tool_id": CAPABILITY_ID, "target": task.target,
            "exit_code": 0, "duration_s": duration_s, "findings": persisted,
            "provider_id": resolution.manifest.provider_id,
            "provider_version": resolution.manifest.provider_version,
            "manifest_fingerprint": resolution.manifest.fingerprint,
            "registry_digest": resolution.registry_digest, "transport": TRANSPORT,
        }

    def _persist_failure(self, job_id: str, message: str) -> None:
        try:
            self.store.append_line(job_id, "stderr", message[:MAX_TEXT])
            self.store.set_failed(job_id, message[:MAX_TEXT])
        except Exception:
            pass

    def inventory(self) -> list[dict[str, Any]]:
        installed = self._readiness()
        return [{
            "capability_id": CAPABILITY_ID, "provider_id": PROVIDER_ID,
            "provider_version": PROVIDER_VERSION,
            "manifest_fingerprint": self._manifest.fingerprint,
            "transport": TRANSPORT, "target_types": ["hostname"],
            "registry_digest": self.registry.digest, "registered": True,
            "selected_for_execution": True, "installed": installed,
            "executable": installed, "readiness": "installed" if installed else "registered",
        }]
