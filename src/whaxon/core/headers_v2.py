"""Bounded Engine V2 provider for passive HTTP security-header observations.

The provider makes one pinned HTTPS GET to ``/``. It does not follow redirects,
fall back to HTTP, or read the response body. Network work runs in a bounded,
killable child process that rechecks target scope before connecting.
"""
from __future__ import annotations

import asyncio
import ipaddress
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
from .http_recon_v2 import (
    CONNECT_TIMEOUT_S,
    MAX_CHILD_OUTPUT_BYTES,
    MAX_RESPONSE_HEADER_BYTES,
    MAX_RESPONSE_HEADERS,
    MAX_TEXT,
    PROCESS_TIMEOUT_S,
    TRANSPORT,
    _BoundedHttpsWorker,
    _checked_headers,
    _PinnedHTTPSConnection,
    _safe_text,
    _send_child_result,
    _valid_target,
)
from .recon_checks import _MISSING_HEADER_KNOWLEDGE
from .scope import ScopeManager
from .workflow import WorkflowTask

CAPABILITY_ID = "web.recon.headers"
PROVIDER_ID = "whaxon.recon.headers"
PROVIDER_VERSION = "1.0.0"
MAX_FINDINGS = len(_MISSING_HEADER_KNOWLEDGE) + 1
_ALLOWED_KINDS = {"http_header_missing", "recon_error"}
_FINDING_KEYS = {
    "kind", "severity", "source", "data", "raw_line", "remediation",
    "impact", "cvss", "cwe", "references", "lookup_hint", "request_context",
}

_MANIFEST = CapabilityManifest(
    capability_id=CAPABILITY_ID,
    provider_id=PROVIDER_ID,
    provider_version=PROVIDER_VERSION,
    transports=(TRANSPORT,),
    protocols=("https",),
    scope_mode="pinned_network",
    target_types=("hostname", "ip"),
    permissions=("network.scan",),
    side_effects=("https_requests", "network_traffic", "target_service_logs"),
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
                "maxItems": MAX_FINDINGS,
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"enum": sorted(_ALLOWED_KINDS)},
                        "severity": {"enum": ["info", "low", "medium"]},
                        "source": {"const": "recon:headers"},
                        "data": {
                            "type": "object",
                            "oneOf": [
                                {
                                    "type": "object",
                                    "properties": {
                                        "header": {"enum": sorted(_MISSING_HEADER_KNOWLEDGE)},
                                        "url": {"type": "string", "maxLength": MAX_TEXT},
                                    },
                                    "required": ["header", "url"],
                                    "additionalProperties": False,
                                },
                                {
                                    "type": "object",
                                    "properties": {
                                        "target": {"type": "string", "maxLength": 253},
                                        "error": {"type": "string", "maxLength": MAX_TEXT},
                                    },
                                    "required": ["target", "error"],
                                    "additionalProperties": False,
                                },
                            ],
                        },
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
                    "required": sorted(_FINDING_KEYS),
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
        "Exactly one GET / over HTTPS port 443; no redirect following or HTTP fallback.",
        "The child resolves once, checks every answer against scope, and connects only to vetted numeric addresses.",
        "TLS certificate verification uses the standard trust store; response bodies are not read.",
        f"Response headers are capped at {MAX_RESPONSE_HEADERS} fields and {MAX_RESPONSE_HEADER_BYTES} bytes; child IPC output is capped at {MAX_CHILD_OUTPUT_BYTES} bytes.",
        "Only the root response is observed; missing headers do not establish exploitability.",
    ),
)


def _response_url(host: str) -> str:
    authority = f"[{host}]" if ":" in host else host
    return f"https://{authority}/"


def _collect_findings(target: str, host: str, headers: list[tuple[str, str]]) -> list[Finding]:
    url = _response_url(host)
    normalized = {name.lower(): value for name, value in headers}
    findings: list[Finding] = []
    for header, info in _MISSING_HEADER_KNOWLEDGE.items():
        if header in normalized:
            continue
        findings.append(Finding(
            kind="http_header_missing",
            severity=info["severity"],
            source="recon:headers",
            data={"header": header, "url": url},
            raw_line=_safe_text(f"{url}: missing {header}"),
            remediation=_safe_text(info["remediation"]),
            impact=_safe_text(info["impact"]),
            cwe=_safe_text(info["cwe"]),
            cvss=info["cvss"],
        ))
    if len(findings) > MAX_FINDINGS:
        raise ValueError("header recon produced too many findings")
    return findings


def _error_finding(target: str, message: str) -> Finding:
    safe_message = _safe_text(message)
    return Finding(
        kind="recon_error",
        severity="info",
        source="recon:headers",
        data={"target": target, "error": safe_message},
        raw_line=_safe_text(f"headers GET {target} failed: {message}"),
    )


def _headers_worker(conn: Connection, target: str, scope_path: str) -> None:
    """Resolve and scope in the child, then inspect one fixed HTTPS response."""
    try:
        if not _valid_target(target):
            _send_child_result(conn, {"status": "error", "error": "invalid headers target"})
            return
        scope = ScopeManager(Path(scope_path))
        resolution = scope.resolve_for_execution(target, port=443)
        if not resolution.allowed or not resolution.addresses:
            _send_child_result(conn, {
                "status": "scope_denied",
                "reason": _safe_text(resolution.reason or "scope denied"),
            })
            return
        host = target.strip("[]").rstrip(".")
        connection = _PinnedHTTPSConnection(
            host, resolution.addresses, timeout=CONNECT_TIMEOUT_S,
        )
        response = None
        try:
            host_header = f"[{host}]" if ":" in host else host
            connection.request("GET", "/", headers={
                "Host": host_header,
                "User-Agent": "WHAXON-recon/2.0",
                "Connection": "close",
            })
            response = connection.getresponse()
            headers = _checked_headers(response.getheaders())
            findings = _collect_findings(target, host, headers)
            if not 200 <= int(response.status) < 300:
                findings.append(_error_finding(target, f"HTTPS returned status {response.status}"))
            _send_child_result(conn, {
                "status": "complete",
                "findings": [finding.to_dict() for finding in findings],
            })
        finally:
            if response is not None:
                response.close()
            connection.close()
    except BaseException as exc:
        try:
            _send_child_result(conn, {
                "status": "error",
                "error": _safe_text(f"{type(exc).__name__}: {exc}"),
            })
        except Exception:
            pass
    finally:
        conn.close()


def _decode_findings(value: object, target: str) -> list[Finding]:
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise RuntimeError("headers child returned an invalid finding list")
    findings: list[Finding] = []
    host = target.strip("[]").rstrip(".")
    expected_url = _response_url(host)
    for item in value:
        if not isinstance(item, dict) or set(item) != _FINDING_KEYS:
            raise RuntimeError("headers child returned a malformed finding")
        if (
            item.get("kind") not in _ALLOWED_KINDS
            or item.get("severity") not in {"info", "low", "medium"}
            or item.get("source") != "recon:headers"
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
            or not isinstance(item.get("lookup_hint"), str)
            or len(item["lookup_hint"]) > MAX_TEXT
            or not isinstance(item.get("request_context"), dict)
            or (
                item.get("cvss") is not None
                and (
                    isinstance(item.get("cvss"), bool)
                    or not isinstance(item.get("cvss"), (int, float))
                    or not 0 <= item["cvss"] <= 10
                )
            )
        ):
            raise RuntimeError("headers child returned an invalid finding contract")
        data = item["data"]
        if item["kind"] == "http_header_missing":
            header = data.get("header")
            if (
                set(data) != {"header", "url"}
                or not isinstance(header, str)
                or header not in _MISSING_HEADER_KNOWLEDGE
                or data.get("url") != expected_url
                or item["severity"] != _MISSING_HEADER_KNOWLEDGE[header]["severity"]
                or item["raw_line"] != f"{expected_url}: missing {header}"
                or item["remediation"] != _safe_text(
                    _MISSING_HEADER_KNOWLEDGE[header]["remediation"],
                )
                or item["impact"] != _safe_text(_MISSING_HEADER_KNOWLEDGE[header]["impact"])
                or item["cwe"] != _safe_text(_MISSING_HEADER_KNOWLEDGE[header]["cwe"])
                or item["cvss"] != _MISSING_HEADER_KNOWLEDGE[header]["cvss"]
                or item["references"] != []
                or item["lookup_hint"] != ""
                or item["request_context"] != {}
            ):
                raise RuntimeError("headers child returned an invalid missing-header observation")
        else:
            error = data.get("error")
            if (
                set(data) != {"target", "error"}
                or data.get("target") != target
                or not isinstance(error, str)
                or len(error) > MAX_TEXT
                or item["severity"] != "info"
                or item["raw_line"] != _safe_text(f"headers GET {target} failed: {error}")
                or item["remediation"] != ""
                or item["impact"] != ""
                or item["cvss"] is not None
                or item["cwe"] != ""
                or item["references"] != []
                or item["lookup_hint"] != ""
                or item["request_context"] != {}
            ):
                raise RuntimeError("headers child returned an invalid error observation")
        findings.append(Finding(**item))
    return findings


class HeadersReconProvider:
    """V2 provider for one fixed root-response security-header observation."""

    def __init__(self, *, store, registry: CapabilityRegistry, scope: ScopeManager) -> None:
        self.store = store
        self.registry = registry
        self.scope = scope
        self._manifest = _MANIFEST
        self.registry.register(self._manifest)

    def bindings(self) -> tuple[CapabilityManifest, ...]:
        return (self._manifest,)

    def _readiness(self) -> bool:
        return True

    def _persist_failure(self, job_id: str, message: str) -> None:
        try:
            self.store.append_line(job_id, "stderr", message[:MAX_TEXT])
            self.store.set_failed(job_id, message[:MAX_TEXT])
        except Exception:
            pass

    def _persist_findings(
        self, job_id: str, findings: list[Finding], started: float,
    ) -> tuple[float, list[dict[str, Any]]]:
        for sequence, finding in enumerate(findings):
            if finding.raw_line:
                self.store.append_line(job_id, "stdout", finding.raw_line)
            self.store.append_finding(job_id, finding, sequence)
        persisted = self.store.get_findings(job_id)
        if not isinstance(persisted, list) or len(persisted) != len(findings):
            raise RuntimeError("headers evidence findings did not persist completely")
        duration_s = time.monotonic() - started
        if not self.store.set_finished(job_id, 0, duration_s):
            raise RuntimeError("could not finish headers evidence job")
        return duration_s, persisted

    def resolve_task(
        self, task: WorkflowTask, *, require_installed: bool = False,
    ) -> CapabilityResolution:
        if not isinstance(task, WorkflowTask) or task.capability_id != CAPABILITY_ID:
            raise CapabilityUnavailable(CAPABILITY_ID, ("task capability does not match provider",))
        if not isinstance(task.inputs, dict) or task.inputs:
            raise CapabilityUnavailable(CAPABILITY_ID, ("headers inputs must be empty",))
        if task.impact != self._manifest.impact or set(task.permissions) != set(self._manifest.permissions):
            raise CapabilityUnavailable(CAPABILITY_ID, ("task permissions/impact differ from manifest",))
        if not _valid_target(task.target):
            raise CapabilityUnavailable(CAPABILITY_ID, ("target must be a bare hostname or IP literal",))
        target_type = "ip"
        try:
            ipaddress.ip_address(task.target)
        except ValueError:
            target_type = "hostname"
        resolution = self.registry.resolve(
            CAPABILITY_ID,
            CapabilityRequirements(
                target_type=target_type,
                protocol="https",
                transport=TRANSPORT,
                required_permissions=self._manifest.permissions,
                maximum_impact=self._manifest.impact,
                required_input_schema=self._manifest.input_schema,
                allowed_providers=(PROVIDER_ID,),
                allowed_versions=(PROVIDER_VERSION,),
                allowed_fingerprints=(self._manifest.fingerprint,),
                allowed_side_effects=self._manifest.side_effects,
            ),
        )
        if resolution.manifest.fingerprint != self._manifest.fingerprint:
            raise CapabilityUnavailable(CAPABILITY_ID, ("provider manifest fingerprint changed",))
        if require_installed and not self._readiness():
            raise CapabilityUnavailable(CAPABILITY_ID, ("headers transport is not ready",))
        return resolution

    async def dispatch(self, task: WorkflowTask) -> dict[str, Any]:
        resolution = self.resolve_task(task, require_installed=True)
        job_id = uuid.uuid4().hex[:12]
        if self.store.get(job_id) is not None:
            raise RuntimeError("headers evidence job id collision")
        self.store.create(job_id)
        if not self.store.set_started(job_id, CAPABILITY_ID, task.target):
            raise RuntimeError("could not start headers evidence job")
        self.store.mark_engine_v2_execution_job(job_id)
        started = time.monotonic()
        child = _BoundedHttpsWorker(
            task.target,
            str(self.scope.path.resolve()),
            min(float(task.timeout_s), self._manifest.timeout_s),
            worker_target=_headers_worker,
        )
        try:
            try:
                payload = await asyncio.to_thread(child.run)
            except asyncio.CancelledError:
                child.request_termination()
                raise
            if payload.get("status") == "scope_denied":
                raise PermissionError("current scope denied the headers operation")
            if payload.get("status") != "complete" or set(payload) != {"status", "findings"}:
                raise RuntimeError(str(payload.get("error", "invalid headers child status"))[:MAX_TEXT])
            findings = _decode_findings(payload["findings"], task.target)
            duration_s, persisted = await asyncio.to_thread(
                self._persist_findings, job_id, findings, started,
            )
        except asyncio.CancelledError:
            child.request_termination()
            await asyncio.to_thread(
                self._persist_failure, job_id,
                "CancelledError: child process termination requested; headers outcome not confirmed",
            )
            raise
        except Exception as exc:
            message = _safe_text(f"{type(exc).__name__}: {exc}")
            await asyncio.to_thread(self._persist_failure, job_id, message)
            raise
        return {
            "job_id": job_id,
            "tool_id": CAPABILITY_ID,
            "target": task.target,
            "exit_code": 0,
            "duration_s": duration_s,
            "findings": persisted,
            "provider_id": resolution.manifest.provider_id,
            "provider_version": resolution.manifest.provider_version,
            "manifest_fingerprint": resolution.manifest.fingerprint,
            "registry_digest": resolution.registry_digest,
            "transport": TRANSPORT,
        }

    def inventory(self) -> list[dict[str, Any]]:
        return [{
            "capability_id": CAPABILITY_ID,
            "provider_id": PROVIDER_ID,
            "provider_version": PROVIDER_VERSION,
            "manifest_fingerprint": self._manifest.fingerprint,
            "transport": TRANSPORT,
            "target_types": list(self._manifest.target_types),
            "registry_digest": self.registry.digest,
            "registered": True,
            "selected_for_execution": True,
            "installed": True,
            "executable": True,
            "readiness": "installed",
        }]
