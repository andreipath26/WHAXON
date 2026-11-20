"""Fixed, bounded Engine V2 security.txt reconnaissance.

Exactly one pinned HTTPS GET is made to /.well-known/security.txt. The worker
never follows redirects or URLs declared in the response; scope is rechecked
inside the supervised child before DNS resolution or network activity.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
import uuid
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
    PROCESS_TIMEOUT_S,
    TRANSPORT,
    _BoundedHttpsWorker,
    _checked_headers,
    _PinnedHTTPSConnection,
    _safe_text,
    _send_child_result,
    _valid_target,
)
from .recon_checks import _SECURITY_TXT_FIELDS
from .scope import ScopeManager
from .workflow import WorkflowTask

CAPABILITY_ID = "web.recon.security_txt"
PROVIDER_ID = "whaxon.recon.security_txt"
PROVIDER_VERSION = "1.0.0"
PATH = "/.well-known/security.txt"
MAX_BODY_BYTES = 65_536
MAX_FINDINGS = 2_048
MAX_TEXT = 8_192
_ALLOWED_KINDS = {"security_txt", "security_txt_missing", "recon_error"}
_FINDING_KEYS = {
    "kind", "severity", "source", "data", "raw_line", "remediation",
    "impact", "cvss", "cwe", "references", "lookup_hint", "request_context",
}

_MANIFEST = CapabilityManifest(
    capability_id=CAPABILITY_ID,
    provider_id=PROVIDER_ID,
    provider_version=PROVIDER_VERSION,
    transports=(TRANSPORT,), protocols=("https",), scope_mode="pinned_network",
    target_types=("hostname", "ip"), permissions=("network.scan",),
    side_effects=("https_requests", "network_traffic", "target_service_logs"),
    impact="moderate", readiness="registered", timeout_s=PROCESS_TIMEOUT_S,
    input_schema={"type": "object", "properties": {}, "required": [],
                  "additionalProperties": False},
    output_schema={
        "type": "object",
        "properties": {
            "job_id": {"type": "string", "minLength": 1},
            "tool_id": {"const": CAPABILITY_ID},
            "target": {"type": "string", "minLength": 1},
            "exit_code": {"type": "integer"},
            "duration_s": {"type": "number", "minimum": 0},
            "findings": {"type": "array", "maxItems": MAX_FINDINGS,
                         "items": {"type": "object"}},
            "provider_id": {"const": PROVIDER_ID},
            "provider_version": {"const": PROVIDER_VERSION},
            "manifest_fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "registry_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "transport": {"const": TRANSPORT},
        },
        "required": ["job_id", "tool_id", "target", "exit_code", "duration_s",
                     "findings", "provider_id", "provider_version",
                     "manifest_fingerprint", "registry_digest", "transport"],
        "additionalProperties": False,
    },
    limitations=(
        "Exactly one GET /.well-known/security.txt over HTTPS port 443.",
        "The child resolves once, checks every answer against current scope, and connects only to returned numeric pinned addresses.",
        "Redirects, HTTP fallback, and URLs in the response are never followed.",
        "Response headers are capped at 100 fields and 64 KiB; body at 64 KiB; findings, IPC output and child lifetime are bounded.",
        "RFC 9116 known fields are emitted as informational observations; no expiry or URL is fetched or independently validated.",
    ),
)


def _url(host: str) -> str:
    authority = f"[{host}]" if ":" in host else host
    return f"https://{authority}{PATH}"


def _finding(kind: str, host: str, data: dict[str, Any], raw: str) -> Finding:
    return Finding(kind=kind, severity="info", source="recon:security_txt",
                   data=data, raw_line=_safe_text(raw))


def _parse(host: str, body: bytes) -> list[Finding]:
    url = _url(host)
    text = body.decode("utf-8", errors="replace")
    seen: dict[str, list[str]] = {}
    allowed = {field.lower(): field for field in _SECURITY_TXT_FIELDS}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        field = allowed.get(key.strip().lower())
        value = value.strip()
        if field and value:
            if len(value) > MAX_TEXT:
                raise ValueError("security.txt field exceeded the text limit")
            seen.setdefault(field, []).append(_safe_text(value))
            if sum(len(values) for values in seen.values()) > MAX_FINDINGS:
                raise ValueError("security.txt produced too many findings")
    if not seen:
        return [_finding(
            "security_txt_missing", host,
            {"url": url, "body_present": True, "fields_found": []},
            f"security.txt at {url} contains no recognised RFC 9116 fields",
        )]
    return [
        _finding("security_txt", host, {"url": url, "field": field, "value": value},
                 f"{url}: {field}: {value}")
        for field, values in seen.items() for value in values
    ]


def _worker(conn, target: str, scope_path: str) -> None:
    try:
        if not _valid_target(target):
            _send_child_result(conn, {"status": "error", "error": "invalid security.txt target"})
            return
        scope = ScopeManager(Path(scope_path))
        resolution = scope.resolve_for_execution(target, port=443)
        if not resolution.allowed or not resolution.addresses:
            _send_child_result(conn, {"status": "scope_denied", "reason": _safe_text(resolution.reason or "scope denied")})
            return
        host = target.strip("[]").rstrip(".")
        connection = _PinnedHTTPSConnection(host, resolution.addresses, timeout=CONNECT_TIMEOUT_S)
        response = None
        try:
            host_header = f"[{host}]" if ":" in host else host
            connection.request("GET", PATH, headers={
                "Host": host_header, "User-Agent": "WHAXON-recon/2.0",
                "Connection": "close",
            })
            response = connection.getresponse()
            _checked_headers(response.getheaders())
            status = int(response.status)
            if status < 200 or status >= 300:
                findings = [_finding("recon_error", host,
                    {"url": _url(host), "error": f"HTTPS returned status {status}"},
                    f"security.txt fetch failed for {_url(host)}: HTTPS returned status {status}")]
            else:
                body = response.read(MAX_BODY_BYTES + 1)
                if not isinstance(body, bytes):
                    raise TypeError("HTTPS body reader returned non-bytes")
                if len(body) > MAX_BODY_BYTES:
                    findings = [_finding("recon_error", host,
                        {"url": _url(host), "error": "response body exceeded the 64 KiB limit"},
                        f"security.txt fetch failed for {_url(host)}: response body exceeded the 64 KiB limit")]
                else:
                    findings = _parse(host, body)
        finally:
            if response is not None:
                response.close()
            connection.close()
        _send_child_result(conn, {"status": "complete", "findings": [x.to_dict() for x in findings]})
    except BaseException as exc:
        try:
            _send_child_result(conn, {"status": "error", "error": _safe_text(f"{type(exc).__name__}: {exc}")})
        except Exception:
            pass
    finally:
        conn.close()


def _decode(value: object, target: str) -> list[Finding]:
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise RuntimeError("security.txt child returned an invalid finding list")
    findings = []
    expected_url = _url(target.strip("[]").rstrip("."))
    known_fields = set(_SECURITY_TXT_FIELDS)
    for item in value:
        if not isinstance(item, dict) or set(item) != _FINDING_KEYS:
            raise RuntimeError("security.txt child returned a malformed finding")
        if (item.get("kind") not in _ALLOWED_KINDS or item.get("severity") != "info"
                or item.get("source") != "recon:security_txt"
                or not isinstance(item.get("data"), dict)
                or not isinstance(item.get("raw_line"), str) or len(item["raw_line"]) > MAX_TEXT
                or not isinstance(item.get("remediation"), str) or len(item["remediation"]) > MAX_TEXT
                or not isinstance(item.get("impact"), str) or len(item["impact"]) > MAX_TEXT
                or not isinstance(item.get("cwe"), str)
                or not isinstance(item.get("references"), list)
                or any(not isinstance(ref, str) or len(ref) > MAX_TEXT for ref in item["references"])
                or not isinstance(item.get("lookup_hint"), str) or len(item["lookup_hint"]) > MAX_TEXT
                or not isinstance(item.get("request_context"), dict)
                or item.get("cvss") is not None):
            raise RuntimeError("security.txt child returned an invalid finding contract")
        data = item["data"]
        if item["kind"] == "security_txt":
            if (set(data) != {"url", "field", "value"} or data.get("field") not in known_fields
                    or not isinstance(data.get("value"), str) or len(data["value"]) > MAX_TEXT
                    or data.get("url") != expected_url
                    or item["raw_line"] != f"{data['url']}: {data['field']}: {data['value']}"):
                raise RuntimeError("security.txt child returned an invalid field observation")
        elif item["kind"] == "security_txt_missing":
            if (set(data) != {"url", "body_present", "fields_found"}
                    or data.get("body_present") is not True or data.get("fields_found") != []
                    or data.get("url") != expected_url):
                raise RuntimeError("security.txt child returned an invalid missing observation")
        elif (set(data) != {"url", "error"} or not isinstance(data.get("url"), str)
              or data.get("url") != expected_url or not isinstance(data.get("error"), str)
              or len(data["error"]) > MAX_TEXT):
            raise RuntimeError("security.txt child returned an invalid error observation")
        findings.append(Finding(**item))
    return findings


class SecurityTxtReconProvider:
    """V2 provider for one fixed RFC 9116 endpoint request."""
    def __init__(self, *, store, registry: CapabilityRegistry, scope: ScopeManager) -> None:
        self.store, self.registry, self.scope = store, registry, scope
        self._manifest = _MANIFEST
        self.registry.register(self._manifest)

    def bindings(self) -> tuple[CapabilityManifest, ...]:
        return (self._manifest,)

    def _readiness(self) -> bool:
        return True

    def resolve_task(self, task: WorkflowTask, *, require_installed: bool = False) -> CapabilityResolution:
        if not isinstance(task, WorkflowTask) or task.capability_id != CAPABILITY_ID:
            raise CapabilityUnavailable(CAPABILITY_ID, ("task capability does not match provider",))
        if not isinstance(task.inputs, dict) or task.inputs:
            raise CapabilityUnavailable(CAPABILITY_ID, ("security.txt inputs must be empty",))
        if task.impact != self._manifest.impact or set(task.permissions) != set(self._manifest.permissions):
            raise CapabilityUnavailable(CAPABILITY_ID, ("task permissions/impact differ from manifest",))
        if not _valid_target(task.target):
            raise CapabilityUnavailable(CAPABILITY_ID, ("target must be a bare hostname or IP literal",))
        try:
            ipaddress.ip_address(task.target); target_type = "ip"
        except ValueError:
            target_type = "hostname"
        result = self.registry.resolve(CAPABILITY_ID, CapabilityRequirements(
            target_type=target_type, protocol="https", transport=TRANSPORT,
            required_permissions=self._manifest.permissions, maximum_impact=self._manifest.impact,
            required_input_schema=self._manifest.input_schema, allowed_providers=(PROVIDER_ID,),
            allowed_versions=(PROVIDER_VERSION,), allowed_fingerprints=(self._manifest.fingerprint,),
            allowed_side_effects=self._manifest.side_effects,
        ))
        if result.manifest.fingerprint != self._manifest.fingerprint:
            raise CapabilityUnavailable(CAPABILITY_ID, ("provider manifest fingerprint changed",))
        if require_installed and not self._readiness():
            raise CapabilityUnavailable(CAPABILITY_ID, ("security.txt transport is not ready",))
        return result

    async def dispatch(self, task: WorkflowTask) -> dict[str, Any]:
        resolution = self.resolve_task(task, require_installed=True)
        job_id = uuid.uuid4().hex[:12]
        if self.store.get(job_id) is not None:
            raise RuntimeError("security.txt evidence job id collision")
        self.store.create(job_id)
        if not self.store.set_started(job_id, CAPABILITY_ID, task.target):
            raise RuntimeError("could not start security.txt evidence job")
        self.store.mark_engine_v2_execution_job(job_id)
        started = time.monotonic()
        child = _BoundedHttpsWorker(task.target, str(self.scope.path.resolve()),
            min(float(task.timeout_s), self._manifest.timeout_s), worker_target=_worker)
        try:
            payload = await asyncio.to_thread(child.run)
            if payload.get("status") == "scope_denied":
                raise PermissionError("current scope denied the security.txt operation")
            if payload.get("status") != "complete" or set(payload) != {"status", "findings"}:
                raise RuntimeError(str(payload.get("error", "invalid security.txt child status"))[:MAX_TEXT])
            findings = _decode(payload["findings"], task.target)
            for seq, finding in enumerate(findings):
                if finding.raw_line:
                    self.store.append_line(job_id, "stdout", finding.raw_line)
                self.store.append_finding(job_id, finding, seq)
            persisted = self.store.get_findings(job_id)
            if not isinstance(persisted, list) or len(persisted) != len(findings):
                raise RuntimeError("security.txt evidence findings did not persist completely")
            duration = time.monotonic() - started
            if not self.store.set_finished(job_id, 0, duration):
                raise RuntimeError("could not finish security.txt evidence job")
        except asyncio.CancelledError:
            child.request_termination()
            self._fail(job_id, "CancelledError: child termination requested; outcome not confirmed")
            raise
        except Exception as exc:
            self._fail(job_id, _safe_text(f"{type(exc).__name__}: {exc}"))
            raise
        return {"job_id": job_id, "tool_id": CAPABILITY_ID, "target": task.target,
            "exit_code": 0, "duration_s": duration, "findings": persisted,
            "provider_id": resolution.manifest.provider_id,
            "provider_version": resolution.manifest.provider_version,
            "manifest_fingerprint": resolution.manifest.fingerprint,
            "registry_digest": resolution.registry_digest, "transport": TRANSPORT}

    def _fail(self, job_id: str, message: str) -> None:
        try:
            self.store.append_line(job_id, "stderr", message[:MAX_TEXT])
            self.store.set_failed(job_id, message[:MAX_TEXT])
        except Exception:
            pass

    def inventory(self) -> list[dict[str, Any]]:
        return [{"capability_id": CAPABILITY_ID, "provider_id": PROVIDER_ID,
            "provider_version": PROVIDER_VERSION, "manifest_fingerprint": self._manifest.fingerprint,
            "transport": TRANSPORT, "target_types": list(self._manifest.target_types),
            "registry_digest": self.registry.digest, "registered": True,
            "selected_for_execution": True, "installed": True, "executable": True,
            "readiness": "installed"}]
