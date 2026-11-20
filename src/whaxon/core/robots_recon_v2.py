"""Fixed, bounded Engine V2 robots.txt and sitemap reconnaissance.

The provider makes exactly two HTTPS GETs to fixed paths on the authorized
host. One child-side scope resolution pins both requests; response redirects,
sitemap references and sitemap locations are never followed.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
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
from .scope import ScopeManager
from .workflow import WorkflowTask

CAPABILITY_ID = "web.recon.robots"
PROVIDER_ID = "whaxon.recon.robots"
PROVIDER_VERSION = "1.0.0"
MAX_BODY_BYTES = 65_536
MAX_FINDINGS = 2_048
MAX_TEXT = 8_192
MAX_SITEMAP_URLS = 100
REQUEST_PATHS = ("/robots.txt", "/sitemap.xml")
_ALLOWED_KINDS = {
    "robots_disallow", "robots_sitemap_ref", "sitemap_url", "recon_error",
}
_FINDING_KEYS = {
    "kind", "severity", "source", "data", "raw_line", "remediation",
    "impact", "cvss", "cwe", "references", "lookup_hint", "request_context",
}
_LOC_RE = re.compile(r"<loc>([^<]+)</loc>")


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
                "items": {"type": "object"},
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
        "Exactly GET /robots.txt and GET /sitemap.xml over HTTPS port 443.",
        "The child resolves once, checks every answer against scope, and reuses numeric pinned addresses for both requests.",
        "Redirects and HTTP fallback are disabled; sitemap references and locations are evidence only and are never fetched.",
        "Each response body is capped at 64 KiB; response headers, findings, IPC output and child lifetime are bounded.",
        "Non-2xx and redirect responses produce error evidence and are not reported as missing files.",
    ),
)


def _response_url(host: str, path: str) -> str:
    authority = f"[{host}]" if ":" in host else host
    return f"https://{authority}{path}"


def _error_finding(target: str, path: str, message: str) -> Finding:
    url = _response_url(target.strip("[]").rstrip("."), path)
    message = _safe_text(message)
    return Finding(
        kind="recon_error",
        severity="info",
        source="recon:robots",
        data={"target": target, "url": url, "error": message},
        raw_line=_safe_text(f"robots fetch failed for {url}: {message}"),
    )


def _finding(kind: str, data: dict[str, Any], raw_line: str) -> Finding:
    return Finding(
        kind=kind,
        severity="info",
        source="recon:robots",
        data=data,
        raw_line=_safe_text(raw_line),
    )


def _parse_robots(host: str, body: bytes) -> list[Finding]:
    text = body.decode("utf-8", errors="replace")
    url = _response_url(host, "/robots.txt")
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                if len(path) > MAX_TEXT:
                    raise ValueError("robots.txt path exceeded the text limit")
                safe_path = _safe_text(path)
                findings.append(_finding(
                    "robots_disallow",
                    {"url": url, "path": safe_path},
                    f"{url}: Disallow {safe_path}",
                ))
        elif low.startswith("sitemap:"):
            sitemap = line.split(":", 1)[1].strip()
            if sitemap:
                if len(sitemap) > MAX_TEXT:
                    raise ValueError("robots.txt sitemap reference exceeded the text limit")
                safe_sitemap = _safe_text(sitemap)
                findings.append(_finding(
                    "robots_sitemap_ref",
                    {"url": url, "sitemap": safe_sitemap},
                    f"{url}: Sitemap {safe_sitemap}",
                ))
        if len(findings) > MAX_FINDINGS:
            raise ValueError("robots.txt produced too many findings")
    return findings


def _parse_sitemap(host: str, body: bytes) -> list[Finding]:
    text = body.decode("utf-8", errors="replace")
    sitemap_url = _response_url(host, "/sitemap.xml")
    findings: list[Finding] = []
    for loc in _LOC_RE.findall(text)[:MAX_SITEMAP_URLS]:
        if len(loc) > MAX_TEXT:
            raise ValueError("sitemap location exceeded the text limit")
        safe_loc = _safe_text(loc)
        findings.append(_finding(
            "sitemap_url",
            {"sitemap": sitemap_url, "url": safe_loc},
            f"{sitemap_url}: {safe_loc}",
        ))
    return findings


def _request_fixed_path(
    connection: _PinnedHTTPSConnection,
    host: str,
    path: str,
) -> tuple[int, bytes | None]:
    host_header = f"[{host}]" if ":" in host else host
    response = None
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": host_header,
                "User-Agent": "WHAXON-recon/2.0",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        _checked_headers(response.getheaders())
        status = int(response.status)
        if status < 200 or status >= 300:
            return status, None
        body = response.read(MAX_BODY_BYTES + 1)
        if not isinstance(body, bytes):
            raise TypeError("HTTPS body reader returned non-bytes")
        return status, body
    finally:
        if response is not None:
            response.close()
        # The next fixed path reconnects through the same address set already
        # returned by resolve_for_execution; closing cannot trigger DNS.
        connection.close()


def _robots_worker(conn, target: str, scope_path: str) -> None:
    """Resolve and scope once, then request only the two fixed HTTPS paths."""
    try:
        if not _valid_target(target):
            _send_child_result(conn, {"status": "error", "error": "invalid robots target"})
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
        findings: list[Finding] = []
        try:
            for path in REQUEST_PATHS:
                try:
                    status, body = _request_fixed_path(connection, host, path)
                    if status < 200 or status >= 300:
                        findings.append(_error_finding(
                            target, path, f"HTTPS returned status {status}",
                        ))
                        continue
                    if body is None:
                        findings.append(_error_finding(
                            target, path, "HTTPS response did not include a readable body",
                        ))
                        continue
                    if len(body) > MAX_BODY_BYTES:
                        findings.append(_error_finding(
                            target, path, "response body exceeded the 64 KiB limit",
                        ))
                        continue
                    parsed = (
                        _parse_robots(host, body)
                        if path == "/robots.txt"
                        else _parse_sitemap(host, body)
                    )
                    if len(findings) + len(parsed) > MAX_FINDINGS:
                        findings = findings[:MAX_FINDINGS - 1]
                        findings.append(_error_finding(
                            target, path, "robots response exceeded the finding limit",
                        ))
                        continue
                    findings.extend(parsed)
                except BaseException as exc:
                    # Preserve an error observation for this fixed path; never
                    # reinterpret a failed request as an absent file.
                    findings = findings[:MAX_FINDINGS - 1]
                    findings.append(_error_finding(
                        target, path, f"{type(exc).__name__}: {exc}",
                    ))
                if len(findings) > MAX_FINDINGS:
                    raise ValueError("robots recon produced too many findings")
            _send_child_result(conn, {
                "status": "complete",
                "findings": [finding.to_dict() for finding in findings],
            })
        finally:
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


def _decode_findings(value: object) -> list[Finding]:
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise RuntimeError("robots child returned an invalid finding list")
    findings: list[Finding] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _FINDING_KEYS:
            raise RuntimeError("robots child returned a malformed finding")
        if (
            item.get("kind") not in _ALLOWED_KINDS
            or item.get("severity") != "info"
            or item.get("source") != "recon:robots"
            or not isinstance(item.get("data"), dict)
            or not isinstance(item.get("raw_line"), str)
            or len(item["raw_line"]) > MAX_TEXT
            or not isinstance(item.get("remediation"), str)
            or len(item["remediation"]) > MAX_TEXT
            or not isinstance(item.get("impact"), str)
            or len(item["impact"]) > MAX_TEXT
            or not isinstance(item.get("cwe"), str)
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
            raise RuntimeError("robots child returned an invalid finding contract")
        findings.append(Finding(**item))
    return findings


class RobotsReconProvider:
    """V2 provider for the fixed robots.txt and sitemap HTTPS requests."""

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
        for seq, finding in enumerate(findings):
            if finding.raw_line:
                self.store.append_line(job_id, "stdout", finding.raw_line)
            self.store.append_finding(job_id, finding, seq)
        persisted = self.store.get_findings(job_id)
        if not isinstance(persisted, list) or len(persisted) != len(findings):
            raise RuntimeError("robots evidence findings did not persist completely")
        duration_s = time.monotonic() - started
        if not self.store.set_finished(job_id, 0, duration_s):
            raise RuntimeError("could not finish robots evidence job")
        return duration_s, persisted

    def resolve_task(
        self, task: WorkflowTask, *, require_installed: bool = False,
    ) -> CapabilityResolution:
        if not isinstance(task, WorkflowTask) or task.capability_id != CAPABILITY_ID:
            raise CapabilityUnavailable(CAPABILITY_ID, ("task capability does not match provider",))
        if not isinstance(task.inputs, dict) or task.inputs:
            raise CapabilityUnavailable(CAPABILITY_ID, ("robots inputs must be empty",))
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
            raise CapabilityUnavailable(CAPABILITY_ID, ("robots transport is not ready",))
        return resolution

    async def dispatch(self, task: WorkflowTask) -> dict[str, Any]:
        resolution = self.resolve_task(task, require_installed=True)
        job_id = uuid.uuid4().hex[:12]
        if self.store.get(job_id) is not None:
            raise RuntimeError("robots evidence job id collision")
        self.store.create(job_id)
        if not self.store.set_started(job_id, CAPABILITY_ID, task.target):
            raise RuntimeError("could not start robots evidence job")
        self.store.mark_engine_v2_execution_job(job_id)
        started = time.monotonic()
        child = _BoundedHttpsWorker(
            task.target,
            str(self.scope.path.resolve()),
            min(float(task.timeout_s), self._manifest.timeout_s),
            worker_target=_robots_worker,
        )
        try:
            try:
                payload = await asyncio.to_thread(child.run)
            except asyncio.CancelledError:
                child.request_termination()
                raise
            if payload.get("status") == "scope_denied":
                raise PermissionError("current scope denied the robots operation")
            if payload.get("status") != "complete" or set(payload) != {"status", "findings"}:
                raise RuntimeError(str(payload.get("error", "invalid robots child status"))[:MAX_TEXT])
            findings = _decode_findings(payload["findings"])
            duration_s, persisted = await asyncio.to_thread(
                self._persist_findings, job_id, findings, started,
            )
        except asyncio.CancelledError:
            child.request_termination()
            await asyncio.to_thread(
                self._persist_failure, job_id,
                "CancelledError: child process termination requested; robots outcome not confirmed",
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

