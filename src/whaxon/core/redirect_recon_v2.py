"""Fixed, bounded first-hop Engine V2 redirect observation.

Exactly one scope-pinned HTTPS GET is made to ``/``. The response's status
and Location header are recorded, but redirects are never followed. Persisted
Location displays omit user-info, query strings and fragments.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

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
    MAX_FINDINGS,
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
from .scope import ScopeManager
from .workflow import WorkflowTask

CAPABILITY_ID = "web.recon.redirect_observe"
PROVIDER_ID = "whaxon.recon.redirect_observe"
PROVIDER_VERSION = "1.0.0"
MAX_LOCATION = 2048
_ALLOWED_KINDS = {"redirect_observation", "recon_error"}
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
    side_effects=(
        "dns_queries", "resolver_logs", "https_requests",
        "network_traffic", "target_service_logs",
    ),
    impact="moderate",
    readiness="registered",
    timeout_s=PROCESS_TIMEOUT_S,
    input_schema={
        "type": "object", "properties": {}, "required": [],
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
                "type": "array", "maxItems": MAX_FINDINGS,
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
        "Exactly one GET / over HTTPS port 443; status and Location are observed only.",
        "Location is never followed, including same-origin and cross-origin destinations.",
        "Non-HTTP(S) Location values are displayed only as unsupported-scheme markers and are not classified as web origins.",
        "The child resolves once, checks every answer against current scope, and connects only to returned numeric pinned addresses.",
        "Location display omits credentials, query strings and fragments; response bodies are never read.",
        "Response headers, child output and child lifetime are bounded.",
        "This is a first-hop observation, not the legacy redirect-chain check or full parity.",
    ),
)


def _root_url(host: str) -> str:
    authority = f"[{host}]" if ":" in host else host
    return f"https://{authority}/"


def _origin(scheme: str, host: str, port: int | None) -> tuple[str, str, int]:
    normalized_scheme = scheme.lower()
    if port is None:
        port = 443 if normalized_scheme == "https" else 80
    normalized_host = host.rstrip(".").lower()
    try:
        normalized_host = ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    return normalized_scheme, normalized_host, port


def _display_location(root_url: str, raw_location: str) -> tuple[str, bool, bool]:
    """Return a credential/query-free display and first-hop classifications."""
    if not isinstance(raw_location, str) or len(raw_location) > MAX_LOCATION:
        raise ValueError("Location header exceeded the size limit")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw_location):
        raise ValueError("Location header contained control characters")
    resolved = urljoin(root_url, raw_location.strip())
    try:
        destination = urlsplit(resolved)
        root = urlsplit(root_url)
        scheme = destination.scheme.lower()
        if scheme not in {"http", "https"}:
            # Preserve only the URI scheme; arbitrary non-HTTP payloads are
            # never treated as network destinations or persisted verbatim.
            display = _safe_text(f"{scheme or 'unknown'}:[unsupported location scheme]", MAX_LOCATION)
            return display, False, False
        host = destination.hostname
        if not host:
            raise ValueError("Location header had no destination host")
        port = destination.port
        display_host = f"[{host}]" if ":" in host else host
        default_port = 443 if scheme == "https" else 80
        authority = display_host if port in (None, default_port) else f"{display_host}:{port}"
        # Drop user-info, query and fragment even when they are present in the
        # source Location. Keep only the path for human-readable evidence.
        path = destination.path or "/"
        display = _safe_text(f"{scheme}://{authority}{path}", MAX_LOCATION)
        cross_origin = _origin(scheme, host, port) != _origin(
            root.scheme, root.hostname or "", root.port,
        )
        return display, cross_origin, scheme == "http"
    except (TypeError, ValueError) as exc:
        raise ValueError("Location header was not a valid HTTP(S) destination") from exc


def _finding_error(target: str, message: str) -> Finding:
    url = _root_url(target.strip("[]").rstrip("."))
    safe = _safe_text(message)
    return Finding(
        kind="recon_error", severity="info", source="recon:redirects",
        data={"url": url, "error": safe},
        raw_line=_safe_text(f"redirect observation {url} failed: {safe}"),
    )


def _make_observation(target: str, status: int, raw_location: str | None) -> Finding:
    host = target.strip("[]").rstrip(".")
    url = _root_url(host)
    redirect_status = 300 <= status < 400
    location_present = raw_location is not None
    display = ""
    cross_origin = False
    downgrade = False
    if location_present and raw_location:
        display, observed_cross_origin, observed_downgrade = _display_location(url, raw_location)
        if redirect_status:
            cross_origin = observed_cross_origin
            downgrade = observed_downgrade
    labels = []
    if cross_origin:
        labels.append("cross-origin")
    if downgrade:
        labels.append("HTTPS downgrade")
    suffix = f" Location: {display}" if location_present else " no Location header"
    if labels:
        suffix += f" ({', '.join(labels)})"
    return Finding(
        kind="redirect_observation", severity="info", source="recon:redirects",
        data={
            "url": url,
            "status_code": status,
            "redirect_status": redirect_status,
            "location_present": location_present,
            "location_display": display,
            "cross_origin": cross_origin,
            "https_downgrade": downgrade,
        },
        raw_line=_safe_text(f"{url}: HTTP {status};{suffix}"),
    )


def _worker(conn, target: str, scope_path: str) -> None:
    try:
        if not _valid_target(target):
            _send_child_result(conn, {"status": "error", "error": "invalid redirect target"})
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
            locations = [value for name, value in headers if name.lower() == "location"]
            if len(locations) > 1:
                findings = [_finding_error(target, "response contained multiple Location headers")]
            else:
                status = int(response.status)
                if isinstance(status, bool) or not 100 <= status <= 599:
                    findings = [_finding_error(target, "response contained an invalid HTTP status")]
                else:
                    try:
                        findings = [_make_observation(target, status, locations[0] if locations else None)]
                    except ValueError:
                        findings = [_finding_error(target, "response Location header could not be safely classified")]
        finally:
            if response is not None:
                response.close()
            connection.close()
        _send_child_result(conn, {"status": "complete", "findings": [f.to_dict() for f in findings]})
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


def _decode(value: object, target: str) -> list[Finding]:
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise RuntimeError("redirect child returned an invalid finding list")
    host = target.strip("[]").rstrip(".")
    expected_url = _root_url(host)
    findings: list[Finding] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _FINDING_KEYS:
            raise RuntimeError("redirect child returned a malformed finding")
        if (
            item.get("kind") not in _ALLOWED_KINDS
            or item.get("severity") != "info"
            or item.get("source") != "recon:redirects"
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
            or item.get("cvss") is not None
        ):
            raise RuntimeError("redirect child returned an invalid finding contract")
        data = item["data"]
        if item["kind"] == "redirect_observation":
            expected_keys = {
                "url", "status_code", "redirect_status", "location_present",
                "location_display", "cross_origin", "https_downgrade",
            }
            status = data.get("status_code")
            redirect = isinstance(status, int) and not isinstance(status, bool) and 300 <= status < 400
            location = data.get("location_display")
            present = data.get("location_present")
            if (
                set(data) != expected_keys
                or data.get("url") != expected_url
                or not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599
                or data.get("redirect_status") is not redirect
                or not isinstance(present, bool)
                or not isinstance(location, str) or len(location) > MAX_LOCATION
                or not isinstance(data.get("cross_origin"), bool)
                or not isinstance(data.get("https_downgrade"), bool)
                or (data["https_downgrade"] and not data["cross_origin"])
                or (not present and (location or data["cross_origin"] or data["https_downgrade"]))
            ):
                raise RuntimeError("redirect child returned an invalid observation")
            if location:
                try:
                    parsed = urlsplit(location)
                except ValueError as exc:
                    raise RuntimeError("redirect child returned an invalid Location display") from exc
                if parsed.query or parsed.fragment or parsed.username or parsed.password:
                    raise RuntimeError("redirect child returned an unredacted Location display")
                try:
                    _, expected_cross_origin, expected_downgrade = _display_location(
                        expected_url, location,
                    )
                except ValueError as exc:
                    raise RuntimeError("redirect child returned an invalid Location display") from exc
                if redirect:
                    if (
                        data["cross_origin"] is not expected_cross_origin
                        or data["https_downgrade"] is not expected_downgrade
                    ):
                        raise RuntimeError("redirect child returned inconsistent Location classifications")
            if not redirect and (data["cross_origin"] or data["https_downgrade"]):
                raise RuntimeError("non-redirect response claimed a redirect classification")
            suffix = f" Location: {location}" if present else " no Location header"
            labels = []
            if data["cross_origin"]:
                labels.append("cross-origin")
            if data["https_downgrade"]:
                labels.append("HTTPS downgrade")
            if labels:
                suffix += f" ({', '.join(labels)})"
            expected_raw = _safe_text(f"{expected_url}: HTTP {status};{suffix}")
            if item["raw_line"] != expected_raw:
                raise RuntimeError("redirect child returned inconsistent summary text")
        else:
            if (
                set(data) != {"url", "error"}
                or data.get("url") != expected_url
                or not isinstance(data.get("error"), str)
                or len(data["error"]) > MAX_TEXT
                or item["raw_line"] != _safe_text(f"redirect observation {expected_url} failed: {data['error']}")
            ):
                raise RuntimeError("redirect child returned an invalid error observation")
        findings.append(Finding(**item))
    return findings


class RedirectObservationProvider:
    """V2 provider for a single first-hop redirect observation."""

    def __init__(self, *, store, registry: CapabilityRegistry, scope: ScopeManager) -> None:
        self.store, self.registry, self.scope = store, registry, scope
        self._manifest = _MANIFEST
        self.registry.register(self._manifest)

    def bindings(self) -> tuple[CapabilityManifest, ...]:
        return (self._manifest,)

    def _readiness(self) -> bool:
        return True

    def resolve_task(
        self, task: WorkflowTask, *, require_installed: bool = False,
    ) -> CapabilityResolution:
        if not isinstance(task, WorkflowTask) or task.capability_id != CAPABILITY_ID:
            raise CapabilityUnavailable(CAPABILITY_ID, ("task capability does not match provider",))
        if not isinstance(task.inputs, dict) or task.inputs:
            raise CapabilityUnavailable(CAPABILITY_ID, ("redirect inputs must be empty",))
        if task.impact != self._manifest.impact or set(task.permissions) != set(self._manifest.permissions):
            raise CapabilityUnavailable(CAPABILITY_ID, ("task permissions/impact differ from manifest",))
        if not _valid_target(task.target):
            raise CapabilityUnavailable(CAPABILITY_ID, ("target must be a bare hostname or IP literal",))
        try:
            ipaddress.ip_address(task.target)
            target_type = "ip"
        except ValueError:
            target_type = "hostname"
        resolution = self.registry.resolve(CAPABILITY_ID, CapabilityRequirements(
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
        ))
        if resolution.manifest.fingerprint != self._manifest.fingerprint:
            raise CapabilityUnavailable(CAPABILITY_ID, ("provider manifest fingerprint changed",))
        if require_installed and not self._readiness():
            raise CapabilityUnavailable(CAPABILITY_ID, ("redirect observation transport is not ready",))
        return resolution

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
            raise RuntimeError("redirect evidence findings did not persist completely")
        duration = time.monotonic() - started
        if not self.store.set_finished(job_id, 0, duration):
            raise RuntimeError("could not finish redirect evidence job")
        return duration, persisted

    async def dispatch(self, task: WorkflowTask) -> dict[str, Any]:
        resolution = self.resolve_task(task, require_installed=True)
        job_id = uuid.uuid4().hex[:12]
        if self.store.get(job_id) is not None:
            raise RuntimeError("redirect evidence job id collision")
        self.store.create(job_id)
        if not self.store.set_started(job_id, CAPABILITY_ID, task.target):
            raise RuntimeError("could not start redirect evidence job")
        self.store.mark_engine_v2_execution_job(job_id)
        started = time.monotonic()
        child = _BoundedHttpsWorker(
            task.target, str(self.scope.path.resolve()),
            min(float(task.timeout_s), self._manifest.timeout_s),
            worker_target=_worker,
        )
        try:
            try:
                payload = await asyncio.to_thread(child.run)
            except asyncio.CancelledError:
                child.request_termination()
                raise
            if payload.get("status") == "scope_denied":
                raise PermissionError("current scope denied the redirect observation")
            if payload.get("status") != "complete" or set(payload) != {"status", "findings"}:
                raise RuntimeError(str(payload.get("error", "invalid redirect child status"))[:MAX_TEXT])
            findings = _decode(payload["findings"], task.target)
            duration, persisted = await asyncio.to_thread(
                self._persist_findings, job_id, findings, started,
            )
        except asyncio.CancelledError:
            child.request_termination()
            await asyncio.to_thread(
                self._persist_failure, job_id,
                "CancelledError: child termination requested; redirect observation outcome not confirmed",
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
            "duration_s": duration,
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
