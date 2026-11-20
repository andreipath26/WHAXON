"""Bounded V2 TLS certificate inspection over scope-pinned numeric sockets.

This provider is intentionally fixed to HTTPS/TLS port 443. It does not use
legacy recon helpers or accept URLs, caller-selected ports, redirects, or
resolver settings.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
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
    MAX_TEXT,
    TRANSPORT,
    _BoundedDnsWorker,
    _send_child_result,
    _valid_hostname,
)
from .scope import PinnedSocketAddress, ScopeManager
from .workflow import WorkflowTask

CAPABILITY_ID = "tls.certificate.inspect"
PROVIDER_ID = "whaxon.recon.tls_cert"
PROVIDER_VERSION = "1.0.0"
PROCESS_TIMEOUT_S = 20.0
CONNECT_TIMEOUT_S = 5.0
_FINDING_KEYS = {
    "kind", "severity", "source", "data", "raw_line", "remediation",
    "impact", "cvss", "cwe", "references", "lookup_hint", "request_context",
}
_MANIFEST = CapabilityManifest(
    capability_id=CAPABILITY_ID,
    provider_id=PROVIDER_ID,
    provider_version=PROVIDER_VERSION,
    transports=(TRANSPORT,),
    target_types=("hostname",),
    protocols=("tls",),
    permissions=("network.scan",),
    side_effects=("tls_connection", "certificate_metadata"),
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
                "maxItems": 16,
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"enum": ["ssl_cert", "ssl_cert_invalid", "recon_discovered_host"]},
                        "severity": {"enum": ["info", "medium"]},
                        "source": {"const": "recon:ssl"},
                        "data": {"type": "object"},
                        "raw_line": {"type": "string", "maxLength": MAX_TEXT},
                        "remediation": {"type": "string", "maxLength": MAX_TEXT},
                        "impact": {"type": "string", "maxLength": MAX_TEXT},
                        "cvss": {"type": ["number", "null"]},
                        "cwe": {"type": "string", "maxLength": MAX_TEXT},
                        "references": {"type": "array", "items": {"type": "string", "maxLength": MAX_TEXT}},
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
            "job_id", "tool_id", "target", "exit_code", "duration_s", "findings",
            "provider_id", "provider_version", "manifest_fingerprint",
            "registry_digest", "transport",
        ],
        "additionalProperties": False,
    },
    limitations=(
        "Connects only to TCP port 443 and checks one normalized hostname.",
        "The supervised child resolves once and connects only to returned numeric socket addresses.",
        "Certificate SAN names are informational and never extend engagement scope.",
        "A failed certificate verification may trigger one CERT_NONE retry to collect certificate details; it uses the same vetted numeric address and SNI.",
        "The operation does not follow redirects or accept caller-selected ports or resolver addresses.",
    ),
    scope_mode="pinned_network",
)


def _socket_connect(
    address: PinnedSocketAddress,
    hostname: str,
    context: ssl.SSLContext,
):
    """Connect only to a previously scope-checked numeric sockaddr."""
    raw = socket.socket(address.family, address.socktype, address.proto)
    raw.settimeout(CONNECT_TIMEOUT_S)
    try:
        raw.connect(address.sockaddr)
        return context.wrap_socket(raw, server_hostname=hostname)
    except BaseException:
        raw.close()
        raise


def _read_certificate(address: PinnedSocketAddress, hostname: str) -> tuple[dict[str, Any] | None, str]:
    """Verify TLS first, then optionally collect an invalid peer cert safely."""
    verified_context = ssl.create_default_context()
    try:
        with _socket_connect(address, hostname, verified_context) as tls:
            certificate = tls.getpeercert()
            if not isinstance(certificate, dict) or not certificate:
                raise ssl.SSLError("peer returned no decoded certificate")
            return certificate, ""
    except ssl.SSLCertVerificationError as exc:
        verification_error = f"{type(exc).__name__}: {exc}"[:MAX_TEXT]
        unverified_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified_context.check_hostname = False
        unverified_context.verify_mode = ssl.CERT_NONE
        try:
            with _socket_connect(address, hostname, unverified_context) as tls:
                certificate = tls.getpeercert()
                if not isinstance(certificate, dict) or not certificate:
                    certificate = None
                return certificate, verification_error
        except (OSError, ssl.SSLError, TimeoutError):
            # The verified handshake already established a certificate failure.
            # Keep that observation even when the best-effort detail retry fails.
            return None, verification_error


def _tls_cert_worker(conn: Connection, target: str, scope_path: str) -> None:
    """Resolve and check scope once in the bounded child, then connect by IP."""
    try:
        if not _valid_hostname(target) or target != target.lower().rstrip("."):
            _send_child_result(conn, {"status": "error", "error": "invalid normalized TLS hostname"})
            return
        scope = ScopeManager(Path(scope_path))
        resolution = scope.resolve_for_execution(target, port=443)
        if not resolution.allowed or not resolution.addresses:
            _send_child_result(conn, {
                "status": "scope_denied",
                "reason": str(resolution.reason or "pinned TLS scope denied")[:MAX_TEXT],
            })
            return
        certificate: dict[str, Any] | None = None
        verification_error = ""
        errors: list[str] = []
        for address in resolution.addresses:
            try:
                certificate, verification_error = _read_certificate(address, target)
                break
            except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
                errors.append(f"{type(exc).__name__}: {exc}"[:512])
        if certificate is None and not verification_error:
            _send_child_result(conn, {
                "status": "error",
                "error": ("TLS connection failed: " + "; ".join(errors))[:MAX_TEXT],
            })
            return
        _send_child_result(conn, {
            "status": "complete",
            "certificate": certificate,
            "verification_error": verification_error,
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


def _text(value: object, *, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        return ""
    return value[:limit]


def _cert_field(certificate: dict[str, Any], field: str) -> str:
    parts = certificate.get(field, ())
    if not isinstance(parts, (list, tuple)):
        return ""
    bits = []
    for group in parts:
        if not isinstance(group, (list, tuple)):
            continue
        for entry in group:
            if isinstance(entry, (list, tuple)) and len(entry) == 2:
                bits.append(f"{entry[0]}={entry[1]}")
    return ", ".join(bits)[:MAX_TEXT]


def _certificate_findings(
    certificate: dict[str, Any] | None, target: str, verification_error: str,
) -> list[Finding]:
    if not certificate and not verification_error:
        raise RuntimeError("TLS child returned no certificate")
    findings: list[Finding] = []
    if verification_error:
        error_prefix = f"cert verification failed for {target}: "
        error_detail = verification_error[: max(0, MAX_TEXT - len(error_prefix))]
        findings.append(Finding(
            kind="ssl_cert_invalid",
            severity="medium",
            source="recon:ssl",
            data={"host": target, "error": error_detail},
            raw_line=f"{error_prefix}{error_detail}",
            remediation="Use a certificate from a trusted CA and ensure the hostname matches.",
            impact="Certificate verification failure permits MITM if users ignore the warning.",
            cwe="CWE-295",
            cvss=5.9,
        ))
    if certificate is None:
        return findings
    sans = certificate.get("subjectAltName", ())
    if not isinstance(sans, (list, tuple)) or len(sans) > 512:
        raise RuntimeError("TLS child returned an invalid SAN collection")
    sanitized_sans: list[list[str]] = []
    discovered_hosts: list[str] = []
    for entry in sans:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise RuntimeError("TLS child returned a malformed SAN entry")
        kind, value = entry
        if not isinstance(kind, str) or not isinstance(value, str):
            raise RuntimeError("TLS child returned a malformed SAN value")
        kind, value = kind[:64], value[:MAX_TEXT]
        sanitized_sans.append([kind, value])
        if kind == "DNS" and _valid_hostname(value):
            hostname = value.lower().rstrip(".")
            if hostname != target and hostname not in discovered_hosts and len(discovered_hosts) < 12:
                discovered_hosts.append(hostname)
    subject = _cert_field(certificate, "subject")
    issuer = _cert_field(certificate, "issuer")
    data = {
        "host": target,
        "subject": subject,
        "issuer": issuer,
        "notBefore": _text(certificate.get("notBefore")),
        "notAfter": _text(certificate.get("notAfter")),
        "serialNumber": _text(certificate.get("serialNumber"), limit=256),
        "version": int(certificate.get("version", 0)) if type(certificate.get("version", 0)) is int else 0,
        "subjectAltName": sanitized_sans,
        "verified": not bool(verification_error),
    }
    findings.append(Finding(
        kind="ssl_cert",
        severity="info",
        source="recon:ssl",
        data=data,
        raw_line=f"TLS cert for {target}: issuer={issuer}",
    ))
    for hostname in discovered_hosts:
        findings.append(Finding(
            kind="recon_discovered_host",
            severity="info",
            source="recon:ssl",
            data={"host": hostname, "relation": "san", "from": target},
            raw_line=f"SAN on {target}: {hostname}",
            remediation=(
                "Review whether this host should be in scope. Add via the override "
                "log if authorised; do not auto-scan."
            ),
            impact="Additional hostname associated with the target via certificate SANs.",
        ))
    if len(findings) > 16:
        raise RuntimeError("TLS child returned too many SAN findings")
    return findings


def _decode_findings(value: object, target: str) -> list[Finding]:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise RuntimeError("TLS child returned an invalid finding list")
    result: list[Finding] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _FINDING_KEYS:
            raise RuntimeError("TLS child returned a malformed finding")
        kind = item.get("kind")
        if kind not in {"ssl_cert", "ssl_cert_invalid", "recon_discovered_host"}:
            raise RuntimeError("TLS child returned an unsupported finding")
        if item.get("source") != "recon:ssl" or not isinstance(item.get("data"), dict):
            raise RuntimeError("TLS child returned an invalid finding source or data")
        if not isinstance(item.get("raw_line"), str) or len(item["raw_line"]) > MAX_TEXT:
            raise RuntimeError("TLS child returned an invalid raw line")
        if not isinstance(item.get("remediation"), str) or len(item["remediation"]) > MAX_TEXT:
            raise RuntimeError("TLS child returned an invalid remediation")
        if not isinstance(item.get("impact"), str) or len(item["impact"]) > MAX_TEXT:
            raise RuntimeError("TLS child returned an invalid impact")
        if not isinstance(item.get("references"), list) or any(
            not isinstance(ref, str) or len(ref) > MAX_TEXT for ref in item["references"]
        ):
            raise RuntimeError("TLS child returned invalid references")
        data = item["data"]
        if kind == "ssl_cert":
            expected = {
                "host", "subject", "issuer", "notBefore", "notAfter", "serialNumber",
                "version", "subjectAltName", "verified",
            }
            if (
                set(data) != expected or data.get("host") != target
                or any(not isinstance(data.get(k), str) for k in (
                    "subject", "issuer", "notBefore", "notAfter", "serialNumber",
                ))
                or type(data.get("version")) is not int
                or type(data.get("verified")) is not bool
                or not isinstance(data.get("subjectAltName"), list)
                or item.get("severity") != "info"
                or item.get("raw_line") != f"TLS cert for {target}: issuer={data.get('issuer')}"
            ):
                raise RuntimeError("TLS child returned an invalid certificate finding")
        elif kind == "ssl_cert_invalid":
            if (
                set(data) != {"host", "error"} or data.get("host") != target
                or not isinstance(data.get("error"), str) or len(data["error"]) > MAX_TEXT
                or item.get("severity") != "medium"
                or item.get("raw_line") != f"cert verification failed for {target}: {data['error']}"
                or item.get("cwe") != "CWE-295"
                or item.get("cvss") != 5.9
                or item.get("remediation") != "Use a certificate from a trusted CA and ensure the hostname matches."
                or item.get("impact") != "Certificate verification failure permits MITM if users ignore the warning."
            ):
                raise RuntimeError("TLS child returned an invalid verification finding")
        else:
            hostname = data.get("host")
            if (
                set(data) != {"host", "relation", "from"}
                or not isinstance(hostname, str) or not _valid_hostname(hostname)
                or data.get("relation") != "san" or data.get("from") != target
                or item.get("severity") != "info"
                or item.get("raw_line") != f"SAN on {target}: {hostname}"
                or item.get("remediation") != (
                    "Review whether this host should be in scope. Add via the override "
                    "log if authorised; do not auto-scan."
                )
                or item.get("impact") != "Additional hostname associated with the target via certificate SANs."
            ):
                raise RuntimeError("TLS child returned an invalid informational SAN finding")
        result.append(Finding(
            kind=kind, severity=item["severity"], source=item["source"], data=data,
            raw_line=item["raw_line"], remediation=item["remediation"],
            impact=item["impact"], cvss=item.get("cvss"), cwe=item.get("cwe", ""),
            references=tuple(item["references"]),
            lookup_hint=item.get("lookup_hint", ""),
            request_context=item.get("request_context", {}),
        ))
    invalid = any(item.kind == "ssl_cert_invalid" for item in result)
    certs = [item for item in result if item.kind == "ssl_cert"]
    if len(certs) > 1:
        raise RuntimeError("TLS child returned duplicate certificate findings")
    if certs and certs[0].data["verified"] == invalid:
        raise RuntimeError("TLS child returned inconsistent certificate verification findings")
    if not certs and not invalid:
        raise RuntimeError("TLS child returned neither a certificate nor a verification failure")
    return result


class TlsCertificateProvider:
    """V2 provider for fixed-port, scope-pinned TLS certificate inspection."""

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

    def resolve_task(
        self, task: WorkflowTask, *, require_installed: bool = False,
    ) -> CapabilityResolution:
        if not isinstance(task, WorkflowTask) or task.capability_id != CAPABILITY_ID:
            raise CapabilityUnavailable(CAPABILITY_ID, ("task capability does not match provider",))
        target = task.target.lower().rstrip(".") if isinstance(task.target, str) else ""
        if not _valid_hostname(task.target) or task.target != target:
            raise CapabilityUnavailable(CAPABILITY_ID, ("target must be a normalized hostname",))
        if not isinstance(task.inputs, dict) or task.inputs:
            raise CapabilityUnavailable(CAPABILITY_ID, ("TLS task inputs must be empty",))
        if (
            task.impact != self._manifest.impact
            or set(task.permissions) != set(self._manifest.permissions)
        ):
            raise CapabilityUnavailable(CAPABILITY_ID, ("task permissions/impact differ from manifest",))
        resolution = self.registry.resolve(
            CAPABILITY_ID,
            CapabilityRequirements(
                target_type="hostname",
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
            raise CapabilityUnavailable(CAPABILITY_ID, ("TLS provider manifest fingerprint changed",))
        if require_installed and not self._readiness():
            raise CapabilityUnavailable(CAPABILITY_ID, ("TLS provider is unavailable",))
        return resolution

    def _persist_failure(self, job_id: str, message: str) -> None:
        try:
            self.store.append_line(job_id, "stderr", message[:MAX_TEXT])
            self.store.set_failed(job_id, message[:MAX_TEXT])
        except Exception:
            pass

    async def dispatch(self, task: WorkflowTask) -> dict[str, Any]:
        resolution = self.resolve_task(task, require_installed=True)
        job_id = uuid.uuid4().hex[:12]
        if self.store.get(job_id) is not None:
            raise RuntimeError("TLS evidence job id collision")
        self.store.create(job_id)
        if not self.store.set_started(job_id, CAPABILITY_ID, task.target):
            raise RuntimeError("could not start TLS evidence job")
        self.store.mark_engine_v2_execution_job(job_id)
        started = time.monotonic()
        child = _BoundedDnsWorker(
            task.target,
            str(self.scope.path.resolve()),
            min(float(task.timeout_s), self._manifest.timeout_s),
            worker_target=_tls_cert_worker,
        )
        try:
            try:
                payload = await asyncio.to_thread(child.run)
            except asyncio.CancelledError:
                child.request_termination()
                raise
            if payload.get("status") == "scope_denied":
                raise PermissionError("current scope denied the pinned TLS operation")
            if payload.get("status") != "complete" or set(payload) != {
                "status", "certificate", "verification_error",
            }:
                raise RuntimeError(str(payload.get("error", "invalid TLS child status"))[:MAX_TEXT])
            certificate = payload["certificate"]
            verification_error = payload["verification_error"]
            if (
                (certificate is not None and not isinstance(certificate, dict))
                or not isinstance(verification_error, str)
                or (certificate is None and not verification_error)
            ):
                raise RuntimeError("TLS child returned invalid certificate payload")
            findings = _certificate_findings(certificate, task.target, verification_error)
            validated = _decode_findings([item.to_dict() for item in findings], task.target)
            for seq, finding in enumerate(validated):
                if finding.raw_line:
                    self.store.append_line(job_id, "stdout", finding.raw_line)
                self.store.append_finding(job_id, finding, seq)
            persisted = self.store.get_findings(job_id)
            if not isinstance(persisted, list) or len(persisted) != len(validated):
                raise RuntimeError("TLS evidence findings did not persist completely")
            duration_s = time.monotonic() - started
            if not self.store.set_finished(job_id, 0, duration_s):
                raise RuntimeError("could not finish TLS evidence job")
        except asyncio.CancelledError:
            child.request_termination()
            await asyncio.to_thread(
                self._persist_failure, job_id,
                "CancelledError: child termination requested; external TLS outcome not confirmed",
            )
            raise
        except Exception as exc:
            await asyncio.to_thread(
                self._persist_failure, job_id, f"{type(exc).__name__}: {exc}"[:MAX_TEXT],
            )
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
            "target_types": ["hostname"],
            "registry_digest": self.registry.digest,
            "registered": True,
            "selected_for_execution": True,
            "installed": True,
            "executable": True,
            "readiness": "installed",
        }]
