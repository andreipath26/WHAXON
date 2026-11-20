"""Fixed, bounded Engine V2 HTTPS reconnaissance for an authorized target.

One pinned HTTPS GET to the root path supplies headers for the legacy header,
technology, cookie and WAF observations. It never follows redirects or falls
back to HTTP. DNS resolution and TLS/network activity run inside a killable
child process.
"""
from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import multiprocessing
import socket
import ssl
import threading
import time
import unicodedata
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
from .recon_checks import (
    _COOKIE_FLAG_KNOWLEDGE,
    _MISSING_HEADER_KNOWLEDGE,
    _TECH_MARKERS,
    _WAF_FINGERPRINTS,
    _version_from,
)
from .recon_v2 import _valid_hostname
from .scope import PinnedSocketAddress, ScopeManager
from .workflow import WorkflowTask

CAPABILITY_ID = "web.recon.passive"
PROVIDER_ID = "whaxon.recon.https"
PROVIDER_VERSION = "1.0.0"
TRANSPORT = "isolated_process"
PROCESS_TIMEOUT_S = 40.0
CONNECT_TIMEOUT_S = 8.0
MAX_CHILD_OUTPUT_BYTES = 1_048_576
MAX_FINDINGS = 2048
MAX_TEXT = 8192
MAX_RESPONSE_HEADERS = 100
MAX_RESPONSE_HEADER_BYTES = 65_536
_ALLOWED_KINDS = {
    "http_header_missing",
    "tech_detected",
    "open_port",
    "cookie_insecure",
    "waf_detected",
    "recon_error",
}
_ALLOWED_SOURCES = {
    "recon:headers", "recon:tech", "recon:cookies", "recon:waf", "recon:https",
}
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
                        "source": {"enum": sorted(_ALLOWED_SOURCES)},
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
        "One fixed GET / request over HTTPS port 443; no redirect following or HTTP fallback.",
        "The child resolves the target once, scope-checks every address, then connects only to returned numeric addresses.",
        "TLS certificate verification and hostname validation use the standard trust store.",
        "Only response headers are inspected; response bodies are not read.",
        "Response headers are capped at 100 fields and 64 KiB total; child output is capped at 1 MiB.",
        "Observations describe the root response only and do not establish service ownership.",
    ),
)


def _valid_target(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        return False
    try:
        address = ipaddress.ip_address(value)
        return value == address.compressed
    except ValueError:
        return _valid_hostname(value)


def _safe_text(value: object, limit: int = MAX_TEXT) -> str:
    """Escape terminal-active and invisible Unicode controls before persistence."""
    output: list[str] = []
    length = 0
    for char in str(value):
        category = unicodedata.category(char)
        codepoint = ord(char)
        if category in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            if codepoint < 0x20 or codepoint == 0x7F:
                visible = f"\\x{codepoint:02x}"
            elif codepoint <= 0xFFFF:
                visible = f"\\u{codepoint:04x}"
            else:
                visible = f"\\U{codepoint:08x}"
        else:
            visible = char
        if length + len(visible) > limit:
            break
        output.append(visible)
        length += len(visible)
    return "".join(output)


def _response_url(host: str) -> str:
    authority = f"[{host}]" if ":" in host else host
    return f"https://{authority}/"


def _finding_error(target: str, message: str) -> Finding:
    return Finding(
        kind="recon_error",
        severity="info",
        source="recon:https",
        data={"target": target, "error": _safe_text(message)},
        raw_line=_safe_text(f"https GET {target} failed: {message}"),
    )


def _checked_headers(headers: object) -> list[tuple[str, str]]:
    if not isinstance(headers, list) or len(headers) > MAX_RESPONSE_HEADERS:
        raise ValueError("HTTPS response exceeded the header count limit")
    checked: list[tuple[str, str]] = []
    total = 0
    for item in headers:
        if (
            not isinstance(item, tuple) or len(item) != 2
            or not isinstance(item[0], str) or not isinstance(item[1], str)
        ):
            raise ValueError("HTTPS response contained malformed headers")
        name, value = item
        total += len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4
        if len(name) > 1024 or len(value) > MAX_RESPONSE_HEADER_BYTES:
            raise ValueError("HTTPS response contained an oversized header")
        if total > MAX_RESPONSE_HEADER_BYTES:
            raise ValueError("HTTPS response exceeded the aggregate header limit")
        checked.append((name, value))
    return checked


def _collect_findings(target: str, host: str, headers: list[tuple[str, str]]) -> list[Finding]:
    url = _response_url(host)
    normalized = {key.lower(): value for key, value in headers}
    cookies = [value for key, value in headers if key.lower() == "set-cookie"]
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

    for raw in (normalized.get("server", ""), normalized.get("x-powered-by", "")):
        if not raw:
            continue
        raw_l = raw.lower()
        for marker, canonical in _TECH_MARKERS:
            if marker not in raw_l:
                continue
            version = _version_from(raw_l, marker)
            findings.append(Finding(
                kind="tech_detected",
                severity="info",
                source="recon:tech",
                data={"product": canonical, "banner": _safe_text(raw, 2048),
                      "url": url, "version": version},
                raw_line=_safe_text(f"{url}: {raw}"),
                lookup_hint=_safe_text(f"{canonical} {version}".strip()),
            ))
            if version:
                findings.append(Finding(
                    kind="open_port",
                    severity="info",
                    source="recon:tech",
                    data={
                        "port": 443, "protocol": "tcp", "state": "open",
                        "service": canonical, "version": _safe_text(raw, 2048),
                    },
                    raw_line=_safe_text(f"443/tcp open  https   {raw}"),
                ))
            break

    for raw in cookies:
        parts = [part.strip() for part in raw.split(";") if part.strip()]
        if not parts:
            continue
        name = _safe_text(parts[0].split("=", 1)[0].strip(), 128)
        attrs = {part.split("=", 1)[0].strip().lower() for part in parts[1:]}
        for flag, knowledge in _COOKIE_FLAG_KNOWLEDGE.items():
            if flag in attrs:
                continue
            findings.append(Finding(
                kind="cookie_insecure",
                severity=knowledge["severity"],
                source="recon:cookies",
                data={
                    "url": url, "cookie": name, "missing": flag,
                    "raw": _safe_text(raw, 500),
                },
                raw_line=_safe_text(f"{url}: cookie '{name}' missing {flag}"),
                remediation=_safe_text(knowledge["remediation"]),
                impact=_safe_text(knowledge["impact"]),
                cwe=_safe_text(knowledge["cwe"]),
                cvss=knowledge["cvss"],
            ))

    cookie_blob = " ".join(cookies).lower()
    for name, header_rules, cookie_subs in _WAF_FINGERPRINTS:
        evidence: list[str] = []
        for header_key, value_sub in header_rules:
            value = normalized.get(header_key)
            if value is None:
                continue
            if value_sub == "":
                evidence.append(f"header {header_key}")
            elif value_sub in value.lower():
                evidence.append(f"header {header_key}~{value_sub}")
        for substring in cookie_subs:
            if substring in cookie_blob:
                evidence.append(f"cookie {substring}")
        if evidence:
            findings.append(Finding(
                kind="waf_detected",
                severity="info",
                source="recon:waf",
                data={"url": url, "waf": _safe_text(name, 128),
                      "evidence": evidence[:32]},
                raw_line=_safe_text(
                    f"{url}: WAF/CDN detected -> {name} ({', '.join(evidence[:32])})",
                ),
                remediation=(
                    "No action required. Record the observed WAF/CDN because it "
                    "may affect authorized testing behavior."
                ),
                impact=(
                    "A WAF/CDN may filter requests and can change the behavior "
                    "of authorized tests."
                ),
            ))
    if len(findings) > MAX_FINDINGS:
        raise ValueError("HTTPS recon produced too many findings")
    return findings


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials only scope-vetted numeric socket addresses."""

    def __init__(
        self,
        host: str,
        addresses: tuple[PinnedSocketAddress, ...],
        *,
        timeout: float,
        context: Any | None = None,
        socket_factory=None,
    ) -> None:
        tls_context = context or ssl.create_default_context()
        super().__init__(
            host=host,
            port=443,
            timeout=timeout,
            context=tls_context,
        )
        self._tls_context = tls_context
        self._pinned_addresses = addresses
        self._socket_factory = socket_factory or socket.socket

    def connect(self) -> None:
        last_error: OSError | None = None
        for address in self._pinned_addresses:
            raw = self._socket_factory(
                address.family, address.socktype, address.proto,
            )
            try:
                raw.settimeout(self.timeout)
                raw.connect(address.sockaddr)
                self.sock = self._tls_context.wrap_socket(
                    raw, server_hostname=self.host,
                )
                return
            except (OSError, ssl.SSLError) as exc:
                last_error = exc
                try:
                    raw.close()
                except OSError:
                    pass
        if last_error is not None:
            raise last_error
        raise OSError("scope returned no vetted HTTPS socket addresses")


def _send_child_result(conn: Connection, payload: dict[str, Any]) -> None:
    encoded = json.dumps(
        payload, ensure_ascii=False, allow_nan=False,
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_CHILD_OUTPUT_BYTES:
        encoded = json.dumps({
            "status": "error",
            "error": "child output exceeded the configured limit",
        }, separators=(",", ":")).encode("utf-8")
    conn.send_bytes(encoded)


def _https_worker(conn: Connection, target: str, scope_path: str) -> None:
    try:
        if not _valid_target(target):
            _send_child_result(conn, {"status": "error", "error": "invalid HTTPS target"})
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
            host,
            resolution.addresses,
            timeout=CONNECT_TIMEOUT_S,
        )
        try:
            host_header = f"[{host}]" if ":" in host else host
            connection.request(
                "GET",
                "/",
                headers={
                    "Host": host_header,
                    "User-Agent": "WHAXON-recon/2.0",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            status = int(response.status)
            headers = _checked_headers(response.getheaders())
            findings = _collect_findings(target, host, headers)
            if status < 200 or status >= 300:
                findings.append(_finding_error(
                    target, f"HTTPS returned status {status}",
                ))
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


def _terminate_process(process) -> None:
    try:
        if process.pid is None:
            return
        if not process.is_alive():
            process.join(timeout=0)
            return
    except (AssertionError, ValueError):
        return
    process.terminate()
    process.join(timeout=1.0)
    if process.is_alive():
        kill = getattr(process, "kill", None)
        if callable(kill):
            kill()
        else:
            process.terminate()
        process.join(timeout=1.0)


class _BoundedHttpsWorker:
    def __init__(self, target: str, scope_path: str, timeout_s: float, *, worker_target=None) -> None:
        self.target = target
        self.scope_path = scope_path
        self.timeout_s = timeout_s
        self.worker_target = worker_target or _https_worker
        self._lock = threading.Lock()
        self._process: Any = None
        self._started = False
        self._cancel_requested = False

    def request_termination(self) -> None:
        with self._lock:
            self._cancel_requested = True
            process = self._process
            started = self._started
        if process is not None and started:
            try:
                if process.is_alive():
                    process.terminate()
            except (AssertionError, OSError, ValueError):
                pass

    def run(self) -> dict[str, Any]:
        context = multiprocessing.get_context("spawn")
        parent_conn, child_conn = context.Pipe(duplex=False)
        process = context.Process(
            target=self.worker_target,
            args=(child_conn, self.target, self.scope_path),
            name="whaxon-v2-https-recon",
            daemon=True,
        )
        with self._lock:
            self._process = process
        started_at = time.monotonic()
        try:
            process.start()
            with self._lock:
                self._started = True
                cancelled = self._cancel_requested
            child_conn.close()
            if cancelled:
                process.terminate()
                raise RuntimeError("HTTPS child cancelled before dispatch")
            remaining = max(0.0, self.timeout_s - (time.monotonic() - started_at))
            if not parent_conn.poll(remaining):
                raise TimeoutError("HTTPS child exceeded its hard deadline")
            raw = parent_conn.recv_bytes(MAX_CHILD_OUTPUT_BYTES)
            remaining = max(0.0, self.timeout_s - (time.monotonic() - started_at))
            process.join(timeout=min(0.5, remaining))
            if process.is_alive():
                raise RuntimeError("HTTPS child sent a result but did not exit")
            if process.exitcode != 0:
                raise RuntimeError("HTTPS child exited unsuccessfully")
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("HTTPS child returned malformed JSON") from exc
            if not isinstance(payload, dict):
                raise RuntimeError("HTTPS child returned a non-object result")
            return payload
        finally:
            parent_conn.close()
            try:
                child_conn.close()
            except OSError:
                pass
            _terminate_process(process)
            with self._lock:
                self._process = None
                self._started = False


def _decode_findings(value: object) -> list[Finding]:
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise RuntimeError("HTTPS child returned an invalid finding list")
    findings: list[Finding] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _FINDING_KEYS:
            raise RuntimeError("HTTPS child returned a malformed finding")
        if (
            item.get("kind") not in _ALLOWED_KINDS
            or item.get("severity") not in {"info", "low", "medium"}
            or item.get("source") not in _ALLOWED_SOURCES
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
            raise RuntimeError("HTTPS child returned an invalid finding contract")
        findings.append(Finding(**item))
    return findings


class PassiveHttpsReconProvider:
    """V2 provider for one fixed, scope-pinned HTTPS root response."""

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
            raise RuntimeError("HTTPS evidence findings did not persist completely")
        duration_s = time.monotonic() - started
        if not self.store.set_finished(job_id, 0, duration_s):
            raise RuntimeError("could not finish HTTPS evidence job")
        return duration_s, persisted

    def resolve_task(
        self, task: WorkflowTask, *, require_installed: bool = False,
    ) -> CapabilityResolution:
        if not isinstance(task, WorkflowTask) or task.capability_id != CAPABILITY_ID:
            raise CapabilityUnavailable(CAPABILITY_ID, ("task capability does not match provider",))
        if not isinstance(task.inputs, dict) or task.inputs:
            raise CapabilityUnavailable(CAPABILITY_ID, ("HTTPS recon inputs must be empty",))
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
            raise CapabilityUnavailable(CAPABILITY_ID, ("HTTPS transport is not ready",))
        return resolution

    async def dispatch(self, task: WorkflowTask) -> dict[str, Any]:
        resolution = self.resolve_task(task, require_installed=True)
        job_id = uuid.uuid4().hex[:12]
        if self.store.get(job_id) is not None:
            raise RuntimeError("HTTPS evidence job id collision")
        self.store.create(job_id)
        if not self.store.set_started(job_id, CAPABILITY_ID, task.target):
            raise RuntimeError("could not start HTTPS evidence job")
        self.store.mark_engine_v2_execution_job(job_id)
        started = time.monotonic()
        child = _BoundedHttpsWorker(
            task.target,
            str(self.scope.path.resolve()),
            min(float(task.timeout_s), self._manifest.timeout_s),
        )
        try:
            try:
                payload = await asyncio.to_thread(child.run)
            except asyncio.CancelledError:
                child.request_termination()
                raise
            if payload.get("status") == "scope_denied":
                raise PermissionError("current scope denied the HTTPS operation")
            if payload.get("status") != "complete" or set(payload) != {"status", "findings"}:
                raise RuntimeError(str(payload.get("error", "invalid HTTPS child status"))[:MAX_TEXT])
            findings = _decode_findings(payload["findings"])
            duration_s, persisted = await asyncio.to_thread(
                self._persist_findings, job_id, findings, started,
            )
        except asyncio.CancelledError:
            child.request_termination()
            await asyncio.to_thread(
                self._persist_failure, job_id,
                "CancelledError: child process termination requested; HTTPS outcome not confirmed",
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
