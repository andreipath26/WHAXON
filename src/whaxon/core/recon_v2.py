"""Bounded Engine V2 provider for passive DNS record collection.

This module owns one fixed operation: query A, AAAA, MX, NS, TXT and SOA for
an in-scope hostname. The query set and inputs are not caller configurable.
Network lookup runs in a spawned child process so a stuck resolver can be
terminated without leaving a worker thread behind.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import multiprocessing
import re
import threading
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
from .scope import ScopeManager
from .workflow import WorkflowTask

CAPABILITY_ID = "dns.recon.passive"
PROVIDER_ID = "whaxon.recon.dns"
PROVIDER_VERSION = "1.0.2"
TRANSPORT = "isolated_process"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA")
PROCESS_TIMEOUT_S = 40.0
MAX_CHILD_OUTPUT_BYTES = 1_048_576
MAX_FINDINGS = 2048
MAX_TEXT = 8192
_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_FINDING_KEYS = {
    "kind", "severity", "source", "data", "raw_line", "remediation",
    "impact", "cvss", "cwe", "references", "lookup_hint", "request_context",
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
                        "kind": {"enum": ["dns_record", "recon_error"]},
                        "severity": {"const": "info"},
                        "source": {"const": "recon:dns"},
                        "data": {"type": "object"},
                        "raw_line": {"type": "string", "maxLength": MAX_TEXT},
                        "remediation": {"type": "string"},
                        "impact": {"type": "string"},
                        "cvss": {"type": ["number", "null"]},
                        "cwe": {"type": "string"},
                        "references": {"type": "array", "items": {"type": "string"}},
                        "lookup_hint": {"type": "string"},
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
        "Queries only A, AAAA, MX, NS, TXT and SOA through the configured resolver.",
        "Hostname targets only; no caller-supplied DNS record types or resolver addresses.",
        "Resolver work is terminated when the bounded child-process deadline expires.",
        "Child IPC output is capped at 1 MiB; larger result batches fail closed.",
        "DNS answers are observations, not proof of service availability or ownership.",
    ),
)


def _valid_hostname(value: object) -> bool:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or len(value) > 253 or not value.isascii()
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
        or any(char in value for char in "/?#@:\\[]")
    ):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    # A single terminal dot is a valid absolute DNS name. Stripping every dot
    # would silently accept malformed names such as ``example.com..``.
    hostname = value[:-1] if value.endswith(".") else value
    labels = hostname.split(".")
    return bool(labels) and all(_LABEL.fullmatch(label) for label in labels)


def _send_child_result(conn: Connection, payload: dict[str, Any]) -> None:
    encoded = json.dumps(
        payload, ensure_ascii=False, allow_nan=False,
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_CHILD_OUTPUT_BYTES:
        payload = {"status": "error", "error": "child output exceeded the configured limit"}
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    conn.send_bytes(encoded)


def _dns_worker(conn: Connection, target: str, scope_path: str) -> None:
    """Child entry point. Check fresh scope before starting any DNS query."""
    try:
        scope = ScopeManager(Path(scope_path))
        # This operation queries the configured DNS resolver for the target's
        # records; it does not connect to the resolved target address. Use the
        # normal target scope decision here, while the supervised process
        # bounds the hostname-resolution work that scope.check may perform.
        match = scope.check(target)
        if not match.allowed:
            _send_child_result(conn, {
                "status": "scope_denied",
                "reason": str(match.reason or "scope denied")[:MAX_TEXT],
            })
            return
        from .recon_checks import check_dns

        findings = check_dns(target)
        if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
            _send_child_result(conn, {"status": "error", "error": "invalid DNS finding collection"})
            return
        _send_child_result(conn, {
            "status": "complete",
            "findings": [item.to_dict() if isinstance(item, Finding) else item for item in findings],
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


class _BoundedDnsWorker:
    """Own a child process that can be stopped when its async caller cancels."""

    def __init__(
        self, target: str, scope_path: str, timeout_s: float, *,
        worker_target=None,
    ) -> None:
        self.target = target
        self.scope_path = scope_path
        self.timeout_s = timeout_s
        self.worker_target = worker_target or _dns_worker
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
            name="whaxon-v2-dns-recon",
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
                raise RuntimeError("passive DNS child cancelled before dispatch")
            remaining = max(0.0, self.timeout_s - (time.monotonic() - started_at))
            if not parent_conn.poll(remaining):
                raise TimeoutError("passive DNS child exceeded its hard deadline")
            raw = parent_conn.recv_bytes(MAX_CHILD_OUTPUT_BYTES)
            remaining = max(0.0, self.timeout_s - (time.monotonic() - started_at))
            process.join(timeout=min(0.5, remaining))
            if process.is_alive():
                raise RuntimeError("DNS child sent a result but did not exit")
            if process.exitcode != 0:
                raise RuntimeError("DNS child exited unsuccessfully")
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("DNS child returned malformed JSON") from exc
            if not isinstance(payload, dict):
                raise RuntimeError("DNS child returned a non-object result")
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


def _decode_findings(value: object, target: str) -> list[Finding]:
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise RuntimeError("DNS child returned an invalid finding list")
    decoded: list[Finding] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _FINDING_KEYS:
            raise RuntimeError("DNS child returned a malformed finding")
        if (
            not isinstance(item.get("kind"), str)
            or item.get("kind") not in {"dns_record", "recon_error"}
            or item.get("severity") != "info"
            or item.get("source") != "recon:dns"
            or not isinstance(item.get("data"), dict)
            or not isinstance(item.get("raw_line"), str)
            or len(item["raw_line"]) > MAX_TEXT
            or not isinstance(item.get("remediation"), str)
            or not isinstance(item.get("impact"), str)
            or not isinstance(item.get("cwe"), str)
            or not isinstance(item.get("lookup_hint"), str)
            or not isinstance(item.get("references"), list)
            or any(not isinstance(ref, str) or len(ref) > MAX_TEXT for ref in item["references"])
            or not isinstance(item.get("request_context"), dict)
        ):
            raise RuntimeError("DNS child returned an invalid finding contract")
        data = item["data"]
        rtype = data.get("record_type")
        if rtype not in RECORD_TYPES:
            raise RuntimeError("DNS child returned an unsupported record type")
        if item["kind"] == "dns_record":
            if (
                set(data) != {"record_type", "value", "host"}
                or data.get("host") != target
                or not isinstance(data.get("value"), str)
                or len(data["value"]) > MAX_TEXT
                or item["raw_line"] != f"{target} {rtype} {data.get('value')}"
            ):
                raise RuntimeError("DNS child returned an invalid record observation")
        elif (
            set(data) != {"record_type", "error", "target"}
            or data.get("target") != target
            or not isinstance(data.get("error"), str)
            or len(data["error"]) > MAX_TEXT
            or not item["raw_line"].startswith(f"dns {rtype} {target} failed: ")
        ):
            raise RuntimeError("DNS child returned an invalid record error")
        cvss = item.get("cvss")
        if (
            cvss is not None or item["remediation"] or item["impact"] or item["cwe"]
            or item["references"] or item["lookup_hint"] or item["request_context"]
        ):
            raise RuntimeError("DNS child returned fields outside the record contract")
        decoded.append(Finding(
            kind=item["kind"], severity=item["severity"], source=item["source"],
            data=data, raw_line=item["raw_line"], remediation=item["remediation"],
            impact=item["impact"], cvss=cvss, cwe=item["cwe"],
            references=tuple(item["references"]), lookup_hint=item["lookup_hint"],
            request_context=item["request_context"],
        ))
    return decoded


class PassiveDnsReconProvider:
    """V2 provider for the fixed passive DNS record-query contract."""

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
            raise RuntimeError("DNS evidence findings did not persist completely")
        duration_s = time.monotonic() - started
        if not self.store.set_finished(job_id, 0, duration_s):
            raise RuntimeError("could not finish DNS evidence job")
        return duration_s, persisted

    def resolve_task(
        self, task: WorkflowTask, *, require_installed: bool = False,
    ) -> CapabilityResolution:
        if not isinstance(task, WorkflowTask) or task.capability_id != CAPABILITY_ID:
            raise CapabilityUnavailable(CAPABILITY_ID, ("task capability does not match provider",))
        if not isinstance(task.inputs, dict) or task.inputs:
            raise CapabilityUnavailable(CAPABILITY_ID, ("DNS task inputs must be empty",))
        if task.impact != self._manifest.impact or set(task.permissions) != set(self._manifest.permissions):
            raise CapabilityUnavailable(CAPABILITY_ID, ("task permissions/impact differ from manifest",))
        if not _valid_hostname(task.target):
            raise CapabilityUnavailable(CAPABILITY_ID, ("target must be a normalized hostname",))
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
            raise CapabilityUnavailable(CAPABILITY_ID, ("provider manifest fingerprint changed",))
        if require_installed and not self._readiness():
            raise CapabilityUnavailable(CAPABILITY_ID, ("dnspython is not installed",))
        return resolution

    async def dispatch(self, task: WorkflowTask) -> dict[str, Any]:
        resolution = self.resolve_task(task, require_installed=True)
        job_id = uuid.uuid4().hex[:12]
        if self.store.get(job_id) is not None:
            raise RuntimeError("DNS evidence job id collision")
        self.store.create(job_id)
        if not self.store.set_started(job_id, CAPABILITY_ID, task.target):
            raise RuntimeError("could not start DNS evidence job")
        # Persist ownership before the child can perform a scope lookup or DNS query.
        self.store.mark_engine_v2_execution_job(job_id)
        started = time.monotonic()
        child = _BoundedDnsWorker(
            task.target, str(self.scope.path.resolve()),
            min(float(task.timeout_s), self._manifest.timeout_s),
        )
        try:
            try:
                payload = await asyncio.to_thread(child.run)
            except asyncio.CancelledError:
                child.request_termination()
                raise
            if payload.get("status") == "scope_denied":
                raise PermissionError("current scope denied the DNS operation")
            if payload.get("status") != "complete" or set(payload) != {"status", "findings"}:
                error = payload.get("error", "invalid DNS child status")
                raise RuntimeError(str(error)[:MAX_TEXT])
            findings = _decode_findings(payload["findings"], task.target)
            duration_s, persisted = await asyncio.to_thread(
                self._persist_findings, job_id, findings, started,
            )
        except asyncio.CancelledError:
            child.request_termination()
            await asyncio.to_thread(
                self._persist_failure, job_id,
                "CancelledError: child process termination requested; external DNS outcome not confirmed",
            )
            raise
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"[:MAX_TEXT]
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
        installed = self._readiness()
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
            "installed": installed,
            "executable": installed,
            "readiness": "installed" if installed else "registered",
        }]
