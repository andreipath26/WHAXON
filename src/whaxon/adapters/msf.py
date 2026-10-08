"""Metasploit adapter — runs modules via RPC and produces findings.

Tool IDs have the form:

    msf:exploit:<module_path>      e.g. msf:exploit:windows/smb/ms17_010_eternalblue
    msf:auxiliary:<module_path>    e.g. msf:auxiliary:scanner/smb/smb_version
    msf:post:<module_path>         e.g. msf:post/windows/gather/hashdump

Arguments are supplied as key=value pairs in extra_args, one per space:
    RHOSTS=10.0.0.5 RPORT=445 LHOST=10.0.0.1
"""
from __future__ import annotations

import re
import shlex

from ..core.findings import Finding
from ..core.msf import MSFClient, MSFUnavailableError
from .base import Adapter
from .registry import register


def _record_pivot(store, parent_job_id, session_id, via_exploit):
    """Best-effort: write a pivot edge from the exploit job to the new session."""
    try:
        from ..core import pivot
        conn = store._conn()
        pivot.add_edge(conn, parent_kind="exploit", parent_id=str(parent_job_id or "?"), child_kind="session", child_id=str(session_id), relation="from_exploit", evidence=str(via_exploit or ""))
        try: conn.close()
        except Exception: pass
    except Exception:
        pass
from .msf_parsers import parse_loot

_MODULE_RE = re.compile(r"^msf:(?P<type>exploit|auxiliary|post):(?P<path>.+)$")


# Modules auto-run against a fresh session when WHAXON_MSF_AUTOCHAIN=1.
_AUTOCHAIN = [
    "multi/gather/env",
    "post/linux/gather/enum_system",
    "post/linux/gather/enum_network",
]


def _autochain_enabled() -> bool:
    import os
    return os.environ.get("WHAXON_MSF_AUTOCHAIN", "").strip() in ("1", "true", "yes")


def parse_msf_tool_id(tool_id: str) -> tuple[str, str] | None:
    """Return (module_type, module_path) or None if not an msf tool id."""
    m = _MODULE_RE.match(tool_id)
    if not m:
        return None
    return m.group("type"), m.group("path")


def parse_kv_args(extra_args: str) -> dict:
    """Parse 'RHOSTS=1.2.3.4 RPORT=445' into {'RHOSTS': '1.2.3.4', 'RPORT': '445'}."""
    out: dict = {}
    if not extra_args:
        return out
    try:
        tokens = shlex.split(extra_args)
    except ValueError:
        tokens = extra_args.split()
    for tok in tokens:
        if "=" not in tok:
            continue
        k, _, v = tok.partition("=")
        out[k.strip()] = v.strip()
    return out


class MsfAdapter(Adapter):
    tool_id = "msf"

    def __init__(self, client: MSFClient | None = None) -> None:
        self._client = client or MSFClient()
        self._store = getattr(client, "store", None) if client else None

    def parse(self, lines, ctx=None):
        """MSF findings are produced from the RPC response, not from stdout.

        The web/CLI layer calls `run_module()` directly; this parse()
        method is a no-op for streamed output (used only by the runner's
        fallback path). Real findings come from `run_module()` below.
        """
        return []

    def run_module(self, tool_id: str, extra_args: str, ctx: dict | None = None) -> list[Finding]:
        """Execute the module and return findings for the result."""
        parsed = parse_msf_tool_id(tool_id)
        if parsed is None:
            raise ValueError(f"not an msf tool id: {tool_id}")
        module_type, module_path = parsed
        options = parse_kv_args(extra_args)

        ctx = ctx or {}
        target = ctx.get("target") or options.get("RHOSTS") or options.get("RHOST") or ""

        findings: list[Finding] = []

        try:
            self._client.connect()
        except MSFUnavailableError as e:
            findings.append(Finding(
                kind="msf_error",
                severity="info",
                source="msf",
                data={"error": str(e), "module": module_path, "target": target},
                raw_line=f"MSF unavailable: {e}",
                remediation="Start msfrpcd or set WHAXON_MSF_HOST/PORT/USER/PASS.",
                impact="Cannot execute Metasploit modules without the RPC daemon.",
            ))
            return findings

        # Run the module
        try:
            _opts = dict(options or {})
            _payload = _opts.pop("PAYLOAD", None)
            result = self._client.execute(module_type, module_path, _opts, payload=_payload)
        except Exception as e:
            findings.append(Finding(
                kind="msf_error",
                severity="info",
                source="msf",
                data={"error": str(e), "module": module_path, "target": target},
                raw_line=f"module error: {e}",
            ))
            return findings

        # Result is a dict with 'job_id' and/or 'uuid'
        job_id = result.get("job_id")
        if not job_id:
            findings.append(Finding(
                kind="msf_error",
                severity="low",
                source="msf",
                data={"console_output": (result.get("console_output") or "")[-2000:],
                      "module": module_path, "target": target},
                raw_line=f"module did not start: {module_path}",
                remediation="Inspect console_output; check payload compatibility and options.",
                impact="Module was not executed as a job.",
            ))
            return findings
        job_id = str(job_id)
        findings.append(Finding(
            kind="msf_module_started",
            severity="info",
            source="msf",
            data={
                "module_type": module_type,
                "module_path": module_path,
                "target": target,
                "job_id": str(job_id),
                "options": options,
            },
            raw_line=f"started {module_type}/{module_path} job={job_id}",
            remediation="Monitor for a new session. If no session opens, the target may be patched.",
            impact="Module executed. Session creation depends on the target being vulnerable.",
        ))

        # Structured loot from console output (per-module parsers)
        for item in parse_loot(module_path, result.get("console_output", "")):
            findings.append(Finding(
                kind=item.get("kind", "msf_loot"),
                severity="info",
                source="msf",
                data={**item.get("data", {}), "module": module_path},
                raw_line=item.get("raw", "")[:200],
            ))

        # Look for a session that was created by this module
        # (Metasploit may take time; the tracker will pick it up separately)
        try:
            sessions = self._client.sessions()
        except Exception:
            sessions = {}

        for sid, info in sessions.items():
            try:
                via_exploit = (info.get("via_exploit") or "").replace("exploit/", "", 1)
                via_payload = (info.get("via_payload") or "").replace("payload/", "", 1)
                if via_exploit and via_exploit != module_path:
                    continue
                if _payload and via_payload and via_payload != _payload:
                    continue
            except Exception:
                pass
            host = (info.get("target_host")
                    or info.get("tunnel_peer")
                    or options.get("RHOSTS")
                    or target)
            stype = info.get("type") or module_type
            try:
                _record_pivot(ctx.get("store"), ctx.get("job_id"), sid, info.get("via_exploit") or module_path)
            except Exception:
                pass
            findings.append(Finding(
                kind="msf_session",
                severity="critical",
                source="msf",
                data={
                    "session_id": sid,
                    "host": host,
                    "session_type": stype,
                    "info": info,
                    "module": module_path,
                },
                raw_line=f"session {sid} opened on {host}",
                remediation=(
                    "A foothold has been established. Enumerate the session, "
                    "collect evidence, and pivot according to the engagement scope."
                ),
                impact=(
                    "Full remote access via Metasploit session. Treat as a "
                    "critical compromise of the target."
                ),
                cvss=10.0,
                cwe="CWE-284",
            ))

        # Auto-chain profiling modules against any new session (opt-in)
        if _autochain_enabled() and module_type == "exploit":
            new_sids = [sid for sid, info in sessions.items()
                        if (info.get("via_exploit") or "").replace("exploit/", "", 1) == module_path]
            for sid in new_sids:
                for m in _AUTOCHAIN:
                    try:
                        chain_result = self._client.execute("post", m, {"SESSION": str(sid)})
                        # harvest loot from the chained run into this job
                        for item in parse_loot(m, chain_result.get("console_output", "")):
                            findings.append(Finding(
                                kind=item.get("kind", "msf_loot"),
                                severity="info",
                                source="msf",
                                data={**item.get("data", {}),
                                      "module": m, "session_id": str(sid)},
                                raw_line=item.get("raw", "")[:200],
                            ))
                        findings.append(Finding(
                            kind="msf_chain",
                            severity="info",
                            source="msf",
                            data={"module": m, "session_id": str(sid)},
                            raw_line=f"chained {m} on session {sid}",
                        ))
                    except Exception as e:
                        findings.append(Finding(
                            kind="msf_chain_error",
                            severity="low",
                            source="msf",
                            data={"module": m, "session_id": str(sid), "error": str(e)},
                            raw_line=f"chain failed: {m} on {sid}: {e}",
                        ))

        return findings


register(MsfAdapter())
