"""Executes external tools, streams output through the event bus."""
from __future__ import annotations

import asyncio
import os
import shlex
import signal
import time
import uuid
from collections.abc import Sequence
from pathlib import Path

from .events import (
    EventBus,
    JobFailed,
    JobFindings,
    JobFinished,
    JobOutput,
    JobStarted,
)
from .scope import OutOfScopeError


class _NullVulnDB:
    """A vulndb that has no records. Used when no vulndb is configured,
    so resolve() still annotates every finding with severity_source."""

    def lookup(self, cve_id):
        return None


class ToolRunner:
    def __init__(self, bus: EventBus, catalog=None, scope=None, route_resolver=None, vulndb=None) -> None:
        self._bus = bus
        self._catalog = catalog
        self._scope = scope  # optional ScopeManager
        self._route_resolver = route_resolver  # optional callable(target_host) -> Route | None
        self._vulndb = vulndb  # optional VulnDB, used to resolve severity from CVSS
        self._session_lookup = None
        self._procs: dict[str, asyncio.subprocess.Process] = {}
        self._lines_by_job: dict[str, list[tuple[str, str]]] = {}

    def _resolve_findings(self, findings):
        """Run each finding through the severity resolver. Returns a list
        of dicts (the shape the store expects). Annotations are always set,
        including severity_source, even when no vulndb is configured."""
        from .severity import resolve
        db = self._vulndb if self._vulndb is not None else _NullVulnDB()
        out = []
        for f in findings:
            try:
                out.append(resolve(f, db))
            except Exception:
                out.append(f.to_dict() if hasattr(f, "to_dict") else f)
        return out

    def bind_catalog(self, catalog) -> None:
        """Wire the catalog after construction (Core does this)."""
        self._catalog = catalog

    def bind_session_lookup(self, lookup) -> None:
        """Bind persisted session metadata used for dispatch-time authorization."""
        self._session_lookup = lookup

    def _check_execution_scope(self, target: str):
        if self._scope is None:
            return None
        checker = getattr(self._scope, "check_for_execution", None)
        if callable(checker):
            return checker(target)
        return self._scope.check(target)

    @staticmethod
    def _session_host(value: object) -> str:
        """Extract a host from an MSF peer/host field without retaining its port."""
        host = str(value or "").strip()
        if host.startswith("[") and "]" in host:
            return host[1:host.index("]")]
        if host.count(":") == 1:
            name, port = host.rsplit(":", 1)
            if port.isdigit():
                return name
        return host

    @classmethod
    def _canonical_session_host(cls, value: object) -> str:
        """Normalize a persisted/live session host for identity comparison."""
        import ipaddress

        host = cls._session_host(value).lower().rstrip(".")
        try:
            return ipaddress.ip_address(host).compressed
        except ValueError:
            return host

    def _authorize_session_host(self, value: object, *, source: str) -> str:
        host = self._session_host(value)
        if not host:
            raise ValueError(f"cannot authorize Metasploit session: {source} host is missing")
        if self._scope is not None:
            match = self._check_execution_scope(host)
            if not match.allowed:
                raise OutOfScopeError(host, match.reason, match.matched_rule)
        return host

    def has_tool(self, tool_id: str) -> bool:
        """True if tool_id is in the bound catalog. False if no catalog."""
        if self._catalog is None:
            return False
        return self._catalog.get(tool_id) is not None

    def build_argv(
        self,
        tool_id: str,
        target: str,
        extra_args: str = "",
        outfile: Path | None = None,
    ) -> list[str]:
        """Look up the tool and produce argv from its args template.

        If the tool declares outfile_flag and outfile is given, the
        pair <flag> <outfile> is appended after the template args and
        before user extra_args (so user overrides win).
        """
        if self._catalog is None:
            raise RuntimeError("runner has no catalog bound")
        tool = self._catalog.get(tool_id)
        if tool is None:
            raise ValueError(f"unknown tool: {tool_id}")
        # SC-01: reject targets that could be parsed as argv flags or that
        # contain control characters. Even if scope enforcement lets the
        # target through (override path, session paths), the argv builder
        # must not construct an argument that changes the tool's behavior.
        if not target or target.startswith("-") or any(char.isspace() for char in target):
            raise ValueError(f"refusing to build argv for unsafe target: {target!r}")
        template = tool.args or "{target}"

        # The positional target is the single source of truth for scope
        # enforcement. Never let extra_args silently replace it with a second
        # destination (e.g. sqlmap -u https://out-of-scope.example).
        try:
            extra_tokens = shlex.split(extra_args) if extra_args and extra_args.strip() else []
        except ValueError as e:
            raise ValueError(f"bad extra args: {e}") from e
        target_override_flags = {
            "-u", "--url", "-h", "--host", "--target", "--target-url",
            "--targets", "--target-list", "--domain", "--domains",
            "--target-ip", "--target-host", "-il", "--input-list",
            "--input-file", "--targets-file", "-ir",
        }
        user_overrides_target = any(
            token.lower() in target_override_flags
            or token.lower().startswith((
                "--url=", "-u=", "--host=", "--target=", "--target-url=",
                "--targets=", "--target-list=", "--domain=", "--domains=",
                "--target-ip=", "--target-host=", "--input-list=", "--input-file=",
            ))
            or (
                token.lower().startswith(("-u", "-h", "-il", "-ir"))
                and token.lower() not in target_override_flags
            )
            for token in extra_tokens
        )
        if user_overrides_target:
            raise ValueError(
                "extra_args cannot specify alternate targets or target lists; pass the "
                "authorized target as the positional target argument"
            )

        # Some tools accept multiple positional targets, so checking only
        # explicit flags such as -u/--url is insufficient. Reject common
        # target-shaped values anywhere in extra_args before building argv.
        import ipaddress
        import re
        from urllib.parse import urlsplit

        def _looks_like_target_token(token: str) -> bool:
            value = token.strip()
            if not value:
                return False
            if value.startswith("-"):
                return False
            if "://" in value or value.startswith("//"):
                parsed = urlsplit(value)
                return bool(parsed.hostname)
            if "/" in value:
                # Some tools accept host/path or CIDR-like target values.
                # Inspect the authority portion, but do not treat ordinary
                # relative paths such as /admin as an alternate host.
                authority = value.split("/", 1)[0]
                if authority and _looks_like_target_token(authority):
                    return True
            try:
                ipaddress.ip_address(value.strip("[]"))
                return True
            except ValueError:
                pass
            try:
                ipaddress.ip_network(value, strict=False)
                return True
            except ValueError:
                pass
            host = value
            if host.count(":") == 1:
                possible_host, possible_port = host.rsplit(":", 1)
                if possible_port.isdigit():
                    host = possible_host
            if host.lower() == "localhost":
                return True
            if "." not in host:
                return False
            labels = host.rstrip(".").split(".")
            return all(
                label and len(label) <= 63
                and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
                for label in labels
            )

        if any(_looks_like_target_token(token) for token in extra_tokens):
            raise ValueError(
                "extra_args cannot include a second target or target network; "
                "pass the authorized target as the positional target argument"
            )

        try:
            parts = shlex.split(template.format(target=target))
        except (KeyError, ValueError) as e:
            raise ValueError(f"bad args template for {tool_id}: {e}") from e

        flag = getattr(tool, "outfile_flag", "") or ""
        if flag and outfile is not None:
            parts += [flag, str(outfile)]

        argv = [tool.binary, *parts]
        if extra_tokens:
            argv.extend(extra_tokens)
        return argv

    async def run_tool(
        self,
        tool_id: str,
        target: str,
        job_id: str | None = None,
        extra_args: str = "",
        timeout_s: float | None = 300,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        allow_out_of_scope: bool = False,
        phase: str = "",
        lease_token: str | None = None,
    ) -> str:
        """High-level: run a catalog tool against a target.

        If a scope is bound and the target is out of scope, raises
        OutOfScopeError unless allow_out_of_scope=True.
        """
        if self._scope is not None:
            match = self._check_execution_scope(target)
            hard_deny = getattr(match, "overridable", True) is False
            if not match.allowed and (hard_deny or not allow_out_of_scope):
                from .events import CoverageSkipped
                jid = job_id or uuid.uuid4().hex[:12]
                self._bus.publish(CoverageSkipped(
                    job_id=jid, tool_id=tool_id, target=target,
                    kind="scope_blocked", detail=match.reason or "out of scope",
                    phase=phase,
                ))
                raise OutOfScopeError(
                    target, match.reason, match.matched_rule,
                    overridable=not hard_deny,
                )
            if not match.allowed and allow_out_of_scope:
                # Explicit overrides must be auditable. If the log cannot be
                # written, refuse the bypass rather than silently lose the trail.
                from .override_log import log_override
                scope_path = getattr(self._scope, "path", None)
                if scope_path is None or not log_override(scope_path.parent, tool_id, target):
                    raise RuntimeError(
                        "scope override could not be audited; refusing out-of-scope execution"
                    )

        outfile: Path | None = None
        outdir: Path | None = None
        tool = self._catalog.get(tool_id) if self._catalog else None
        # Use a private, randomly named directory rather than a predictable
        # /tmp/whaxon-<job-id>.json path that another local user could pre-create
        # as a symlink and race against the external tool's file open.
        if tool is not None and getattr(tool, "outfile_flag", ""):  # type: ignore[arg-type]
            import tempfile
            outdir = Path(tempfile.mkdtemp(prefix="whaxon-"))
            outfile = outdir / "output.json"

        # Pivoting is a second authorization boundary: the original target
        # was scope-checked above, but the forwarding session must also be a
        # persisted, open, in-scope session before its local port is trusted.
        effective_target = target
        if (self._route_resolver is not None
                and tool is not None
                and getattr(tool, "pivot_capable", False)):
            from urllib.parse import urlsplit

            parsed_target = urlsplit(target if "://" in target else "//" + target)
            host_only = parsed_target.hostname or ""
            route = self._route_resolver(host_only)
            if route is not None:
                route_host = self._session_host(getattr(route, "target_host", ""))
                local_port = getattr(route, "local_port", None)
                target_port = getattr(route, "target_port", None)
                via_session = str(getattr(route, "via_session", "") or "")
                if route_host.lower().rstrip(".") != host_only.lower().rstrip("."):
                    raise ValueError("pivot route target does not match the authorized target")
                if (not isinstance(local_port, int) or isinstance(local_port, bool)
                        or not 1 <= local_port <= 65535):
                    raise ValueError("pivot route has an invalid local forwarding port")
                if (not isinstance(target_port, int) or isinstance(target_port, bool)
                        or not 1 <= target_port <= 65535):
                    raise ValueError("pivot route has an invalid remote target port")
                if not via_session or self._session_lookup is None:
                    raise RuntimeError(
                        "pivot route requires persisted session authorization context"
                    )
                stored_session = self._session_lookup(via_session)
                if not stored_session or stored_session.get("status") != "open":
                    raise ValueError("pivot route session is not an open persisted session")
                stored_host = self._authorize_session_host(
                    stored_session.get("host"), source="persisted pivot session"
                )
                live_host = self._authorize_session_host(
                    getattr(route, "session_host", ""), source="live pivot session"
                )
                if stored_host.lower().rstrip(".") != live_host.lower().rstrip("."):
                    raise ValueError("pivot session identity changed since it was persisted")
                effective_target = "127.0.0.1:" + str(local_port)

        # Re-authorize immediately before process creation. This catches an
        # engagement scope tightened while route discovery or argv preparation
        # was in progress; the initial check above remains the early gate.
        if self._scope is not None:
            final_match = self._check_execution_scope(target)
            if not final_match.allowed:
                if not allow_out_of_scope:
                    from .events import CoverageSkipped
                    jid = job_id or uuid.uuid4().hex[:12]
                    self._bus.publish(CoverageSkipped(
                        job_id=jid, tool_id=tool_id, target=target,
                        kind="scope_blocked",
                        detail=final_match.reason or "out of scope",
                        phase=phase,
                    ))
                    raise OutOfScopeError(
                        target, final_match.reason, final_match.matched_rule
                    )
                from .override_log import log_override
                scope_path = getattr(self._scope, "path", None)
                if scope_path is None or not log_override(
                    scope_path.parent, tool_id, target
                ):
                    raise RuntimeError(
                        "scope override could not be audited; refusing out-of-scope execution"
                    )

        try:
            argv = self.build_argv(tool_id, effective_target, extra_args=extra_args, outfile=outfile)
            return await self.run(
                tool_id=tool_id,
                job_id=job_id,
                argv=argv,
                target=target,  # original host — attribution stays with the target
                cwd=cwd,
                env=env,
                timeout_s=timeout_s,
                outfile=outfile,
                phase=phase,
                lease_token=lease_token,
            )
        finally:
            if outdir is not None:
                import shutil
                shutil.rmtree(outdir, ignore_errors=True)

    def _run_msf_session(
        self, session_id: str, command: str, timeout_s: float,
        *, expected_host: str | None = None,
    ) -> str:
        """Run a command inside a Metasploit session."""
        from .msf import MSFClient, MSFUnavailableError
        client = MSFClient()
        if not client.is_up():
            raise MSFUnavailableError("Metasploit RPC is not reachable")
        sessions = client.sessions()
        if str(session_id) not in sessions:
            raise ValueError(
                f"session {session_id} not found (have: {sorted(sessions)})"
            )
        info = sessions[str(session_id)] or {}
        # Re-check the live RPC peer at dispatch; the stored host may be stale.
        live_host = info.get("target_host") or info.get("session_host") or info.get("tunnel_peer") or info.get("peer_host")
        authorized_live_host = self._authorize_session_host(live_host, source="live RPC")
        if expected_host is not None:
            if self._canonical_session_host(expected_host) != self._canonical_session_host(authorized_live_host):
                raise ValueError(
                    "Metasploit session identity changed since it was persisted; refusing dispatch"
                )
        actual_type = info.get("type") or ""
        required = getattr(self, '_required_session_type', "") or ""
        if required and actual_type and actual_type != required:
            raise ValueError(
                f"session {session_id} is type {actual_type!r}, tool requires {required!r}"
            )
        return client.session_exec(session_id, command, timeout=timeout_s)


    async def _run_smb_session(self, session_id: str, command: str,
                              timeout_s: float) -> str:
        """Run a command over SMB via impacket-smbclient.

        session_id format: smb:user@host[:port]. Credentials come from
        WHAXON_SMB_PASS (and optionally WHAXON_SMB_DOMAIN). Never embedded
        in the session id — that string lands in logs.
        """
        import asyncio as _asyncio
        import os as _os
        if not str(session_id).startswith("smb:"):
            raise ValueError(
                "smb session id must be smb:user@host[:port], got " + repr(session_id)
            )
        spec = str(session_id)[len("smb:"):]
        user_host = spec
        port = None
        if ":" in spec:
            head, _, tail = spec.rpartition(":")
            if tail.isdigit():
                user_host, port = head, tail
        host = user_host.split("@", 1)[-1]
        user = user_host.split("@", 1)[0] if "@" in user_host else ""
        domain = _os.environ.get("WHAXON_SMB_DOMAIN", "")
        if (
            user_host.count("@") != 1
            or not user
            or any(ch in user for ch in "/:@\r\n\0")
            or any(ch in host for ch in "/@\r\n\0")
            or any(ch in domain for ch in "/:@\r\n\0")
            or (port is not None and not 1 <= int(port) <= 65535)
            or any(ch in str(session_id) for ch in "\r\n\0")
            or any(ch in command for ch in "\r\n\0")
        ):
            return "[error] invalid SMB session identity or command"
        if self._scope is not None:
            match = self._check_execution_scope(host)
            if not match.allowed:
                raise OutOfScopeError(host, match.reason, match.matched_rule)
        password = _os.environ.get("WHAXON_SMB_PASS", "")
        if not password:
            return "[error] WHAXON_SMB_PASS not set"
        if any(ch in password for ch in "\r\n\0"):
            return "[error] SMB password must not contain newlines or NUL"
        argv = ["impacket-smbclient"]
        prefix = (domain + "/") if domain else ""
        # Never put the password in argv: ps/procfs can expose it to other
        # local users. Impacket prompts when no password is supplied; its
        # non-TTY getpass fallback consumes the first stdin line.
        argv.append(prefix + user + "@" + host)
        if port:
            argv += ["-port", port]
        stdin_bytes = (password + "\n" + command + "\nexit\n").encode()
        try:
            proc = await _asyncio.create_subprocess_exec(
                *argv,
                stdin=_asyncio.subprocess.PIPE,
                stdout=_asyncio.subprocess.PIPE,
                stderr=_asyncio.subprocess.PIPE,
                start_new_session=(_os.name == "posix"),
            )
            stdout, stderr = await _asyncio.wait_for(
                proc.communicate(stdin_bytes), timeout=timeout_s,
            )
        except TimeoutError:
            await self._kill_process_tree(proc)
            await proc.wait()
            return "[error] smb timeout"
        except FileNotFoundError:
            return "[error] impacket-smbclient not found"
        text = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")
        if err and not text:
            text = err
        if not text and proc.returncode:
            text = "[error] smb exit " + str(proc.returncode)
        return text

    async def _run_wmi_session(self, session_id: str, command: str,
                              timeout_s: float) -> str:
        """Run a command over WMI via impacket-wmiexec.

        session_id format: wmi:user@host[:port]. Credentials come from
        WHAXON_WMI_PASS (falls back to WHAXON_SMB_PASS). Optional
        WHAXON_WMI_DOMAIN (falls back to WHAXON_SMB_DOMAIN).
        """
        import asyncio as _asyncio
        import os as _os
        if not str(session_id).startswith("wmi:"):
            raise ValueError(
                "wmi session id must be wmi:user@host[:port], got " + repr(session_id)
            )
        spec = str(session_id)[len("wmi:"):]
        user_host = spec
        port = None
        if ":" in spec:
            head, _, tail = spec.rpartition(":")
            if tail.isdigit():
                user_host, port = head, tail
        host = user_host.split("@", 1)[-1]
        user = user_host.split("@", 1)[0] if "@" in user_host else ""
        domain = _os.environ.get("WHAXON_WMI_DOMAIN") or _os.environ.get("WHAXON_SMB_DOMAIN", "")
        if (
            user_host.count("@") != 1
            or not user
            or any(ch in user for ch in "/:@\r\n\0")
            or any(ch in host for ch in "/@\r\n\0")
            or any(ch in domain for ch in "/:@\r\n\0")
            or (port is not None and not 1 <= int(port) <= 65535)
            or any(ch in str(session_id) for ch in "\r\n\0")
        ):
            return "[error] invalid WMI session identity"
        if self._scope is not None:
            match = self._check_execution_scope(host)
            if not match.allowed:
                raise OutOfScopeError(host, match.reason, match.matched_rule)
        password = _os.environ.get("WHAXON_WMI_PASS") or _os.environ.get("WHAXON_SMB_PASS", "")
        if not password:
            return "[error] WHAXON_WMI_PASS not set (and WHAXON_SMB_PASS empty)"
        if any(ch in password for ch in "\r\n\0"):
            return "[error] WMI password must not contain newlines or NUL"
        argv = ["impacket-wmiexec"]
        prefix = (domain + "/") if domain else ""
        # Keep credentials out of argv; impacket prompts for a missing password.
        argv.append(prefix + user + "@" + host)
        argv.append(command)
        if port:
            argv += ["-port", port]
        try:
            proc = await _asyncio.create_subprocess_exec(
                *argv,
                stdin=_asyncio.subprocess.PIPE,
                stdout=_asyncio.subprocess.PIPE,
                stderr=_asyncio.subprocess.PIPE,
                start_new_session=(_os.name == "posix"),
            )
            stdout, stderr = await _asyncio.wait_for(
                proc.communicate((password + "\n").encode()), timeout=timeout_s,
            )
        except TimeoutError:
            await self._kill_process_tree(proc)
            await proc.wait()
            return "[error] wmi timeout"
        except FileNotFoundError:
            return "[error] impacket-wmiexec not found"
        text = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")
        if err and not text:
            text = err
        if not text and proc.returncode:
            text = "[error] wmi exit " + str(proc.returncode)
        return text

    async def _run_ssh_session(self, session_id: str, command: str,
                              timeout_s: float) -> str:
        """Run a command over SSH.

        session_id format: ssh:user@host[:port]. The host part is
        scope-checked before running — unlike MSF sessions, there is
        no prior establishment that would have checked it.
        """
        import asyncio as _asyncio
        if not str(session_id).startswith("ssh:"):
            raise ValueError(
                f"ssh session id must be ssh:user@host[:port], got {session_id!r}"
            )
        spec = str(session_id)[len("ssh:"):]
        user_host = spec
        port = None
        if ":" in spec:
            head, _, tail = spec.rpartition(":")
            if tail.isdigit():
                user_host, port = head, tail
        host = user_host.split("@", 1)[-1]
        if self._scope is not None:
            match = self._check_execution_scope(host)
            if not match.allowed:
                raise OutOfScopeError(host, match.reason, match.matched_rule)
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=accept-new"]
        if port:
            argv += ["-p", port]
        argv += [user_host, command]
        try:
            proc = await _asyncio.create_subprocess_exec(
                *argv,
                stdout=_asyncio.subprocess.PIPE,
                stderr=_asyncio.subprocess.PIPE,
            )
            stdout, stderr = await _asyncio.wait_for(
                proc.communicate(), timeout=timeout_s,
            )
        except TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return "[error] ssh timeout"
        except FileNotFoundError:
            return "[error] ssh binary not found"
        text = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")
        if err and not text:
            text = err
        if not text and proc.returncode:
            text = "[error] ssh exit " + str(proc.returncode)
        return text


    async def run_in_session(
        self,
        tool_id: str,
        session_id: str,
        job_id: str | None = None,
        timeout_s: float = 15.0,
        extra_args: str = "",
    ) -> str:
        """Run a session-scoped tool inside a Metasploit session.

        Does not spawn a subprocess. Writes the tool command to the
        session and collects the response via MSFClient.session_exec.
        Emits the same Job* events so the store cannot tell the
        difference at that layer.
        """
        if self._catalog is None:
            raise RuntimeError("runner has no catalog bound")
        tool = self._catalog.get(tool_id)
        if tool is None:
            raise ValueError(f"unknown tool: {tool_id}")
        transport = getattr(tool, "transport", "cli")
        if transport not in ("msf_session", "ssh", "smb", "wmi"):
            raise ValueError(
                f"tool {tool_id} is not session-scoped (transport={transport})"
            )
        raw_command = getattr(tool, "command", "")
        is_template = "{command}" in raw_command
        command = raw_command.replace("{command}", extra_args) if is_template else raw_command
        if not command and not is_template:
            raise ValueError(f"session tool {tool_id} has no command")

        if job_id is None:
            job_id = uuid.uuid4().hex[:12]
        target_label = f"session:{session_id}"

        if transport == "msf_session":
            if self._session_lookup is None:
                raise RuntimeError("Metasploit session dispatch requires persisted session authorization context")
            stored = self._session_lookup(str(session_id))
            if not stored or stored.get("status") != "open":
                raise ValueError(f"session {session_id} is not an open persisted session")
            stored_host = self._authorize_session_host(stored.get("host"), source="stored")
            self._required_session_type = getattr(tool, 'required_session_type', "") or ""
            output = self._run_msf_session(
                session_id, command, timeout_s, expected_host=stored_host,
            )
        elif transport == "smb":
            output = await self._run_smb_session(session_id, command, timeout_s)
        elif transport == "wmi":
            output = await self._run_wmi_session(session_id, command, timeout_s)
        else:
            output = await self._run_ssh_session(
                session_id, command, timeout_s,
            )

        self._bus.publish(JobStarted(
            job_id=job_id, tool_id=tool_id, target=target_label,
        ))
        # Cap session output to avoid multi-megabyte findings.
        _MAX_LINES = 5000
        _MAX_BYTES = 1_000_000
        _raw = (output or "").splitlines()
        _capped: list[str] = []
        _bytes = 0
        for _ln in _raw:
            if len(_capped) >= _MAX_LINES or _bytes >= _MAX_BYTES:
                _capped.append("[runner] output truncated at " + str(len(_capped)) + " lines (" + str(_bytes) + " bytes)")
                break
            _capped.append(_ln)
            _bytes += len(_ln) + 1

        self._lines_by_job.setdefault(job_id, [])
        for line in _capped:
            self._lines_by_job[job_id].append(("stdout", line))
            self._bus.publish(JobOutput(
                job_id=job_id, stream="stdout", line=line,
            ))

        self._bus.publish(JobFinished(
            job_id=job_id, exit_code=0, duration_s=0.0,
        ))

        try:
            from whaxon.adapters.registry import get_adapter
            adapter = get_adapter(tool_id)
        except Exception:
            adapter = None
        if adapter is not None:
            ctx = {
                "job_id": job_id,
                "target": target_label,
                "session_id": str(session_id),
            }
            try:
                findings = adapter.parse(
                    self._lines_by_job[job_id], ctx,
                )
            except Exception:
                findings = []
            if findings:
                resolved = self._resolve_findings(findings)
                self._bus.publish(JobFindings(
                    job_id=job_id, findings=tuple(resolved),
                ))
        return job_id

    async def run(
        self,
        tool_id: str,
        job_id: str | None = None,
        argv: Sequence[str] = (),
        target: str = "",
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout_s: float | None = None,
        outfile: Path | None = None,
        phase: str = "",
        lease_token: str | None = None,
    ) -> str:
        if job_id is None:
            job_id = uuid.uuid4().hex[:12]
        self._bus.publish(JobStarted(job_id=job_id, tool_id=tool_id, target=target, lease_token=lease_token))
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=env,
                # Isolate each tool so timeout/cancel can stop child processes too.
                start_new_session=(os.name == "posix"),
            )
        except FileNotFoundError as e:
            from .events import CoverageSkipped
            self._bus.publish(CoverageSkipped(
                job_id=job_id, tool_id=tool_id, target=target,
                kind="binary_missing", detail=str(e),
                phase=phase,
            ))
            self._bus.publish(JobFailed(job_id=job_id, error=f"tool not found: {e}", lease_token=lease_token))
            raise

        self._procs[job_id] = proc

        self._lines_by_job.setdefault(job_id, [])

        max_output_lines = 5000
        max_output_bytes = 1_000_000
        max_line_bytes = 16_384
        captured = {"lines": 0, "bytes": 0, "truncated": False}

        def emit_line(raw: bytes, name: str) -> None:
            if captured["truncated"]:
                return
            if (
                captured["lines"] >= max_output_lines
                or captured["bytes"] + len(raw) > max_output_bytes
            ):
                captured["truncated"] = True
                marker = (
                    f"[runner] output truncated at {captured['lines']} lines "
                    f"and {captured['bytes']} bytes"
                )
                self._lines_by_job[job_id].append((name, marker))
                self._bus.publish(JobOutput(job_id=job_id, stream=name, line=marker, lease_token=lease_token))
                return
            captured["lines"] += 1
            captured["bytes"] += len(raw)
            if len(raw) > max_line_bytes:
                raw = raw[:max_line_bytes] + b" ...[line truncated]"
            text = raw.decode(errors="replace").rstrip("\r")
            self._lines_by_job[job_id].append((name, text))
            self._bus.publish(JobOutput(job_id=job_id, stream=name, line=text, lease_token=lease_token))

        async def pump(stream: asyncio.StreamReader | None, name: str) -> None:
            if stream is None:
                return
            buffer = bytearray()
            discarding_long_line = False
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    break
                if discarding_long_line:
                    newline = chunk.find(b"\n")
                    if newline < 0:
                        continue
                    chunk = chunk[newline + 1:]
                    discarding_long_line = False
                if not chunk:
                    continue
                buffer.extend(chunk)
                while True:
                    newline = buffer.find(b"\n")
                    if newline < 0:
                        break
                    raw = bytes(buffer[:newline])
                    del buffer[:newline + 1]
                    emit_line(raw, name)
                if len(buffer) > max_line_bytes:
                    emit_line(bytes(buffer[:max_line_bytes]) + b" ...[line truncated]", name)
                    buffer.clear()
                    discarding_long_line = True
            if buffer and not discarding_long_line:
                emit_line(bytes(buffer), name)

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    pump(proc.stdout, "stdout"),
                    pump(proc.stderr, "stderr"),
                    proc.wait(),
                ),
                timeout=timeout_s,
            )
        except TimeoutError:
            await self._kill_process_tree(proc)
            from .events import CoverageSkipped
            self._bus.publish(CoverageSkipped(
                job_id=job_id, tool_id=tool_id, target=target,
                kind="timeout", detail="exceeded timeout_s",
                phase=phase,
            ))
            self._bus.publish(JobFailed(job_id=job_id, error="timeout", lease_token=lease_token))
            self._procs.pop(job_id, None)
            self._lines_by_job.pop(job_id, None)
            return job_id

        self._procs.pop(job_id, None)
        self._bus.publish(JobFinished(
            job_id=job_id,
            exit_code=proc.returncode or 0,
            duration_s=time.monotonic() - start,
            lease_token=lease_token,
        ))
        if outfile is not None and not outfile.exists():
            import sys as _sys
            print(
                f"[runner] {tool_id}: expected outfile not produced: {outfile}",
                file=_sys.stderr,
            )

        self._publish_findings(
            tool_id, job_id, self._lines_by_job.pop(job_id, []),
            argv=argv, target=target, outfile=outfile, lease_token=lease_token,
        )
        return job_id

    def _publish_findings(
        self,
        tool_id: str,
        job_id: str,
        lines: list[tuple[str, str]],
        *,
        argv: Sequence[str] = (),
        target: str = "",
        outfile: Path | None = None,
        lease_token: str | None = None,
    ) -> None:
        findings = []
        # Try adapter first (richer output)
        try:
            from ..adapters import get_adapter
            adapter = get_adapter(tool_id)
            if adapter is not None:
                findings = adapter.parse(lines, ctx={
                    "tool_id": tool_id,
                    "extra_args": " ".join(argv[1:]) if len(argv) > 1 else "",
                    "argv": list(argv),
                    "target": target,
                    "outfile": str(outfile) if outfile else "",
                })
        except Exception as e:
            import sys
            print(f"[runner] adapter error for {tool_id}: {e!r}", file=sys.stderr)
            findings = []
        # Fall back to the legacy parser registry
        if not findings:
            from .findings import parse_findings
            findings = parse_findings(tool_id, lines)
        if findings:
            resolved = self._resolve_findings(findings)
            self._bus.publish(JobFindings(
                job_id=job_id,
                findings=tuple(resolved),
                lease_token=lease_token,
            ))

    @staticmethod
    async def _kill_process_tree(proc: asyncio.subprocess.Process) -> None:
        """Stop the tool and any descendants started in its isolated process group."""
        if os.name == "posix":
            # The process-group leader may already have exited while a child
            # still holds stdout/stderr open. Kill the group even in that case.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                if proc.returncode is None:
                    proc.kill()
        elif proc.returncode is None:
            proc.kill()
        try:
            await proc.wait()
        except ProcessLookupError:
            pass

    async def cancel(self, job_id: str) -> None:
        proc = self._procs.get(job_id)
        if proc is not None:
            # The leader may have exited while a descendant still holds pipes
            # open. Kill the isolated process group regardless of leader status.
            await self._kill_process_tree(proc)
