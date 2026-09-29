"""Executes external tools, streams output through the event bus."""
from __future__ import annotations

import asyncio
import shlex
import time
import uuid
from pathlib import Path
from typing import Sequence

from .scope import ScopeManager, OutOfScopeError
from .events import (
    EventBus, JobStarted, JobOutput, JobFinished, JobFailed, JobFindings,
)


class ToolRunner:
    def __init__(self, bus: EventBus, catalog=None, scope=None) -> None:
        self._bus = bus
        self._catalog = catalog
        self._scope = scope  # optional ScopeManager
        self._procs: dict[str, asyncio.subprocess.Process] = {}
        self._lines_by_job: dict[str, list[tuple[str, str]]] = {}

    def bind_catalog(self, catalog) -> None:
        """Wire the catalog after construction (Core does this)."""
        self._catalog = catalog

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
        template = tool.args or "{target}"
        try:
            parts = shlex.split(template.format(target=target))
        except (KeyError, ValueError) as e:
            raise ValueError(f"bad args template for {tool_id}: {e}") from e

        flag = getattr(tool, "outfile_flag", "") or ""
        if flag and outfile is not None:
            parts += [flag, str(outfile)]

        argv = [tool.binary, *parts]
        if extra_args and extra_args.strip():
            try:
                argv.extend(shlex.split(extra_args))
            except ValueError as e:
                raise ValueError(f"bad extra args: {e}") from e
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
    ) -> str:
        """High-level: run a catalog tool against a target.

        If a scope is bound and the target is out of scope, raises
        OutOfScopeError unless allow_out_of_scope=True.
        """
        if self._scope is not None and not allow_out_of_scope:
            match = self._scope.check(target)
            if not match.allowed:
                raise OutOfScopeError(target, match.reason, match.matched_rule)

        outfile: Path | None = None
        tool = self._catalog.get(tool_id) if self._catalog else None
        if tool is not None and getattr(tool, "outfile_flag", ""):
            import tempfile
            jid = job_id or uuid.uuid4().hex[:12]
            outfile = Path(tempfile.gettempdir()) / f"whaxon-{jid}.json"
            try:
                outfile.unlink()
            except FileNotFoundError:
                pass

        argv = self.build_argv(tool_id, target, extra_args=extra_args, outfile=outfile)
        return await self.run(
            tool_id=tool_id,
            job_id=job_id,
            argv=argv,
            target=target,
            cwd=cwd,
            env=env,
            timeout_s=timeout_s,
            outfile=outfile,
        )

    def _run_msf_session(self, session_id: str, command: str,
                        timeout_s: float) -> str:
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
        return client.session_exec(session_id, command, timeout=timeout_s)


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
            match = self._scope.check(host)
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
        except _asyncio.TimeoutError:
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
        if transport not in ("msf_session", "ssh"):
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
            output = self._run_msf_session(session_id, command, timeout_s)
        else:
            output = await self._run_ssh_session(
                session_id, command, timeout_s,
            )

        self._bus.publish(JobStarted(
            job_id=job_id, tool_id=tool_id, target=target_label,
        ))
        self._lines_by_job.setdefault(job_id, [])
        for line in (output or "").splitlines():
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
                self._bus.publish(JobFindings(
                    job_id=job_id, findings=findings,
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
    ) -> str:
        if job_id is None:
            job_id = uuid.uuid4().hex[:12]
        self._bus.publish(JobStarted(job_id=job_id, tool_id=tool_id, target=target))
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=env,
            )
        except FileNotFoundError as e:
            self._bus.publish(JobFailed(job_id=job_id, error=f"tool not found: {e}"))
            raise

        self._procs[job_id] = proc

        self._lines_by_job.setdefault(job_id, [])

        async def pump(stream: asyncio.StreamReader | None, name: str) -> None:
            if stream is None:
                return
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode(errors="replace").rstrip("\n")
                self._lines_by_job[job_id].append((name, text))
                self._bus.publish(JobOutput(
                    job_id=job_id, stream=name,
                    line=text,
                ))

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    pump(proc.stdout, "stdout"),
                    pump(proc.stderr, "stderr"),
                    proc.wait(),
                ),
                timeout=timeout_s,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            self._bus.publish(JobFailed(job_id=job_id, error="timeout"))
            self._procs.pop(job_id, None)
            return job_id

        self._procs.pop(job_id, None)
        self._bus.publish(JobFinished(
            job_id=job_id,
            exit_code=proc.returncode or 0,
            duration_s=time.monotonic() - start,
        ))
        if outfile is not None and not outfile.exists():
            import sys as _sys
            print(
                f"[runner] {tool_id}: expected outfile not produced: {outfile}",
                file=_sys.stderr,
            )

        self._publish_findings(
            tool_id, job_id, self._lines_by_job.pop(job_id, []),
            argv=argv, target=target, outfile=outfile,
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
            self._bus.publish(JobFindings(
                job_id=job_id,
                findings=tuple(f.to_dict() for f in findings),
            ))

    async def cancel(self, job_id: str) -> None:
        proc = self._procs.get(job_id)
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
