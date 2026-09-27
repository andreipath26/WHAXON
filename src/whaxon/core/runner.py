"""Executes external tools, streams output through the event bus."""
from __future__ import annotations

import asyncio
import shlex
import time
import uuid
from pathlib import Path
from typing import Sequence

from .events import (
    EventBus, JobStarted, JobOutput, JobFinished, JobFailed, JobFindings,
)


class ToolRunner:
    def __init__(self, bus: EventBus, catalog=None) -> None:
        self._bus = bus
        self._catalog = catalog
        self._procs: dict[str, asyncio.subprocess.Process] = {}
        self._lines_by_job: dict[str, list[tuple[str, str]]] = {}

    def bind_catalog(self, catalog) -> None:
        """Wire the catalog after construction (Core does this)."""
        self._catalog = catalog

    def build_argv(self, tool_id: str, target: str, extra_args: str = "") -> list[str]:
        """Look up the tool and produce argv from its args template."""
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
    ) -> str:
        """High-level: run a catalog tool against a target."""
        argv = self.build_argv(tool_id, target, extra_args=extra_args)
        return await self.run(
            tool_id=tool_id,
            job_id=job_id,
            argv=argv,
            target=target,
            cwd=cwd,
            env=env,
            timeout_s=timeout_s,
        )

    async def run(
        self,
        tool_id: str,
        job_id: str | None = None,
        argv: Sequence[str] = (),
        target: str = "",
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout_s: float | None = None,
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
        self._publish_findings(tool_id, job_id, self._lines_by_job.pop(job_id, []))
        return job_id

    def _publish_findings(self, tool_id: str, job_id: str, lines: list[tuple[str, str]]) -> None:
        findings = []
        # Try adapter first (richer output)
        try:
            from ..adapters import get_adapter
            adapter = get_adapter(tool_id)
            if adapter is not None:
                findings = adapter.parse(lines, ctx={"tool_id": tool_id})
        except Exception:
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
