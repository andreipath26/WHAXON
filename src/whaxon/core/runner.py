"""Executes external tools, streams output through the event bus."""
from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from typing import Sequence

from .events import (
    EventBus, JobStarted, JobOutput, JobFinished, JobFailed,
)


class ToolRunner:
    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._procs: dict[str, asyncio.subprocess.Process] = {}

    async def run(
        self,
        tool_id: str,
        argv: Sequence[str],
        target: str = "",
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout_s: float | None = None,
    ) -> str:
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

        async def pump(stream: asyncio.StreamReader | None, name: str) -> None:
            if stream is None:
                return
            while True:
                line = await stream.readline()
                if not line:
                    break
                self._bus.publish(JobOutput(
                    job_id=job_id, stream=name,
                    line=line.decode(errors="replace").rstrip("\n"),
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
        return job_id

    async def cancel(self, job_id: str) -> None:
        proc = self._procs.get(job_id)
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
