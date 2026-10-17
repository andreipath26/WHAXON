"""Durable job worker: drain pending rows through the runner.

A chained job (e.g. nikto queued by the auto-chain) is a row in the
jobs table with status='pending', not a thread. The worker claims
pending rows atomically and runs them. Any long-lived host (serve,
web, gui, tui) drains on startup and on a cadence; the CLI exposes
`whaxon jobs drain` for the one-shot case.

This is what makes the auto-chain durable across process exit: the
row survives, the next worker finishes it.
"""
from __future__ import annotations

import asyncio
import logging

_log = logging.getLogger(__name__)


def drain(store, runner, *, max_jobs: int = 50) -> int:
    """Claim and run pending jobs until none remain. Returns count run.

    Runs synchronously — each job is awaited to completion before the
    next is claimed. Idempotent on a clean exit: a crash mid-job leaves
    the row 'running', which reconcile_stale() corrects at next startup.
    """
    ran = 0
    for _ in range(max_jobs):
        row = store.claim_pending()
        if row is None:
            break
        job_id = row["id"]
        tool = row["tool"]
        target = row["target"]
        try:
            asyncio.run(runner.run_tool(
                tool_id=tool, target=target, job_id=job_id,
            ))
        except Exception as e:
            _log.warning("drained job %s failed: %s", job_id, e)
            try:
                store.set_failed(job_id, f"{type(e).__name__}: {e}")
            except Exception:
                pass
        ran += 1
    return ran


async def drain_async(store, runner, *, max_jobs: int = 50) -> int:
    """Async drain for hosts that already own an event loop.

    Same semantics as drain(), but awaits run_tool on the caller's loop.
    Used by whaxon serve / web / tui / gui.
    """
    ran = 0
    for _ in range(max_jobs):
        row = store.claim_pending()
        if row is None:
            break
        job_id = row["id"]
        try:
            await runner.run_tool(
                tool_id=row["tool"], target=row["target"], job_id=job_id,
            )
        except Exception as e:
            _log.warning("drained job %s failed: %s", job_id, e)
            try:
                store.set_failed(job_id, f"{type(e).__name__}: {e}")
            except Exception:
                pass
        ran += 1
    return ran
