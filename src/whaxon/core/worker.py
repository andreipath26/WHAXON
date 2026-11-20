"""Lease-based durable worker for pending jobs."""
from __future__ import annotations

import asyncio
import logging
import uuid

_log = logging.getLogger(__name__)
_DEFAULT_LEASE_TTL_S = 120.0


async def _renew_lease(store, runner, job_id: str, token: str, interval_s: float) -> None:
    """Keep a live job owned; terminate its process if its fencing token is lost."""
    while True:
        await asyncio.sleep(interval_s)
        try:
            renewed = store.heartbeat_job(job_id, token)
        except Exception:
            _log.exception("heartbeat failed for job %s", job_id)
            renewed = False
        if not renewed:
            _log.error("worker lost lease for job %s; cancelling execution", job_id)
            try:
                await runner.cancel(job_id)
            except Exception:
                _log.exception("could not cancel job after lease loss: %s", job_id)
            return


async def drain_async(
    store, runner, *, max_jobs: int = 50, exclude_ids=None, include_ids=None,
    lease_ttl_s: float = _DEFAULT_LEASE_TTL_S, worker_id: str | None = None,
) -> int:
    """Claim and await jobs, renewing each lease until execution completes."""
    if lease_ttl_s < 3:
        raise ValueError("lease_ttl_s must be at least 3 seconds")
    owner = worker_id or f"whaxon-{uuid.uuid4().hex}"
    ran = 0
    for _ in range(max_jobs):
        row = store.claim_pending(
            exclude_ids=exclude_ids, include_ids=include_ids, worker_id=owner,
        )
        if row is None:
            break
        job_id = row["id"]
        token = row["lease_token"]
        heartbeat = asyncio.create_task(
            _renew_lease(store, runner, job_id, token, lease_ttl_s / 3),
            name=f"whaxon-lease-{job_id}",
        )
        try:
            await runner.run_tool(
                tool_id=row["tool"], target=row["target"], job_id=job_id,
                lease_token=token,
            )
        except Exception as exc:
            _log.warning("drained job %s failed: %s", job_id, exc)
            try:
                store.set_failed(
                    job_id, f"{type(exc).__name__}: {exc}", lease_token=token,
                )
            except Exception:
                _log.exception("could not persist failure for job %s", job_id)
        finally:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass
        # Let event subscribers persist the result and enqueue follow-up work
        # before dropping the fencing token used to accept final findings.
        await asyncio.sleep(0)
        try:
            store.release_lease(job_id, token)
        except Exception:
            _log.exception("could not release completed job lease: %s", job_id)
        ran += 1
    return ran


def drain(store, runner, *, max_jobs: int = 50, exclude_ids=None) -> int:
    """Synchronous wrapper for CLI/one-shot callers."""
    return asyncio.run(drain_async(
        store, runner, max_jobs=max_jobs, exclude_ids=exclude_ids,
    ))
