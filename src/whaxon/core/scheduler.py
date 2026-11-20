"""Durable, bounded-concurrency DAG scheduler for Engine v2 workflow plans."""
from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Callable
from typing import Any

from .workflow import WorkflowTask

_log = logging.getLogger(__name__)


class WorkflowScheduler:
    """Run persisted DAG nodes through injected policy and capability services.

    Claims are durable and atomic. Independent DAG nodes may run concurrently,
    while dependencies are only released by successful predecessor completion.
    The scheduler never constructs shell commands and authorization is fail-closed.
    """

    def __init__(self, store, *, authorize: Callable[[WorkflowTask], bool],
                 dispatch: Callable[[WorkflowTask], Any], worker_id: str = "workflow-worker"):
        if not callable(authorize) or not callable(dispatch):
            raise TypeError("authorize and dispatch callbacks are required")
        self.store = store
        self.authorize = authorize
        self.dispatch = dispatch
        self.worker_id = worker_id

    async def _invoke(self, callback, task: WorkflowTask, deadline: float):
        """Invoke sync or async policy/provider code within one task deadline.

        Synchronous callbacks run off-loop so lease heartbeats and other tasks
        continue while they work. A timed-out thread cannot be force-killed;
        dispatch timeout is therefore recorded as uncertain, never replayed
        as if cancellation had stopped an external effect.
        """
        loop = asyncio.get_running_loop()
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError
        is_async = inspect.iscoroutinefunction(callback) or inspect.iscoroutinefunction(
            type(callback).__call__
        )
        if is_async:
            result = callback(task)
        else:
            result = await asyncio.wait_for(
                asyncio.to_thread(callback, task), timeout=remaining,
            )
        if inspect.isawaitable(result):
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError
            return await asyncio.wait_for(result, timeout=remaining)
        return result

    async def _heartbeat(self, attempt_id: str, interval: float, lost: asyncio.Event) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                renewed = await asyncio.to_thread(
                    self.store.heartbeat_workflow_attempt, attempt_id,
                )
            except Exception:
                _log.exception("workflow lease heartbeat failed for attempt %s", attempt_id)
                lost.set()
                return
            if not renewed:
                lost.set()
                return

    async def _execute(self, row: dict[str, Any]) -> dict[str, str]:
        task = WorkflowTask(
            id=row["id"], capability_id=row["capability_id"], target=row["target"],
            inputs=row["inputs"], depends_on=tuple(row["depends_on"]),
            permissions=tuple(row["permissions"]), impact=row["impact"],
            timeout_s=row["timeout_s"], idempotency_key=row["idempotency_key"],
        )
        attempt_id = row["attempt_id"]
        lease_lost = asyncio.Event()
        heartbeat_interval = min(10.0, max(0.1, task.timeout_s / 3.0))
        heartbeat = asyncio.create_task(
            self._heartbeat(attempt_id, heartbeat_interval, lease_lost),
        )
        deadline = asyncio.get_running_loop().time() + task.timeout_s
        dispatch_started = False
        try:
            try:
                authorized = await self._invoke(self.authorize, task, deadline)
            except Exception as exc:
                if lease_lost.is_set():
                    return {"task_id": task.id, "status": "uncertain"}
                self.store.finish_task_attempt(
                    attempt_id, "blocked",
                    error=f"policy authorization failed closed: {type(exc).__name__}",
                )
                return {"task_id": task.id, "status": "blocked"}
            if lease_lost.is_set():
                return {"task_id": task.id, "status": "uncertain"}
            if authorized is not True:
                self.store.finish_task_attempt(
                    attempt_id, "blocked", error="deterministic policy denied task",
                )
                return {"task_id": task.id, "status": "blocked"}

            # Cancellation can arrive while authorization is in progress.
            # Refuse dispatch if the durable stop barrier has already been set.
            if self.store.workflow_cancellation_requested(row["plan_id"]):
                self.store.finish_task_attempt(
                    attempt_id, "cancelled", error="cancelled before provider dispatch",
                )
                return {"task_id": task.id, "status": "cancelled"}
            # Recheck the policy at the consequential dispatch boundary:
            # authorization may expire or scope may change while queued.
            try:
                still_authorized = await self._invoke(self.authorize, task, deadline)
            except Exception as exc:
                self.store.finish_task_attempt(
                    attempt_id, "blocked",
                    error=f"dispatch-boundary authorization failed closed: {type(exc).__name__}",
                )
                return {"task_id": task.id, "status": "blocked"}
            if still_authorized is not True:
                self.store.finish_task_attempt(
                    attempt_id, "blocked", error="dispatch-boundary policy denied task",
                )
                return {"task_id": task.id, "status": "blocked"}
            if lease_lost.is_set() or not self.store.workflow_attempt_owned(attempt_id):
                return {"task_id": task.id, "status": "uncertain"}
            if not self.store.mark_workflow_dispatch_started(row["plan_id"], attempt_id):
                # This gate may close for cancellation, deadline, resource or
                # mission budget reasons. A budget refusal is NOT cancellation.
                cancelled = self.store.workflow_cancellation_requested(row["plan_id"])
                outcome = "cancelled" if cancelled else "blocked"
                error = (
                    "cancelled before provider dispatch" if cancelled
                    else "durable execution gate closed before provider dispatch"
                )
                self.store.finish_task_attempt(attempt_id, outcome, error=error)
                return {
                    "task_id": task.id,
                    "status": self.store.get_workflow_attempt_status(attempt_id),
                }
            dispatch_started = True
            result = await self._invoke(self.dispatch, task, deadline)
            if lease_lost.is_set():
                return {"task_id": task.id, "status": "uncertain"}
            # A stop request during external dispatch cannot prove that side
            # effects were cancelled. Do not report a clean post-stop success.
            if self.store.workflow_cancellation_requested(row["plan_id"]):
                self.store.finish_task_attempt(
                    attempt_id, "uncertain",
                    error="cancellation requested while provider was executing; outcome requires reconciliation",
                )
                return {"task_id": task.id, "status": "uncertain"}
            self.store.finish_task_attempt(attempt_id, "succeeded", result=result)
            # Cancellation can win the commit after our last policy read.
            committed = self.store.get_workflow_attempt_status(attempt_id)
            return {"task_id": task.id, "status": committed}
        except TimeoutError:
            if lease_lost.is_set():
                return {"task_id": task.id, "status": "uncertain"}
            self.store.finish_task_attempt(
                attempt_id, "uncertain", error="task timed out; reconcile before retry",
            )
            return {"task_id": task.id, "status": "uncertain"}
        except asyncio.CancelledError:
            if not lease_lost.is_set():
                self.store.finish_task_attempt(
                    attempt_id, "uncertain",
                    error="scheduler cancelled while task was active; reconcile before retry",
                )
            raise
        except Exception as exc:
            if lease_lost.is_set():
                return {"task_id": task.id, "status": "uncertain"}
            _log.exception("workflow task %s failed", task.id)
            # A provider may have produced external effects before raising.
            # The scheduler cannot distinguish a pre-effect provider failure
            # from a post-effect disconnect. Never make either automatically
            # retryable after dispatch crossed the durable intent boundary.
            # Only failures known to precede dispatch can be safely retried.
            outcome = "uncertain" if dispatch_started else "failed"
            error = (
                f"provider outcome unknown after dispatch: {type(exc).__name__}; "
                "reconcile before retry"
                if dispatch_started else f"{type(exc).__name__}: {exc}"
            )
            self.store.finish_task_attempt(
                attempt_id, outcome, error=error,
            )
            committed = self.store.get_workflow_attempt_status(attempt_id)
            return {"task_id": task.id, "status": committed}
        finally:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)

    async def run(self, plan_id: str, *, max_tasks: int = 100,
                  max_attempts: int = 2, max_concurrency: int = 4) -> dict[str, Any]:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in (max_tasks, max_attempts, max_concurrency)
        ):
            raise ValueError("max_tasks, max_attempts and max_concurrency must be positive integers")
        if self.store.get_workflow_plan(plan_id) is None:
            raise ValueError(f"unknown workflow plan: {plan_id}")
        # Check even when the plan has no claimable tasks. Without this,
        # terminal task rows could let a tampered plan return "complete".
        self.store.verify_workflow_plan_integrity(plan_id)
        # Caller-supplied values may tighten, but never loosen durable limits.
        limits = self.store.get_workflow_limits(plan_id)
        max_tasks = min(max_tasks, limits["max_total_attempts"])
        max_concurrency = min(max_concurrency, limits["max_concurrency"])

        claimed = 0
        outcomes: list[dict[str, str]] = []
        claim_lock = asyncio.Lock()

        async def worker() -> None:
            nonlocal claimed
            while True:
                async with claim_lock:
                    if claimed >= max_tasks:
                        return
                    row = self.store.claim_ready_workflow_task(
                        plan_id, self.worker_id, max_attempts=max_attempts,
                    )
                    if row is None:
                        return
                    claimed += 1
                outcomes.append(await self._execute(row))

        await asyncio.gather(*(worker() for _ in range(min(max_concurrency, max_tasks))))
        tasks = self.store.list_workflow_tasks(plan_id)
        # Failed attempts may still be retryable. Report completion only when
        # every task has reached a terminal outcome under the attempt policy.
        # Database counts avoid truncation of long-lived plans at API page limits.
        attempts = self.store.count_workflow_task_attempts(plan_id)
        counts = attempts
        terminal = {"succeeded", "blocked", "cancelled", "uncertain"}
        complete = all(
            task["status"] in terminal
            or (
                task["status"] == "failed"
                and counts.get(task["id"], 0) >= max_attempts
            )
            for task in tasks
        )
        return {
            "plan_id": plan_id, "attempts": claimed, "outcomes": outcomes,
            "tasks": [{"id": task["id"], "status": task["status"]} for task in tasks],
            "complete": complete,
        }
