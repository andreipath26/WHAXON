"""Durable at-least-once lifecycle event delivery for Engine V2 E3.

Lifecycle event storage and consumer cursors are authoritative in JobStore.
A callback may produce an external effect before failing; the cursor then
remains unacknowledged, permitting duplicate delivery after restart. Receivers
must deduplicate by (plan_id, event.id); exactly-once is NOT guaranteed.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any


class WorkflowEventOutbox:
    def __init__(self, store):
        self.store = store

    def deliver(
        self, plan_id: str, consumer_id: str,
        publish: Callable[[dict[str, Any]], Any], *,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Publish a bounded event page and checkpoint only successful calls.

        Never execute the producer side effects here. The caller owns the
        transport, authentication, acknowledgement receipt, and idempotency.
        """
        if not callable(publish):
            raise TypeError("publish must be callable")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer between 1 and 1000")
        audit = self.store.get_workflow_audit_integrity(plan_id)
        if not audit["consistent"]:
            raise ValueError("workflow audit is inconsistent; delivery refused")
        events = self.store.list_unacknowledged_workflow_events(
            plan_id, consumer_id, limit=limit,
        )
        delivered = 0
        for event in events:
            # If the callback raises after a remote effect, do NOT ack it:
            # subsequent calls may deliver the same event again.
            result = publish(event)
            if inspect.isawaitable(result):
                # A coroutine object does not mean publication completed.
                # Do not acknowledge an asynchronous callback not awaited.
                if inspect.iscoroutine(result):
                    result.close()
                raise TypeError("publish must be synchronous; async result not delivered")
            self.store.acknowledge_workflow_events(
                plan_id, consumer_id, event["id"],
            )
            delivered += 1
        return {
            "plan_id": plan_id,
            "consumer_id": consumer_id,
            "delivered": delivered,
            "last_event_id": self.store.get_workflow_event_cursor(
                plan_id, consumer_id,
            ),
            "delivery_guarantee": "at_least_once",
            "receiver_deduplication_required": True,
        }
