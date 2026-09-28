"""Attach next-step suggestions to findings via each adapter's advice.

Subscribes to JobFindings. For each finding, looks up the adapter for
its `source` (tool id) and asks suggest_next_steps(). Persists any
returned advice as a `suggestion` finding on the same job, deduped by
(for_kind, tool).
"""
from __future__ import annotations

from .events import EventBus, JobFindings
from .findings import Finding


class _FindingShim:
    """Read-only attribute accessor so adapters see dataclass-shaped
    fields even when we hand them a raw dict."""
    def __init__(self, d: dict):
        self._d = d or {}
    def __getattr__(self, name):
        if name == "kind":
            return self._d.get("kind")
        if name == "severity":
            return self._d.get("severity")
        if name == "source":
            return self._d.get("source")
        if name == "data":
            return self._d.get("data") or {}
        if name == "raw_line":
            return self._d.get("raw_line") or ""
        if name == "remediation":
            return self._d.get("remediation") or ""
        if name == "impact":
            return self._d.get("impact") or ""
        if name == "cvss":
            return self._d.get("cvss")
        if name == "cwe":
            return self._d.get("cwe") or ""
        if name == "references":
            return tuple(self._d.get("references") or ())
        return None


class Suggester:
    def __init__(self, bus: EventBus, store, adapters_lookup) -> None:
        self.bus = bus
        self.store = store
        self.adapters_lookup = adapters_lookup

    def attach(self) -> None:
        self.bus.subscribe(JobFindings, self._on_findings)

    def _on_findings(self, e: JobFindings) -> None:
        try:
            existing = self.store.get_findings(e.job_id) or []
        except Exception:
            return
        seq = 2000
        seen = set()
        for f in existing:
            d = f.get("data") or {}
            seen.add((f.get("kind"), d.get("for_kind"), d.get("tool")))
        for raw in e.findings or ():
            if raw.get("kind") == "suggestion":
                continue
            try:
                adapter = self.adapters_lookup(raw.get("source") or "")
            except Exception:
                adapter = None
            if adapter is None:
                continue
            try:
                advice = adapter.suggest_next_steps(_FindingShim(raw))
            except Exception:
                continue
            for item in advice or []:
                try:
                    label, tool_id, extra = item
                except Exception:
                    continue
                key = ("suggestion", raw.get("kind"), tool_id)
                if key in seen:
                    continue
                seen.add(key)
                seq += 1
                new = Finding(
                    kind="suggestion",
                    severity="info",
                    source="suggester",
                    data={"label": label, "tool": tool_id,
                          "extra_args": extra or "",
                          "for_kind": raw.get("kind")},
                    raw_line=str(label)[:200],
                )
                try:
                    self.store.append_finding(e.job_id, new.to_dict(), seq)
                except Exception:
                    continue
