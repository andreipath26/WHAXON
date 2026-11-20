"""E4 capability-level provider reconciliation across trusted implementations.

This batch verifies that read-only audit never changes dispatch eligibility,
provider selection, or the identity approved by an immutable plan.
"""
from types import SimpleNamespace

import pytest

from whaxon.core.capabilities import CapabilityManifest, CapabilityUnavailable
from whaxon.core.providers import BoundProviderRouter
from whaxon.core.workflow import WorkflowTask


class _Provider:
    def __init__(self, provider_id, capability="network.services.discover"):
        self.manifest = CapabilityManifest(
            capability, provider_id, "v1", ("local_process",),
            permissions=("network.scan",), impact="moderate",
        )
        self.dispatched = []

    def bindings(self):
        return (self.manifest,)

    def resolve_task(self, task, *, require_installed=False):
        assert task.capability_id == self.manifest.capability_id
        return SimpleNamespace(manifest=self.manifest)

    async def dispatch(self, task):
        self.dispatched.append(task.id)
        return {
            "provider_id": self.manifest.provider_id,
            "provider_version": self.manifest.provider_version,
            "manifest_fingerprint": self.manifest.fingerprint,
        }

    def inventory(self):
        return []

    def portfolio_audit(self):
        return {"schema_version": "whaxon.portfolio-audit.v1",
                "rows": [], "execution_enabled_by_audit": False}


def test_e4_audit_reconciles_selected_and_unselected_trusted_alternatives():
    primary = _Provider("trusted.primary")
    secondary = _Provider("trusted.secondary")
    router = BoundProviderRouter(
        (primary, secondary),
        preferred_providers={"network.services.discover": "trusted.secondary"},
    )
    before = router.manifest_for("network.services.discover")
    report = router.portfolio_audit()
    rows = report["operation_bindings"]
    assert [(row["provider_id"], row["selection_status"]) for row in rows] == [
        ("trusted.primary", "unselected"),
        ("trusted.secondary", "selected"),
    ]
    assert report["execution_enabled_by_audit"] is False
    assert all(row["authorization_required"] is True for row in rows)
    assert all(row["lab_validated"] is False for row in rows)
    assert rows[0]["manifest_fingerprint"] is None
    assert rows[1]["manifest_fingerprint"] == secondary.manifest.fingerprint
    assert router.manifest_for("network.services.discover") == before


def test_e4_audit_reports_missing_preferred_provider_without_fallback():
    router = BoundProviderRouter(
        (_Provider("trusted.available"),),
        preferred_providers={"network.services.discover": "trusted.missing"},
    )
    rows = router.operation_reconciliation()
    assert any(row["selection_status"] == "preferred_provider_missing"
               and row["provider_id"] == "trusted.missing" for row in rows)
    assert not any(row["selected"] for row in rows)
    with pytest.raises(CapabilityUnavailable, match="preferred execution provider"):
        router.manifest_for("network.services.discover")


def test_e4_audit_reports_preference_without_any_trusted_provider():
    router = BoundProviderRouter(
        (), preferred_providers={"web.server.audit": "trusted.not-installed"},
    )
    assert router.operation_reconciliation() == [{
        "capability_id": "web.server.audit",
        "provider_id": "trusted.not-installed",
        "selected": False,
        "selection_status": "preferred_provider_missing",
        "selection_explicit": True,
        "manifest_fingerprint": None,
        "authorization_required": True,
        "smoke_tested": False,
        "lab_validated": False,
        "end_to_end_verified": False,
    }]
    with pytest.raises(CapabilityUnavailable):
        router.manifest_for("web.server.audit")


def test_e4_audit_cannot_approve_or_execute_a_semantic_plan():
    provider = _Provider("trusted.primary")
    router = BoundProviderRouter((provider,))
    task = WorkflowTask(
        "scan", "network.services.discover", "192.0.2.10",
        permissions=("network.scan",), impact="moderate",
    )
    assert router.plan_binding_valid(task, {}) is False
    _ = router.portfolio_audit()
    assert provider.dispatched == []
    assert router.plan_binding_valid(task, {}) is False
    assert router.plan_binding_valid(task, {
        "provider_bindings": {"scan": {
            "provider_id": provider.manifest.provider_id,
            "manifest_fingerprint": provider.manifest.fingerprint,
        }},
    }) is True


def test_e4_audit_refuses_ambiguous_unconfigured_alternatives():
    first = _Provider("trusted.first")
    second = _Provider("trusted.second")
    with pytest.raises(ValueError, match="ambiguous bound capability"):
        BoundProviderRouter((first, second))
