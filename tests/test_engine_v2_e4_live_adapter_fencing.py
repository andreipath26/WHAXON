"""Engine V2 E4: live adapter migration and manifest drift are fail closed."""
from types import SimpleNamespace

import pytest

from whaxon.core.capabilities import CapabilityRegistry, CapabilityUnavailable
from whaxon.core.providers import BoundProviderRouter, CatalogAdapterProvider
from whaxon.core.workflow import WorkflowTask


class _Catalog:
    def __init__(self, tool):
        self.tool = tool

    def list(self):
        return [self.tool]

    def get(self, tool_id):
        return self.tool if tool_id == self.tool.id else None


def _router(monkeypatch):
    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda _tool: object())
    monkeypatch.setattr(whaxon.adapters, "list_adapters", lambda: ["nmap"])
    tool = SimpleNamespace(
        id="nmap", name="nmap", transport="cli",
        command="nmap", executable="nmap", args=["-sV"], enabled=True,
    )
    registry = CapabilityRegistry()
    provider = CatalogAdapterProvider(
        catalog=_Catalog(tool), runner=SimpleNamespace(),
        store=SimpleNamespace(), registry=registry,
    )
    return BoundProviderRouter((provider,)), tool, registry


def test_e4_registered_adapter_disappearance_refuses_resolution(monkeypatch):
    import whaxon.adapters

    router, _, registry = _router(monkeypatch)
    before = registry.digest
    assert router.portfolio_audit()["summary"]["bound"] == 1

    monkeypatch.setattr(whaxon.adapters, "list_adapters", lambda: [])
    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda _tool: None)
    report = router.portfolio_audit()
    row = report["rows"][0]
    assert report["summary"]["stale_binding"] == 1
    assert row["state"] == "stale_binding"
    assert row["reason"] == "registered_adapter_disappeared"
    assert row["previously_bound"] is True
    assert row["binding_current"] is False
    assert row["v2_provider_bound"] is False
    assert report["execution_enabled_by_audit"] is False
    assert registry.digest == before

    task = WorkflowTask(
        "recon", "tool.nmap", "192.0.2.10",
        impact="moderate", permissions=("network.scan",),
    )
    with pytest.raises(CapabilityUnavailable, match="no longer registered"):
        router.resolve_task(task, require_installed=True)


def test_e4_catalog_drift_is_stale_and_does_not_rebind(monkeypatch):
    router, tool, registry = _router(monkeypatch)
    initial = router.portfolio_audit()["rows"][0]
    assert initial["state"] == "bound"
    fingerprint = initial["bound_manifest_fingerprint"]
    digest = registry.digest
    tool.args = ["--changed"]
    changed = router.portfolio_audit()["rows"][0]
    assert changed["state"] == "stale_binding"
    assert changed["reason"] == "catalog_contract_changed"
    assert changed["bound_manifest_fingerprint"] == fingerprint
    assert changed["binding_current"] is False
    assert registry.digest == digest


def test_e4_stale_manifest_never_silently_rebinds(monkeypatch):
    router, _, registry = _router(monkeypatch)
    monkeypatch.setattr(registry, "list", lambda _capability=None: [])
    row = router.portfolio_audit()["rows"][0]
    assert row["state"] == "stale_binding"
    assert row["reason"] == "manifest_binding_mismatch"
    assert row["v2_provider_bound"] is False
    assert router.portfolio_audit()["summary"]["stale_binding"] == 1
