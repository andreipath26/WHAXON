"""E4: the API-facing provider list must never advertise unselected execution."""
from types import SimpleNamespace

from whaxon.core.capabilities import CapabilityManifest
from whaxon.core.providers import BoundProviderRouter


class _Provider:
    def __init__(self, identity, *, installed=True):
        self.manifest = CapabilityManifest(
            "service.http.enumerate", identity, "1", ("local_process",),
            target_types=("hostname",), impact="low",
        )
        self.installed = installed
        self.inventory_row = {
            "capability_id": self.manifest.capability_id,
            "provider_id": identity,
            "registered": True,
            "installed": installed,
            "executable": installed,
            "readiness": "installed" if installed else "registered",
            "reason": "ready_for_local_execution" if installed else "missing_binary",
        }

    def bindings(self):
        return (self.manifest,)

    def resolve_task(self, task, *, require_installed=False):
        return SimpleNamespace(manifest=self.manifest)

    async def dispatch(self, task):
        raise AssertionError("inventory must never dispatch")

    def inventory(self):
        return [self.inventory_row]


def test_e4_api_inventory_marks_unselected_installed_provider_non_executable():
    alpha = _Provider("trusted.alpha")
    beta = _Provider("trusted.beta")
    router = BoundProviderRouter(
        (alpha, beta),
        preferred_providers={"service.http.enumerate": "trusted.beta"},
    )
    rows = {row["provider_id"]: row for row in router.inventory()}
    assert rows["trusted.alpha"]["installed"] is True
    assert rows["trusted.alpha"]["selected_for_execution"] is False
    assert rows["trusted.alpha"]["executable"] is False
    assert rows["trusted.alpha"]["reason"] == "provider_not_selected_for_execution"
    assert rows["trusted.beta"]["selected_for_execution"] is True
    assert rows["trusted.beta"]["executable"] is True
    assert alpha.inventory_row["executable"] is True


def test_e4_missing_selected_provider_does_not_advertise_unsafe_fallback():
    alpha = _Provider("trusted.alpha")
    router = BoundProviderRouter(
        (alpha,),
        preferred_providers={"service.http.enumerate": "trusted.missing"},
    )
    row = router.inventory()[0]
    assert row["installed"] is True
    assert row["executable"] is False
    assert row["selected_for_execution"] is False


def test_e4_selected_but_missing_binary_does_not_claim_execution_readiness():
    alpha = _Provider("trusted.alpha", installed=False)
    router = BoundProviderRouter((alpha,))
    row = router.inventory()[0]
    assert row["selected_for_execution"] is True
    assert row["installed"] is False
    assert row["executable"] is False
    assert row["reason"] == "missing_binary"


def test_e4_router_inventory_is_repeatable_and_non_mutating():
    alpha = _Provider("trusted.alpha")
    beta = _Provider("trusted.beta")
    router = BoundProviderRouter(
        (alpha, beta),
        preferred_providers={"service.http.enumerate": "trusted.alpha"},
    )
    first = router.inventory()
    second = router.inventory()
    assert first == second
    assert all("selected_for_execution" not in item for item in (
        alpha.inventory_row, beta.inventory_row,
    ))
    assert router.manifest_for("service.http.enumerate") == alpha.manifest
