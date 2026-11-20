from types import SimpleNamespace

import pytest

from whaxon.core.capabilities import CapabilityRegistry
from whaxon.core.providers import CatalogAdapterProvider
from whaxon.core.workflow import WorkflowTask


class _Catalog:
    def __init__(self, tools):
        self.tools = {tool.id: tool for tool in tools}

    def list(self):
        return list(self.tools.values())

    def get(self, tool_id):
        return self.tools.get(tool_id)


class _Runner:
    def __init__(self):
        self.calls = []

    async def run_tool(self, **kwargs):
        self.calls.append(kwargs)
        return kwargs["job_id"]


class _Store:
    def get(self, job_id):
        return {
            "id": job_id, "tool": "nmap", "target": "192.0.2.10",
            "status": "finished", "exit_code": 0,
            "duration_s": 0.25, "error": None,
        }

    def get_findings(self, job_id):
        return [{"kind": "open_port", "data": {"port": 443}}]


def _tool(tool_id="nmap", *, available=True, category="recon"):
    return SimpleNamespace(id=tool_id, available=available, category=category)


def test_catalog_adapter_provider_executes_through_core_runner(monkeypatch):
    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    catalog = _Catalog([_tool()])
    runner = _Runner()
    provider = CatalogAdapterProvider(
        catalog=catalog, runner=runner, store=_Store(),
        registry=CapabilityRegistry(),
    )

    import asyncio
    result = asyncio.run(provider.dispatch(
        WorkflowTask(
            "scan", "tool.nmap", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        ),
    ))

    assert result["tool_id"] == "nmap"
    assert result["findings"][0]["data"]["port"] == 443
    assert runner.calls[0]["tool_id"] == "nmap"
    assert runner.calls[0]["target"] == "192.0.2.10"
    assert runner.calls[0]["phase"] == "workflow"


def test_catalog_adapter_provider_rejects_dynamic_cli_arguments(monkeypatch):
    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=_Runner(), store=_Store(),
        registry=CapabilityRegistry(),
    )
    with pytest.raises(ValueError, match="no dynamic inputs"):
        import asyncio
        asyncio.run(provider.dispatch(
            WorkflowTask(
                "scan", "tool.nmap", "192.0.2.10",
                inputs={"extra_args": "-p-"}, permissions=("network.scan",),
                impact="moderate",
            ),
        ))


def test_catalog_adapter_provider_refuses_missing_binary(monkeypatch):
    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool(available=False)]), runner=_Runner(), store=_Store(),
        registry=CapabilityRegistry(),
    )
    with pytest.raises(RuntimeError, match="not installed"):
        import asyncio
        asyncio.run(provider.dispatch(
            WorkflowTask(
            "scan", "tool.nmap", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        ),
        ))


def test_provider_does_not_register_exploit_or_credential_tools(monkeypatch):
    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    registry = CapabilityRegistry()
    CatalogAdapterProvider(
        catalog=_Catalog([_tool("hydra"), _tool("commix"), _tool("nmap")]),
        runner=_Runner(), store=_Store(), registry=registry,
    )
    assert [item.capability_id for item in registry.list()] == ["tool.nmap"]


def test_core_default_workflow_policy_requires_scope_permission_and_matching_impact():
    from types import SimpleNamespace

    from whaxon.core import Core
    from whaxon.core.capabilities import CapabilityManifest, CapabilityRegistry

    core = Core.__new__(Core)
    core.capabilities = CapabilityRegistry()
    core.capabilities.register(CapabilityManifest(
        capability_id="tool.nmap",
        provider_id="whaxon.adapter.nmap",
        provider_version="catalog-v1",
        transports=("local_process",),
        permissions=("network.scan",),
        impact="moderate",
    ))
    core.scope = SimpleNamespace(
        check=lambda target: SimpleNamespace(allowed=target == "192.0.2.10"),
    )
    allowed = WorkflowTask(
        "scan", "tool.nmap", "192.0.2.10",
        permissions=("network.scan",), impact="moderate",
    )
    assert core.authorize_workflow_task(allowed) is True
    assert core.authorize_workflow_task(WorkflowTask(
        "scan", "tool.nmap", "192.0.2.10", impact="moderate",
    )) is False
    assert core.authorize_workflow_task(WorkflowTask(
        "scan", "tool.nmap", "192.0.2.10",
        permissions=("network.scan",), impact="low",
    )) is False
    assert core.authorize_workflow_task(WorkflowTask(
        "scan", "tool.nmap", "198.51.100.20",
        permissions=("network.scan",), impact="moderate",
    )) is False


def test_core_plan_bound_policy_requires_exact_unrevoked_approval(tmp_path):
    import time
    from types import SimpleNamespace

    from whaxon.core import Core
    from whaxon.core.capabilities import CapabilityManifest, CapabilityRegistry
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    core = Core.__new__(Core)
    core.store = JobStore(tmp_path / "policy-approval.db")
    core.capabilities = CapabilityRegistry()
    core.capabilities.register(CapabilityManifest(
        capability_id="tool.nmap",
        provider_id="whaxon.adapter.nmap",
        provider_version="catalog-v1",
        transports=("local_process",),
        permissions=("network.scan",),
        impact="moderate",
    ))
    core.scope = SimpleNamespace(
        check=lambda target: SimpleNamespace(allowed=target == "192.0.2.10"),
    )
    task = WorkflowTask(
        "scan", "tool.nmap", "192.0.2.10",
        permissions=("network.scan",), impact="moderate",
    )
    plan = WorkflowPlan("mission", (task,))
    core.store.create_mission("mission", "controlled lab")
    core.store.save_workflow_plan("p", plan)
    assert core.authorize_workflow_task_for_plan("p", task) is False
    core.store.grant_workflow_approval(
        "p", "scan", "approval", "operator", expires_at=time.time() + 300,
    )
    assert core.authorize_workflow_task_for_plan("p", task) is True
    assert core.authorize_workflow_task_for_plan("p", WorkflowTask(
        "scan", "tool.nmap", "198.51.100.20",
        permissions=("network.scan",), impact="moderate",
    )) is False
    core.store.revoke_workflow_approval("p", "approval", actor="operator")
    assert core.authorize_workflow_task_for_plan("p", task) is False


def test_engine_v2_scope_execution_gate_rejects_dns_rebinding_preview():
    from types import SimpleNamespace

    from whaxon.core import Core
    from whaxon.core.capabilities import CapabilityManifest, CapabilityRegistry

    core = Core.__new__(Core)
    core.capabilities = CapabilityRegistry()
    core.capabilities.register(CapabilityManifest(
        capability_id="tool.nmap", provider_id="whaxon.adapter.nmap",
        provider_version="catalog-v1", transports=("local_process",),
        permissions=("network.scan",), impact="moderate",
    ))
    core.scope = SimpleNamespace(
        check=lambda target: SimpleNamespace(allowed=True),
        check_for_execution=lambda target: SimpleNamespace(allowed=False),
    )
    task = WorkflowTask(
        "scan", "tool.nmap", "lab.example",
        permissions=("network.scan",), impact="moderate",
    )
    assert core.authorize_workflow_task(task) is False


def test_engine_v2_scope_requires_literal_true_not_truthy_authorization():
    from types import SimpleNamespace

    from whaxon.core import Core
    from whaxon.core.capabilities import CapabilityManifest, CapabilityRegistry

    core = Core.__new__(Core)
    core.capabilities = CapabilityRegistry()
    core.capabilities.register(CapabilityManifest(
        capability_id="tool.nmap", provider_id="whaxon.adapter.nmap",
        provider_version="catalog-v1", transports=("local_process",),
        permissions=("network.scan",), impact="moderate",
    ))
    core.scope = SimpleNamespace(check=lambda target: SimpleNamespace(allowed="yes"))
    task = WorkflowTask(
        "scan", "tool.nmap", "192.0.2.10",
        permissions=("network.scan",), impact="moderate",
    )
    assert core.authorize_workflow_task(task) is False


def test_engine_v2_plan_authorization_rejects_modified_low_impact_nodes(tmp_path):
    from types import SimpleNamespace

    from whaxon.core import Core
    from whaxon.core.capabilities import CapabilityManifest, CapabilityRegistry
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    core = Core.__new__(Core)
    core.store = JobStore(tmp_path / "plan-auth-identity.db")
    core.capabilities = CapabilityRegistry()
    core.capabilities.register(CapabilityManifest(
        capability_id="tool.fixture", provider_id="whaxon.adapter.fixture",
        provider_version="catalog-v1", transports=("local_process",),
        permissions=(), impact="low",
    ))
    core.scope = SimpleNamespace(check=lambda target: SimpleNamespace(allowed=True))
    original = WorkflowTask("scan", "tool.fixture", "192.0.2.10", impact="low")
    core.store.create_mission("m", "controlled lab")
    core.store.save_workflow_plan("p", WorkflowPlan("m", (original,)))
    assert core.authorize_workflow_task_for_plan("p", original) is True
    assert core.authorize_workflow_task_for_plan(
        "p", WorkflowTask("scan", "tool.fixture", "192.0.2.11", impact="low"),
    ) is False
    assert core.authorize_workflow_task_for_plan("missing", original) is False
    core.store.request_workflow_cancellation("p")
    assert core.authorize_workflow_task_for_plan("p", original) is False


def test_engine_v2_plan_authorization_rejects_tampered_sqlite_plan(tmp_path):
    from types import SimpleNamespace

    from whaxon.core import Core
    from whaxon.core.capabilities import CapabilityManifest, CapabilityRegistry
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    core = Core.__new__(Core)
    core.store = JobStore(tmp_path / "tampered-auth.db")
    core.capabilities = CapabilityRegistry()
    core.capabilities.register(CapabilityManifest(
        capability_id="tool.fixture", provider_id="whaxon.adapter.fixture",
        provider_version="catalog-v1", transports=("local_process",),
        permissions=(), impact="low",
    ))
    core.scope = SimpleNamespace(check=lambda target: SimpleNamespace(allowed=True))
    task = WorkflowTask("scan", "tool.fixture", "192.0.2.10", impact="low")
    core.store.create_mission("m", "controlled lab")
    core.store.save_workflow_plan("p", WorkflowPlan("m", (task,)))
    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_tasks SET target=? WHERE plan_id=?",
            ("192.0.2.200", "p"),
        )
    finally:
        conn.close()
    assert core.authorize_workflow_task_for_plan("p", task) is False


def test_engine_v2_scheduler_requires_plan_bound_policy_by_default(tmp_path):
    from whaxon.core import Core
    from whaxon.core.store import JobStore

    core = Core.__new__(Core)
    core.store = JobStore(tmp_path / "scheduler-approval-default.db")
    with pytest.raises(ValueError, match="plan_id required"):
        core.workflow_scheduler()


def test_engine_v2_scheduler_uses_plan_bound_approval_instead_of_scope_only(tmp_path):
    import asyncio
    from types import SimpleNamespace

    from whaxon.core import Core
    from whaxon.core.capabilities import CapabilityManifest, CapabilityRegistry
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan, WorkflowTask

    core = Core.__new__(Core)
    core.store = JobStore(tmp_path / "scheduler-plan-approval.db")
    core.capabilities = CapabilityRegistry()
    core.capabilities.register(CapabilityManifest(
        capability_id="tool.fixture", provider_id="whaxon.adapter.fixture",
        provider_version="catalog-v1", transports=("local_process",),
        permissions=("network.scan",), impact="moderate",
    ))
    core.scope = SimpleNamespace(check=lambda target: SimpleNamespace(allowed=True))
    core.store.create_mission("m", "controlled lab")
    task = WorkflowTask(
        "scan", "tool.fixture", "192.0.2.10",
        permissions=("network.scan",), impact="moderate",
    )
    core.store.save_workflow_plan("p", WorkflowPlan("m", (task,)))
    dispatched = []
    scheduler = core.workflow_scheduler(
        plan_id="p", dispatch=lambda task: dispatched.append(task.id),
    )
    result = asyncio.run(scheduler.run("p"))
    assert dispatched == []
    assert result["tasks"] == [{"id": "scan", "status": "blocked"}]


def test_engine_v2_scope_revocation_from_another_process_takes_effect(tmp_path):
    import json

    from whaxon.core import Core
    from whaxon.core.capabilities import CapabilityManifest, CapabilityRegistry
    from whaxon.core.scope import ScopeManager

    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "enabled": True, "engagement": "test",
        "in_scope": ["lab.example"], "out_of_scope": [],
    }), encoding="utf-8")
    core = Core.__new__(Core)
    core.capabilities = CapabilityRegistry()
    core.capabilities.register(CapabilityManifest(
        capability_id="tool.fixture", provider_id="whaxon.adapter.fixture",
        provider_version="catalog-v1", transports=("local_process",),
        permissions=(), impact="low",
    ))
    core.scope = ScopeManager(scope_path)
    task = WorkflowTask("scan", "tool.fixture", "lab.example", impact="low")
    assert core.authorize_workflow_task(task) is True
    scope_path.write_text(json.dumps({
        "enabled": True, "engagement": "test",
        "in_scope": ["lab.example"], "out_of_scope": ["lab.example"],
    }), encoding="utf-8")
    assert core.authorize_workflow_task(task) is False
    scope_path.write_text("{invalid", encoding="utf-8")
    assert core.authorize_workflow_task(task) is False


@pytest.mark.parametrize("target, expected", [
    ("192.0.2.10", "ip"),
    ("2001:db8::1", "ip"),
    ("lab.example", "hostname"),
    ("https://lab.example/path", "url"),
])
def test_catalog_target_type_classification_is_pure(target, expected):
    from whaxon.core.providers import _target_type
    assert _target_type(target) == expected


@pytest.mark.parametrize("target", [
    "", " lab.example", "lab.example/path", "user@lab.example",
    "https://user:secret@lab.example/", "https://lab.example/#fragment",
    "ftp://lab.example/", "lab.example?query=1",
])
def test_catalog_target_type_rejects_ambiguous_or_credential_targets(target):
    from whaxon.core.providers import _target_type
    with pytest.raises(ValueError):
        _target_type(target)


def test_catalog_provider_selects_bound_adapter_over_third_party_registry_entry(monkeypatch):
    import asyncio

    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityManifest

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    registry = CapabilityRegistry()
    runner = _Runner()
    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=runner, store=_Store(), registry=registry,
    )
    # Higher-readiness third-party provider cannot be used as a catalog adapter.
    registry.register(CapabilityManifest(
        capability_id="tool.nmap", provider_id="other.provider",
        provider_version="1", transports=("local_process",),
        target_types=("ip",), readiness="end_to_end_verified",
    ))
    result = asyncio.run(provider.dispatch(WorkflowTask(
            "scan", "tool.nmap", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        )))
    assert result["tool_id"] == "nmap"
    assert len(runner.calls) == 1


def test_catalog_provider_rejects_unsupported_target_type_before_dispatch(monkeypatch):
    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityUnavailable

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    registry = CapabilityRegistry()
    runner = _Runner()
    CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=runner, store=_Store(), registry=registry,
    )
    # Explicit resolver contract: a provider limited to hostnames must not
    # match a URL task, even when the capability identifier is identical.
    with pytest.raises(CapabilityUnavailable):
        registry.resolve("tool.nmap", __import__(
            "whaxon.core.capabilities", fromlist=["CapabilityRequirements"]
        ).CapabilityRequirements(target_type="unsupported-target"))
    assert runner.calls == []


def test_catalog_dispatch_rejects_undeclared_task_permissions(monkeypatch):
    import asyncio

    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityUnavailable

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    runner = _Runner()
    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=runner, store=_Store(),
        registry=CapabilityRegistry(),
    )
    with pytest.raises(CapabilityUnavailable, match="permissions"):
        asyncio.run(provider.dispatch(WorkflowTask(
            "scan", "tool.nmap", "192.0.2.10",
            permissions=("credentials.read",), impact="moderate",
        )))
    assert runner.calls == []


def test_catalog_dispatch_pins_bound_version_against_newer_registry_entry(monkeypatch):
    import asyncio

    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityManifest

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    registry = CapabilityRegistry()
    runner = _Runner()
    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=runner, store=_Store(), registry=registry,
    )
    registry.register(CapabilityManifest(
        capability_id="tool.nmap", provider_id="whaxon.adapter.nmap",
        provider_version="catalog-v3", transports=("local_process",),
        target_types=("hostname", "ip", "url"), permissions=("network.scan",),
        impact="moderate", readiness="end_to_end_verified",
    ))
    result = asyncio.run(provider.dispatch(WorkflowTask(
            "scan", "tool.nmap", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        )))
    assert result["tool_id"] == "nmap"
    assert len(runner.calls) == 1


def test_catalog_dispatch_rejects_job_identity_mismatch(monkeypatch):
    import asyncio

    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())

    class WrongJobStore(_Store):
        def get(self, job_id):
            return {**super().get(job_id), "tool": "nikto", "target": "192.0.2.99"}

    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=_Runner(),
        store=WrongJobStore(), registry=CapabilityRegistry(),
    )
    with pytest.raises(RuntimeError, match="identity"):
        asyncio.run(provider.dispatch(WorkflowTask(
            "scan", "tool.nmap", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        )))


def test_core_authorization_rejects_provider_without_local_transport():
    from types import SimpleNamespace

    from whaxon.core import Core
    from whaxon.core.capabilities import CapabilityManifest

    core = Core.__new__(Core)
    core.capabilities = CapabilityRegistry()
    core.capabilities.register(CapabilityManifest(
        capability_id="tool.fixture", provider_id="remote.fixture",
        provider_version="1", transports=("remote_agent",),
        target_types=("ip",), impact="low",
    ))
    core.scope = SimpleNamespace(check=lambda target: SimpleNamespace(allowed=True))
    assert core.authorize_workflow_task(
        WorkflowTask("scan", "tool.fixture", "192.0.2.10", impact="low"),
    ) is False


def test_provider_inventory_reports_installed_and_missing_without_false_validation(monkeypatch):
    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    registry = CapabilityRegistry()
    catalog = _Catalog([_tool("nmap", available=True), _tool("nikto", available=False)])
    provider = CatalogAdapterProvider(
        catalog=catalog, runner=_Runner(), store=_Store(), registry=registry,
    )
    inventory = {item["capability_id"]: item for item in provider.inventory()}
    assert inventory["tool.nmap"]["executable"] is True
    assert inventory["tool.nmap"]["readiness"] == "installed"
    assert inventory["tool.nikto"]["executable"] is False
    assert inventory["tool.nikto"]["reason"] == "binary_not_installed"
    assert not any(item["lab_validated"] for item in inventory.values())
    assert registry.list("tool.nmap")[0].readiness == "registered"


def test_catalog_provider_ignores_unbound_newer_manifest_when_pinned_version_available(monkeypatch):
    import asyncio

    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityManifest

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    registry = CapabilityRegistry()
    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=_Runner(), store=_Store(),
        registry=registry,
    )
    registry.register(CapabilityManifest(
        capability_id="tool.nmap", provider_id="whaxon.adapter.nmap",
        provider_version="catalog-v2", transports=("local_process",),
        target_types=("hostname", "ip", "url"), permissions=("network.scan",),
        impact="moderate", readiness="end_to_end_verified",
    ))
    result = asyncio.run(provider.dispatch(WorkflowTask(
            "scan", "tool.nmap", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        )))
    assert result["tool_id"] == "nmap"


@pytest.mark.parametrize("tool_id, target, expected", [
    ("nmap", "192.0.2.10", True),
    ("nmap", "https://lab.example", False),
    ("gobuster", "lab.example", True),
    ("gobuster", "https://lab.example", False),
    ("ffuf", "https://lab.example", True),
    ("ffuf", "lab.example", False),
    ("sqlmap", "https://lab.example/?id=1", True),
    ("sqlmap", "192.0.2.10", False),
    ("dnsrecon", "lab.example", True),
    ("dnsrecon", "https://lab.example", False),
])
def test_resolver_matches_packaged_target_templates(monkeypatch, tool_id, target, expected):
    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityUnavailable

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool(tool_id)]), runner=_Runner(), store=_Store(),
        registry=CapabilityRegistry(),
    )
    task = WorkflowTask("scan", f"tool.{tool_id}", target, permissions=("network.scan",), impact="moderate")
    if expected:
        assert provider.resolve_task(task).manifest.capability_id == f"tool.{tool_id}"
    else:
        with pytest.raises(CapabilityUnavailable):
            provider.resolve_task(task)


@pytest.mark.parametrize("target", [
    "example.com:abc", "example.com:123", "localhost:80", "bad..example",
    "https://example.com:abc/", "https://example.com:99999/",
    "http://[::1", "https://example.com/hello world",
    "example.com/../../", "foo_bar.example",
])
def test_target_classifier_fails_closed_on_malformed_authorities(target):
    from whaxon.core.providers import _target_type

    with pytest.raises(ValueError):
        _target_type(target)


def test_provider_inventory_checks_live_binary(monkeypatch):
    import whaxon.adapters
    import whaxon.core.providers as provider_module

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    tool = SimpleNamespace(id="nmap", available=True, binary="nmap", transport="cli")
    provider = CatalogAdapterProvider(
        catalog=_Catalog([tool]), runner=_Runner(), store=_Store(),
        registry=CapabilityRegistry(),
    )
    monkeypatch.setattr(provider_module.shutil, "which", lambda binary: None)
    item = provider.inventory()[0]
    assert item["installed"] is False
    assert item["executable"] is False
    assert item["reason"] == "binary_not_installed"
    assert item["smoke_tested"] is False


def test_catalog_argv_changes_require_new_version_on_restart(tmp_path, monkeypatch):
    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityUnavailable
    from whaxon.core.store import JobStore

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    store = JobStore(tmp_path / "catalog-version.db")
    first = SimpleNamespace(id="nmap", args="-sT {target}", binary="nmap", transport="cli", available=True)
    catalog = _Catalog([first])
    provider = CatalogAdapterProvider(
        catalog=catalog, runner=_Runner(), store=_Store(),
        registry=CapabilityRegistry(store),
    )
    task = WorkflowTask("scan", "tool.nmap", "192.0.2.10", permissions=("network.scan",), impact="moderate")
    original = provider.resolve_task(task).manifest
    catalog.tools["nmap"] = SimpleNamespace(
        id="nmap", args="-sV {target}", binary="nmap", transport="cli", available=True,
    )
    with pytest.raises(CapabilityUnavailable, match="changed"):
        provider.resolve_task(task)
    restored = CapabilityRegistry(store)
    rebound = CatalogAdapterProvider(
        catalog=catalog, runner=_Runner(), store=_Store(), registry=restored,
    )
    current = rebound.resolve_task(task).manifest
    assert current.provider_version != original.provider_version
    assert len(restored.list("tool.nmap")) == 2


def test_direct_provider_dispatch_rejects_missing_permission_and_impact(monkeypatch):
    import asyncio

    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityUnavailable

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    runner = _Runner()
    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=runner, store=_Store(),
        registry=CapabilityRegistry(),
    )
    with pytest.raises(CapabilityUnavailable):
        asyncio.run(provider.dispatch(
            WorkflowTask("scan", "tool.nmap", "192.0.2.10"),
        ))
    assert runner.calls == []


def test_runner_job_id_mismatch_is_not_reported_as_success(monkeypatch):
    import asyncio

    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())

    class OtherRunner(_Runner):
        async def run_tool(self, **kwargs):
            self.calls.append(kwargs)
            return "wrong-job"

    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=OtherRunner(), store=_Store(),
        registry=CapabilityRegistry(),
    )
    task = WorkflowTask("scan", "tool.nmap", "192.0.2.10", permissions=("network.scan",), impact="moderate")
    with pytest.raises(RuntimeError, match="mismatched execution identity"):
        asyncio.run(provider.dispatch(task))


def test_missing_persisted_provider_job_identity_fails_closed(monkeypatch):
    import asyncio

    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())

    class IncompleteStore(_Store):
        def get(self, job_id):
            return {"id": job_id, "status": "finished", "exit_code": 0}

    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=_Runner(), store=IncompleteStore(),
        registry=CapabilityRegistry(),
    )
    task = WorkflowTask("scan", "tool.nmap", "192.0.2.10", permissions=("network.scan",), impact="moderate")
    with pytest.raises(RuntimeError, match="identity"):
        asyncio.run(provider.dispatch(task))


def test_router_dispatches_through_registered_provider_not_scheduler(monkeypatch):
    import asyncio

    import whaxon.adapters
    from whaxon.core.providers import BoundProviderRouter

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    catalog = _Catalog([_tool("nmap")])
    runner = _Runner()
    bound = CatalogAdapterProvider(
        catalog=catalog, runner=runner, store=_Store(), registry=CapabilityRegistry(),
    )
    router = BoundProviderRouter((bound,))
    task = WorkflowTask(
        "scan", "tool.nmap", "192.0.2.10",
        permissions=("network.scan",), impact="moderate",
    )
    assert router.resolve_task(task).manifest.provider_id == "whaxon.adapter.nmap"
    result = asyncio.run(router.dispatch(task))
    assert result["tool_id"] == "nmap"
    assert len(runner.calls) == 1


def test_router_rejects_duplicate_capabilities_and_untrusted_registry_only(monkeypatch):
    import asyncio

    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityUnavailable
    from whaxon.core.providers import BoundProviderRouter

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    registry = CapabilityRegistry()
    first = CatalogAdapterProvider(
        catalog=_Catalog([_tool("nmap")]), runner=_Runner(),
        store=_Store(), registry=registry,
    )
    router = BoundProviderRouter((first,))
    other = CatalogAdapterProvider(
        catalog=_Catalog([_tool("nmap")]), runner=_Runner(),
        store=_Store(), registry=registry,
    )
    with pytest.raises(ValueError, match="ambiguous bound capability"):
        router.register(other)
    with pytest.raises(CapabilityUnavailable, match="trusted execution provider"):
        asyncio.run(router.dispatch(WorkflowTask(
            "scan", "tool.unknown", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        )))


def test_catalog_portfolio_reconciles_unsupported_tools_without_registering(monkeypatch):
    import whaxon.adapters
    from whaxon.core.providers import BoundProviderRouter

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    catalog = _Catalog([
        _tool("nmap"),
        _tool("hydra"),
        SimpleNamespace(id="ssh_cmd", available=True, transport="ssh", binary=""),
    ])
    registry = CapabilityRegistry()
    bridge = CatalogAdapterProvider(
        catalog=catalog, runner=_Runner(), store=_Store(), registry=registry,
    )
    rows = {item["capability_id"]: item for item in BoundProviderRouter((bridge,)).inventory()}
    assert rows["tool.nmap"]["registered"] is True
    assert rows["tool.hydra"]["reason"] == "not_admitted_for_engine_v2"
    assert rows["tool.ssh_cmd"]["reason"] == "unsupported_transport"
    assert rows["tool.hydra"]["executable"] is False
    assert rows["tool.ssh_cmd"]["executable"] is False
    assert [x.capability_id for x in registry.list()] == ["tool.nmap"]


def test_router_refuses_changed_catalog_and_unbound_provider_impostor(monkeypatch):
    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityManifest, CapabilityUnavailable
    from whaxon.core.providers import BoundProviderRouter

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    tool = SimpleNamespace(
        id="nmap", args="-sT {target}", binary="nmap", transport="cli",
        available=True,
    )
    catalog = _Catalog([tool])
    registry = CapabilityRegistry()
    bridge = CatalogAdapterProvider(
        catalog=catalog, runner=_Runner(), store=_Store(), registry=registry,
    )
    router = BoundProviderRouter((bridge,))
    registry.register(CapabilityManifest(
        capability_id="tool.danger",
        provider_id="untrusted.external", provider_version="1",
        transports=("local_process",), permissions=("network.scan",),
        impact="moderate", readiness="end_to_end_verified",
    ))
    with pytest.raises(CapabilityUnavailable):
        router.resolve_task(WorkflowTask(
            "scan", "tool.danger", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        ))
    catalog.tools["nmap"] = SimpleNamespace(
        id="nmap", args="-sT -p- {target}", binary="nmap",
        transport="cli", available=True,
    )
    with pytest.raises(CapabilityUnavailable, match="catalog executable/argv changed"):
        router.resolve_task(WorkflowTask(
            "scan", "tool.nmap", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        ))


def test_router_accepts_catalog_with_no_admitted_execution_providers(monkeypatch):
    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityUnavailable
    from whaxon.core.providers import BoundProviderRouter

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda tool_id: object())
    bridge = CatalogAdapterProvider(
        catalog=_Catalog([_tool("operator_custom")]), runner=_Runner(),
        store=_Store(), registry=CapabilityRegistry(),
    )
    router = BoundProviderRouter((bridge,))
    assert router.inventory()[0]["reason"] == "not_admitted_for_engine_v2"
    with pytest.raises(CapabilityUnavailable):
        router.resolve_task(WorkflowTask(
            "custom", "tool.operator_custom", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        ))


def test_catalog_v2_provider_fences_legacy_before_dispatch(monkeypatch):
    import asyncio

    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, 'get_adapter', lambda _tool: object())
    fenced = []
    runner = _Runner()
    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=runner,
        store=_Store(), registry=CapabilityRegistry(),
        suppress_legacy_followup=lambda job_id: fenced.append(job_id),
    )
    asyncio.run(provider.dispatch(WorkflowTask(
        "scan", "tool.nmap", "192.0.2.10",
        permissions=("network.scan",), impact="moderate",
    )))
    assert len(fenced) == 1
    assert runner.calls[0]['job_id'] == fenced[0]


def test_catalog_v2_provider_fails_closed_if_autochain_fence_fails(monkeypatch):
    import asyncio

    import whaxon.adapters

    monkeypatch.setattr(whaxon.adapters, 'get_adapter', lambda _tool: object())
    runner = _Runner()

    def reject(_job_id):
        raise RuntimeError('fence unavailable')

    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool()]), runner=runner,
        store=_Store(), registry=CapabilityRegistry(),
        suppress_legacy_followup=reject,
    )
    with pytest.raises(RuntimeError, match='fence unavailable'):
        asyncio.run(provider.dispatch(WorkflowTask(
            "scan", "tool.nmap", "192.0.2.10",
            permissions=("network.scan",), impact="moderate",
        )))
    assert runner.calls == []


def test_router_selects_explicit_provider_for_shared_semantic_capability():
    """A new provider is admitted without changing the scheduler contract."""
    import asyncio

    from whaxon.core.capabilities import CapabilityManifest
    from whaxon.core.providers import BoundProviderRouter

    class Trusted:
        def __init__(self, provider_id):
            self.manifest = CapabilityManifest(
                "service.http.enumerate", provider_id, "1", ("local_process",),
                target_types=("hostname",), permissions=("network.scan",),
                impact="moderate",
            )
            self.calls = 0

        def bindings(self):
            return (self.manifest,)

        def resolve_task(self, task, *, require_installed=False):
            assert task.capability_id == self.manifest.capability_id
            assert task.target == "example.test"
            return SimpleNamespace(manifest=self.manifest)

        async def dispatch(self, task):
            self.calls += 1
            return {
                "provider_id": self.manifest.provider_id,
                "provider_version": self.manifest.provider_version,
                "manifest_fingerprint": self.manifest.fingerprint,
                "status": "succeeded",
            }

        def inventory(self):
            return [{"capability_id": self.manifest.capability_id,
                     "provider_id": self.manifest.provider_id}]

    primary = Trusted("trusted.primary")
    alternate = Trusted("trusted.alternate")
    router = BoundProviderRouter(
        (primary, alternate),
        preferred_providers={"service.http.enumerate": "trusted.alternate"},
    )
    task = WorkflowTask(
        "http", "service.http.enumerate", "example.test",
        permissions=("network.scan",), impact="moderate",
    )
    assert router.manifest_for(task.capability_id).provider_id == "trusted.alternate"
    assert asyncio.run(router.dispatch(task))["provider_id"] == "trusted.alternate"
    assert primary.calls == 0
    assert alternate.calls == 1
    assert len(router.inventory()) == 2


def test_router_missing_explicit_provider_fails_closed():
    from whaxon.core.capabilities import CapabilityManifest, CapabilityUnavailable
    from whaxon.core.providers import BoundProviderRouter

    class Provider:
        def bindings(self):
            return (CapabilityManifest(
                "service.http.enumerate", "trusted.only", "1", ("local_process",),
            ),)

        def resolve_task(self, task, *, require_installed=False):
            raise AssertionError("unselected provider must not be called")

        async def dispatch(self, task):
            raise AssertionError("unselected provider must not dispatch")

        def inventory(self):
            return []

    router = BoundProviderRouter(
        (Provider(),),
        preferred_providers={"service.http.enumerate": "trusted.missing"},
    )
    with pytest.raises(CapabilityUnavailable, match="preferred execution provider"):
        router.manifest_for("service.http.enumerate")
    with pytest.raises(CapabilityUnavailable):
        router.resolve_task(WorkflowTask("http", "service.http.enumerate", "example.test"))


def test_multi_provider_execution_requires_approval_bound_manifest(tmp_path):
    """Immutable plan metadata protects approved operations from provider swap."""
    from whaxon.core import Core
    from whaxon.core.capabilities import CapabilityManifest
    from whaxon.core.providers import BoundProviderRouter
    from whaxon.core.store import JobStore
    from whaxon.core.workflow import WorkflowPlan

    class Provider:
        def __init__(self, provider_id):
            self.manifest = CapabilityManifest(
                "service.http.enumerate", provider_id, "1", ("local_process",),
                target_types=("hostname",), impact="low",
            )

        def bindings(self):
            return (self.manifest,)

        def resolve_task(self, task, *, require_installed=False):
            return SimpleNamespace(manifest=self.manifest)

        async def dispatch(self, task):
            raise AssertionError("policy tests must not dispatch")

        def inventory(self):
            return []

    first = Provider("trusted.alpha")
    second = Provider("trusted.beta")
    task = WorkflowTask(
        "http", "service.http.enumerate", "lab.example", impact="low",
    )
    core = Core.__new__(Core)
    core.store = JobStore(tmp_path / "selection.db")
    core.store.create_mission("m", "controlled lab")
    core.providers = BoundProviderRouter(
        (first, second),
        preferred_providers={"service.http.enumerate": "trusted.beta"},
    )
    core.scope = SimpleNamespace(
        check_for_execution=lambda _target: SimpleNamespace(allowed=True),
    )
    core.store.save_workflow_plan("unpinned", WorkflowPlan("m", (task,)))
    assert core.authorize_workflow_task_for_plan("unpinned", task) is False

    pinned = {
        "provider_bindings": {
            "http": {
                "provider_id": second.manifest.provider_id,
                "manifest_fingerprint": second.manifest.fingerprint,
            },
        },
    }
    core.store.save_workflow_plan("pinned", WorkflowPlan("m", (task,), metadata=pinned))
    assert core.authorize_workflow_task_for_plan("pinned", task) is True

    core.providers = BoundProviderRouter(
        (first, second),
        preferred_providers={"service.http.enumerate": "trusted.alpha"},
    )
    assert core.authorize_workflow_task_for_plan("pinned", task) is False


def test_router_refuses_incompatible_semantic_provider_contracts():
    """A shared name alone must never authorize a different operation."""
    from whaxon.core.capabilities import CapabilityManifest
    from whaxon.core.providers import BoundProviderRouter

    class Provider:
        def __init__(self, name, output_schema):
            self.manifest = CapabilityManifest(
                "service.http.enumerate", name, "1", ("local_process",),
                target_types=("hostname",), impact="low",
                output_schema=output_schema,
            )

        def bindings(self):
            return (self.manifest,)

        def resolve_task(self, task, *, require_installed=False):
            return SimpleNamespace(manifest=self.manifest)

        async def dispatch(self, task):
            raise AssertionError("incompatible provider cannot dispatch")

        def inventory(self):
            return []

    trusted = Provider("trusted.alpha", {"type": "object"})
    incompatible = Provider("trusted.beta", {"type": "array"})
    with pytest.raises(ValueError, match="incompatible providers"):
        BoundProviderRouter(
            (trusted, incompatible),
            preferred_providers={"service.http.enumerate": "trusted.beta"},
        )



def test_provider_pin_remains_required_after_alternative_is_removed(monkeypatch):
    """Pinned plans must not silently change identity with one provider left."""
    import whaxon.adapters
    from whaxon.core.providers import BoundProviderRouter

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda _tool: object())
    adapter = CatalogAdapterProvider(
        catalog=_Catalog([_tool("nmap")]), runner=_Runner(),
        store=_Store(), registry=CapabilityRegistry(),
    )
    router = BoundProviderRouter((adapter,))
    task = WorkflowTask(
        "scan", "tool.nmap", "192.0.2.10",
        permissions=("network.scan",), impact="moderate",
    )
    selected = router.manifest_for("tool.nmap")
    assert router.plan_binding_valid(task, {
        "provider_bindings": {
            "scan": {"provider_id": selected.provider_id,
                     "manifest_fingerprint": selected.fingerprint},
        },
    }) is True
    assert router.plan_binding_valid(task, {
        "provider_bindings": {
            "scan": {"provider_id": "replaced.provider",
                     "manifest_fingerprint": selected.fingerprint},
        },
    }) is False
    assert router.plan_binding_valid(task, {
        "provider_bindings": {
            "scan": {"provider_id": selected.provider_id,
                     "manifest_fingerprint": "stale-fingerprint"},
        },
    }) is False
    assert router.plan_binding_valid(task, {
        "provider_bindings": {},
    }) is False
    assert router.plan_binding_valid(task, {
        "provider_bindings": "invalid",
    }) is False
    assert router.plan_binding_valid(task, {
        "provider_bindings": None,
    }) is False
    # Existing, unpinned single-provider plans remain compatible.
    assert router.plan_binding_valid(task, {}) is True



def test_e4_portfolio_audit_reconciles_catalog_and_adapter_only(monkeypatch):
    """An adapter without a catalog entry is visible, not executable."""
    import whaxon.adapters
    from whaxon.core.providers import BoundProviderRouter

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda _id: object())
    monkeypatch.setattr(
        whaxon.adapters, "list_adapters",
        lambda: ["nmap", "adapter_without_catalog", "hydra"],
    )
    catalog = _Catalog([
        _tool("nmap"), _tool("hydra"),
        SimpleNamespace(
            id="msf_session_operation", available=True,
            transport="msf_session", binary="",
        ),
        _tool("no_adapter"),
    ])
    provider = CatalogAdapterProvider(
        catalog=catalog, runner=_Runner(), store=_Store(),
        registry=CapabilityRegistry(),
    )
    router = BoundProviderRouter((provider,))
    before = tuple(manifest.fingerprint for manifest in provider.bindings())
    report = router.portfolio_audit()
    rows = {row["tool_id"]: row for row in report["rows"]}
    assert report["schema_version"] == "whaxon.portfolio-audit.v1"
    assert report["execution_enabled_by_audit"] is False
    assert report["catalog_count"] == 4
    assert report["adapter_count"] == 3
    assert rows["nmap"]["state"] == "bound"
    assert rows["adapter_without_catalog"]["state"] == "adapter_only"
    assert rows["hydra"]["state"] == "not_admitted"
    assert rows["msf_session_operation"]["state"] == "unsupported_transport"
    assert rows["no_adapter"]["state"] == "not_admitted"
    assert not rows["adapter_without_catalog"]["v2_provider_bound"]
    assert not rows["msf_session_operation"]["v2_provider_bound"]
    assert tuple(manifest.fingerprint for manifest in provider.bindings()) == before


def test_e4_portfolio_audit_reports_missing_adapter_without_admission(monkeypatch):
    import whaxon.adapters
    from whaxon.core.providers import BoundProviderRouter

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda _id: None)
    monkeypatch.setattr(whaxon.adapters, "list_adapters", lambda: [])
    bridge = CatalogAdapterProvider(
        catalog=_Catalog([_tool("nmap")]), runner=_Runner(), store=_Store(),
        registry=CapabilityRegistry(),
    )
    report = BoundProviderRouter((bridge,)).portfolio_audit()
    assert report["summary"]["catalog_only"] == 1
    assert report["rows"][0]["state"] == "catalog_only"
    assert report["rows"][0]["v2_provider_bound"] is False


def test_router_unknown_capability_has_no_trusted_provider_error():
    from whaxon.core.capabilities import CapabilityUnavailable
    from whaxon.core.providers import BoundProviderRouter

    router = BoundProviderRouter(())
    with pytest.raises(CapabilityUnavailable, match="no trusted execution provider"):
        router.manifest_for("operation.unknown")



def test_e4_optional_portfolio_audit_preserves_minimal_provider_contract():
    """Previously admitted trusted providers need no new audit method."""
    from whaxon.core.capabilities import CapabilityManifest
    from whaxon.core.providers import BoundProviderRouter

    class MinimalProvider:
        def bindings(self):
            return (
                CapabilityManifest(
                    "operation.example", "trusted.minimal", "1",
                    ("local_process",),
                ),
            )

        def resolve_task(self, task, *, require_installed=False):
            raise AssertionError("inspection must not resolve a task")

        async def dispatch(self, task):
            raise AssertionError("inspection must not dispatch")

        def inventory(self):
            return []

    router = BoundProviderRouter((MinimalProvider(),))
    report = router.portfolio_audit()
    assert report == {
        "schema_version": "whaxon.portfolio-audit.v1",
        "provider_audits": [],
        "execution_enabled_by_audit": False,
    }



def test_semantic_operation_and_legacy_alias_use_same_guarded_runner(monkeypatch):
    """Semantic IDs keep the V2 runner, evidence, version and authorization."""
    import asyncio

    import whaxon.adapters
    from whaxon.core.providers import (
        BoundProviderRouter,
        CatalogAdapterProvider,
        SemanticOperationProvider,
    )

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda _tool: object())
    registry = CapabilityRegistry()
    runner = _Runner()
    bridge = CatalogAdapterProvider(
        catalog=_Catalog([_tool("nmap")]), runner=runner,
        store=_Store(), registry=registry,
    )
    semantic = SemanticOperationProvider(bridge, registry)
    router = BoundProviderRouter((bridge, semantic))
    task = WorkflowTask(
        "scan", "network.services.discover", "192.0.2.10",
        permissions=("network.scan",), impact="moderate",
    )
    selected = router.manifest_for("network.services.discover")
    assert selected.provider_id == router.manifest_for("tool.nmap").provider_id
    assert selected.fingerprint != router.manifest_for("tool.nmap").fingerprint
    assert router.plan_binding_valid(task, {}) is False
    assert router.plan_binding_valid(task, {
        "provider_bindings": {
            "scan": {"provider_id": selected.provider_id,
                     "manifest_fingerprint": selected.fingerprint},
        },
    }) is True
    output = asyncio.run(router.dispatch(task))
    assert output["capability_id"] == "network.services.discover"
    assert output["legacy_capability_id"] == "tool.nmap"
    assert output["tool_id"] == "nmap"
    assert output["manifest_fingerprint"] == selected.fingerprint
    assert len(runner.calls) == 1
    assert runner.calls[0]["tool_id"] == "nmap"
    assert "tool.nmap" in {m.capability_id for m in registry.list()}
    assert "network.services.discover" in {m.capability_id for m in registry.list()}


def test_semantic_operation_rejects_changed_registry_manifest(monkeypatch):
    import whaxon.adapters
    from whaxon.core.capabilities import CapabilityUnavailable
    from whaxon.core.providers import CatalogAdapterProvider, SemanticOperationProvider

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda _tool: object())
    registry = CapabilityRegistry()
    bridge = CatalogAdapterProvider(
        catalog=_Catalog([_tool("nmap")]), runner=_Runner(),
        store=_Store(), registry=registry,
    )
    semantic = SemanticOperationProvider(bridge, registry)
    task = WorkflowTask(
        "scan", "network.services.discover", "192.0.2.10",
        permissions=("network.scan",), impact="moderate",
    )
    assert semantic.resolve_task(task).manifest.capability_id == "network.services.discover"
    registry._manifests.pop((
        "network.services.discover", "whaxon.adapter.nmap",
        semantic.bindings()[0].provider_version,
    ))
    with pytest.raises(CapabilityUnavailable, match="semantic provider manifest changed"):
        semantic.resolve_task(task)


def test_e4_catalog_audit_does_not_claim_bound_after_catalog_drift(monkeypatch):
    """Changed catalog argv cannot be advertised as a bound V2 provider."""
    import whaxon.adapters
    from whaxon.core.providers import BoundProviderRouter

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda _id: object())
    monkeypatch.setattr(whaxon.adapters, "list_adapters", lambda: ["nmap"])
    tool = _tool("nmap")
    catalog = _Catalog([tool])
    registry = CapabilityRegistry()
    provider = CatalogAdapterProvider(
        catalog=catalog, runner=_Runner(), store=_Store(), registry=registry,
    )
    router = BoundProviderRouter((provider,))
    before = router.portfolio_audit()
    assert before["rows"][0]["state"] == "bound"

    # A post-registration catalog modification invalidates the versioned
    # argv contract until a deliberately reviewed provider is reloaded.
    tool.args = ["--new-argv"]
    report = router.portfolio_audit()
    assert report["rows"][0]["state"] == "stale_binding"
    assert report["rows"][0]["v2_provider_bound"] is False
    assert report["rows"][0]["reason"] == "catalog_contract_changed"
    assert report["execution_enabled_by_audit"] is False


def test_e4_catalog_audit_does_not_claim_bound_after_registry_drift(monkeypatch):
    """A missing persisted manifest must not look like an admitted binding."""
    import whaxon.adapters
    from whaxon.core.providers import BoundProviderRouter

    monkeypatch.setattr(whaxon.adapters, "get_adapter", lambda _id: object())
    monkeypatch.setattr(whaxon.adapters, "list_adapters", lambda: ["nmap"])
    registry = CapabilityRegistry()
    provider = CatalogAdapterProvider(
        catalog=_Catalog([_tool("nmap")]),
        runner=_Runner(), store=_Store(), registry=registry,
    )
    router = BoundProviderRouter((provider,))
    assert router.portfolio_audit()["rows"][0]["state"] == "bound"

    monkeypatch.setattr(registry, "list", lambda _capability=None: [])
    report = router.portfolio_audit()
    assert report["rows"][0]["state"] == "stale_binding"
    assert report["rows"][0]["v2_provider_bound"] is False
    assert report["execution_enabled_by_audit"] is False
