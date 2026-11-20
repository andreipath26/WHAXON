"""Authorization regression coverage for low-impact network effects."""
from __future__ import annotations

import time

import pytest

import whaxon.core.store as store_module
from whaxon.core import Core
from whaxon.core.capabilities import CapabilityManifest
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


class _ProviderBindings:
    def __init__(self, manifest: CapabilityManifest) -> None:
        self.manifest = manifest

    def manifest_for(self, capability_id: str) -> CapabilityManifest:
        assert capability_id == self.manifest.capability_id
        return self.manifest

    def plan_binding_valid(self, _task: WorkflowTask, _metadata: dict) -> bool:
        return True


def _authorize_test_plan(
    tmp_path,
    monkeypatch,
    *,
    impact: str,
    permissions: tuple[str, ...],
    side_effects: tuple[str, ...],
) -> tuple[Core, WorkflowTask]:
    core = Core(tmp_path)
    core.create_mission("approval-mission", "Exercise exact V2 plan authorization")
    manifest = CapabilityManifest(
        capability_id="fixture.network_effect",
        provider_id="fixture.authorization",
        provider_version="1.0.0",
        transports=("local_process",),
        target_types=("hostname",),
        permissions=permissions,
        side_effects=side_effects,
        impact=impact,
    )
    task = WorkflowTask(
        id="task-1",
        capability_id=manifest.capability_id,
        target="example.test",
        permissions=permissions,
        impact=impact,
    )
    core.save_workflow_plan("approval-plan", WorkflowPlan("approval-mission", (task,)))
    core.providers = _ProviderBindings(manifest)
    monkeypatch.setattr(core, "authorize_workflow_task", lambda _task: True)
    return core, task


@pytest.mark.parametrize(
    ("permissions", "side_effects"),
    [
        (("network.scan",), ()),
        ((), ("network_traffic",)),
    ],
)
def test_low_impact_network_effect_requires_exact_plan_approval(
    tmp_path, monkeypatch, permissions, side_effects,
):
    core, task = _authorize_test_plan(
        tmp_path,
        monkeypatch,
        impact="low",
        permissions=permissions,
        side_effects=side_effects,
    )

    assert core.authorize_workflow_task_for_plan("approval-plan", task) is False
    assert core.grant_workflow_approval(
        "approval-plan", task.id, "approval-exact", "operator",
        expires_at=time.time() + 3600,
    )
    assert core.authorize_workflow_task_for_plan("approval-plan", task) is True


def test_non_network_read_only_plan_remains_auto_authorized(tmp_path, monkeypatch):
    core, task = _authorize_test_plan(
        tmp_path,
        monkeypatch,
        impact="read_only",
        permissions=(),
        side_effects=(),
    )

    assert core.authorize_workflow_task_for_plan("approval-plan", task) is True


def test_approval_queue_includes_low_impact_network_candidates_only(tmp_path):
    core = Core(tmp_path)
    core.create_mission("queue-mission", "Exercise the backend approval candidate service")

    cases = (
        ("permission-task", "fixture.network_permission", ("network.scan",), (), "low"),
        ("effect-task", "fixture.network_effect", (), ("network_traffic",), "low"),
        ("read-only-task", "fixture.read_only", (), (), "read_only"),
    )
    for task_id, capability_id, permissions, side_effects, impact in cases:
        manifest = CapabilityManifest(
            capability_id=capability_id,
            provider_id="fixture.approval-queue",
            provider_version="1.0.0",
            transports=("local_process",),
            target_types=("hostname",),
            permissions=permissions,
            side_effects=side_effects,
            impact=impact,
        )
        core.capabilities.register(manifest)
        task = WorkflowTask(
            id=task_id,
            capability_id=capability_id,
            target="example.test",
            permissions=permissions,
            impact=impact,
        )
        plan = WorkflowPlan(
            "queue-mission",
            (task,),
            metadata={
                "provider_bindings": {
                    task_id: {
                        "provider_id": manifest.provider_id,
                        "manifest_fingerprint": manifest.fingerprint,
                    },
                },
            },
        )
        core.save_workflow_plan(f"plan-{task_id}", plan)

    candidates = core.workflow_approval_queue(limit=2)
    candidate_ids = {item["task_key"] for item in candidates}

    assert candidate_ids == {"permission-task", "effect-task"}
    assert len(core.workflow_approval_queue(limit=1)) == 1
    assert all("permissions_json" not in item and "plan_json" not in item for item in candidates)



@pytest.mark.parametrize(
    ("scope_mode", "expected_method"),
    [
        ("network", "check_for_execution"),
        ("dns_query", "check_for_dns_query"),
        ("pinned_network", "check_for_pinned_execution"),
        ("unknown", None),
    ],
)
def test_core_scope_preflight_uses_manifest_scope_mode(
    tmp_path, scope_mode, expected_method,
):
    from types import SimpleNamespace

    core = Core(tmp_path)
    calls = []

    class _Scope:
        def load(self):
            return None

        def check_for_execution(self, target):
            calls.append(("check_for_execution", target))
            return SimpleNamespace(allowed=True)

        def check_for_dns_query(self, target):
            calls.append(("check_for_dns_query", target))
            return SimpleNamespace(allowed=True)

        def check_for_pinned_execution(self, target):
            calls.append(("check_for_pinned_execution", target))
            return SimpleNamespace(allowed=True)

    core.scope = _Scope()
    manifest = CapabilityManifest(
        capability_id="fixture.scope_mode",
        provider_id="fixture.scope_mode",
        provider_version="1.0.0",
        transports=("local_process",),
        target_types=("hostname",),
        permissions=("network.scan",),
        impact="moderate",
        scope_mode=scope_mode if scope_mode != "unknown" else "network",
    )
    if scope_mode == "unknown":
        # Simulate malformed persisted/provider metadata reaching the policy
        # boundary; normal manifest construction rejects this mode earlier.
        manifest = SimpleNamespace(
            capability_id=manifest.capability_id,
            impact=manifest.impact,
            permissions=manifest.permissions,
            scope_mode="unknown",
        )

    class _Bindings:
        def resolve_task(self, _task, *, require_installed):
            assert require_installed is True
            return SimpleNamespace(manifest=manifest)

    core.providers = _Bindings()
    task = WorkflowTask(
        id="scope-mode-task",
        capability_id="fixture.scope_mode",
        target="example.test",
        permissions=("network.scan",),
        impact="moderate",
    )

    assert core.authorize_workflow_task(task) is (expected_method is not None)
    if expected_method is None:
        assert calls == []
    else:
        assert calls == [(expected_method, "example.test")]


@pytest.mark.parametrize("scope_mode", ["dns_query", "pinned_network"])
def test_core_dns_and_pinned_preflights_do_not_resolve_hostname(
    tmp_path, monkeypatch, scope_mode,
):
    import json
    import socket

    from whaxon.core.scope import ScopeManager

    data_dir = tmp_path / "core-data"
    data_dir.mkdir()
    core = Core(data_dir)
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "engagement": "scope-mode-test",
        "enabled": True,
        "in_scope": ["*.acme.test", "10.0.0.0/8"],
        "out_of_scope": [],
    }))
    core.scope = ScopeManager(scope_path)

    def unexpected_resolution(*_args, **_kwargs):
        pytest.fail("Core preflight must not resolve the target hostname")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_resolution)

    manifest = CapabilityManifest(
        capability_id="fixture.scope_mode",
        provider_id="fixture.scope_mode",
        provider_version="1.0.0",
        transports=("local_process",),
        target_types=("hostname",),
        permissions=("network.scan",),
        impact="moderate",
        scope_mode=scope_mode,
    )

    from types import SimpleNamespace

    class _Bindings:
        def resolve_task(self, _task, *, require_installed):
            assert require_installed is True
            return SimpleNamespace(manifest=manifest)

    core.providers = _Bindings()
    task = WorkflowTask(
        id="scope-mode-no-dns",
        capability_id="fixture.scope_mode",
        target="service.acme.test",
        permissions=("network.scan",),
        impact="moderate",
    )

    assert core.authorize_workflow_task(task) is True


def _queue_manifest(capability_id, provider_id, side_effects):
    return CapabilityManifest(
        capability_id=capability_id,
        provider_id=provider_id,
        provider_version="1.0.0",
        transports=("local_process",),
        target_types=("hostname",),
        permissions=(),
        side_effects=side_effects,
        impact="low",
    )


def _queue_task(task_id, capability_id, *, metadata=None):
    task = WorkflowTask(
        id=task_id,
        capability_id=capability_id,
        target="example.test",
        permissions=(),
        impact="low",
    )
    plan = WorkflowPlan("queue-mission", (task,), metadata=metadata or {})
    return task, plan


def test_approval_queue_surfaces_unpinned_and_malformed_network_tasks(tmp_path):
    core = Core(tmp_path)
    core.create_mission("queue-mission", "Exercise malformed approval metadata")
    manifest = _queue_manifest(
        "fixture.queue_network", "fixture.queue_network_provider", ("network_traffic",),
    )
    core.capabilities.register(manifest)

    _, unpinned_plan = _queue_task("unpinned-task", manifest.capability_id)
    core.save_workflow_plan("plan-unpinned", unpinned_plan)
    _, malformed_shape_plan = _queue_task(
        "malformed-shape-task",
        manifest.capability_id,
        metadata={"provider_bindings": ["not", "a", "mapping"]},
    )
    core.save_workflow_plan("plan-malformed-shape", malformed_shape_plan)
    _, malformed_null_plan = _queue_task(
        "malformed-null-task",
        manifest.capability_id,
        metadata={"provider_bindings": {"malformed-null-task": None}},
    )
    core.save_workflow_plan("plan-malformed-null", malformed_null_plan)
    _, malformed_json_plan = _queue_task("malformed-json-task", manifest.capability_id)
    core.save_workflow_plan("plan-malformed-json", malformed_json_plan)

    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_plans SET plan_json=? WHERE id=?",
            ("{", "plan-malformed-json"),
        )
        conn.commit()
    finally:
        conn.close()

    candidates = core.workflow_approval_queue(limit=10)
    candidate_ids = {item["task_key"] for item in candidates}

    assert candidate_ids == {
        "unpinned-task", "malformed-shape-task", "malformed-null-task",
        "malformed-json-task",
    }
    malformed_json = next(
        item for item in candidates if item["task_key"] == "malformed-json-task"
    )
    assert malformed_json["approval_valid"] is False


def test_approval_queue_uses_exact_provider_binding_and_fallback_for_unpinned(
    tmp_path,
):
    core = Core(tmp_path)
    core.create_mission("queue-mission", "Exercise exact provider bindings")
    capability_id = "fixture.multi_provider"
    network_manifest = _queue_manifest(
        capability_id, "fixture.network_provider", ("network_traffic",),
    )
    safe_manifest = _queue_manifest(
        capability_id, "fixture.safe_provider", (),
    )
    core.capabilities.register(network_manifest)
    core.capabilities.register(safe_manifest)

    _, pinned_safe_plan = _queue_task(
        "pinned-safe-task",
        capability_id,
        metadata={"provider_bindings": {"pinned-safe-task": {
            "provider_id": safe_manifest.provider_id,
            "manifest_fingerprint": safe_manifest.fingerprint,
        }}},
    )
    core.save_workflow_plan("plan-pinned-safe", pinned_safe_plan)
    _, unpinned_plan = _queue_task("unpinned-network-task", capability_id)
    core.save_workflow_plan("plan-unpinned-network", unpinned_plan)

    candidates = core.store.list_workflow_approval_candidates(limit=10)

    assert [item["task_key"] for item in candidates] == ["unpinned-network-task"]


def test_approval_queue_paginates_past_irrelevant_pending_tasks(tmp_path, monkeypatch):
    core = Core(tmp_path)
    core.create_mission("queue-mission", "Exercise approval candidate pagination")
    monkeypatch.setattr(store_module, "_APPROVAL_CANDIDATE_PAGE_SIZE", 2)
    network_manifest = _queue_manifest(
        "fixture.old_network", "fixture.old_network_provider", ("network_traffic",),
    )
    safe_manifest = _queue_manifest(
        "fixture.recent_safe", "fixture.recent_safe_provider", (),
    )
    core.capabilities.register(network_manifest)
    core.capabilities.register(safe_manifest)

    _, network_plan = _queue_task("older-network-task", network_manifest.capability_id)
    core.save_workflow_plan("plan-older-network", network_plan)
    for task_id, plan_id in (
        ("newer-safe-task-1", "plan-newer-safe-1"),
        ("newer-safe-task-2", "plan-newer-safe-2"),
    ):
        _, safe_plan = _queue_task(
            task_id,
            safe_manifest.capability_id,
            metadata={"provider_bindings": {task_id: {
                "provider_id": safe_manifest.provider_id,
                "manifest_fingerprint": safe_manifest.fingerprint,
            }}},
        )
        core.save_workflow_plan(plan_id, safe_plan)

    conn = core.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_tasks SET created_at=? WHERE plan_id=?",
            (1.0, "plan-older-network"),
        )
        conn.execute(
            "UPDATE workflow_tasks SET created_at=? WHERE plan_id=?",
            (2.0, "plan-newer-safe-1"),
        )
        conn.execute(
            "UPDATE workflow_tasks SET created_at=? WHERE plan_id=?",
            (3.0, "plan-newer-safe-2"),
        )
        conn.commit()
    finally:
        conn.close()

    candidates = core.store.list_workflow_approval_candidates(limit=1)

    assert [item["task_key"] for item in candidates] == ["older-network-task"]



def test_approval_queue_stops_at_total_scan_budget(tmp_path, monkeypatch):
    core = Core(tmp_path)
    core.create_mission("queue-mission", "Exercise approval scan budget")
    monkeypatch.setattr(store_module, "_APPROVAL_CANDIDATE_PAGE_SIZE", 2)
    monkeypatch.setattr(store_module, "_APPROVAL_CANDIDATE_SCAN_BUDGET", 3)
    safe_manifest = _queue_manifest(
        "fixture.budget_safe", "fixture.budget_safe_provider", (),
    )
    network_manifest = _queue_manifest(
        "fixture.budget_network", "fixture.budget_network_provider",
        ("network_traffic",),
    )
    core.capabilities.register(safe_manifest)
    core.capabilities.register(network_manifest)

    for index in range(3):
        task_id = f"safe-task-{index}"
        _, plan = _queue_task(
            task_id,
            safe_manifest.capability_id,
            metadata={"provider_bindings": {task_id: {
                "provider_id": safe_manifest.provider_id,
                "manifest_fingerprint": safe_manifest.fingerprint,
            }}},
        )
        plan_id = f"plan-safe-{index}"
        core.save_workflow_plan(plan_id, plan)
    _, network_plan = _queue_task("budget-network-task", network_manifest.capability_id)
    core.save_workflow_plan("plan-budget-network", network_plan)

    conn = core.store._conn()
    try:
        for index in range(3):
            conn.execute(
                "UPDATE workflow_tasks SET created_at=? WHERE plan_id=?",
                (float(4 - index), f"plan-safe-{index}"),
            )
        conn.execute(
            "UPDATE workflow_tasks SET created_at=? WHERE plan_id=?",
            (1.0, "plan-budget-network"),
        )
        conn.commit()
    finally:
        conn.close()

    statements = []
    original_conn = core.store._conn

    def traced_conn():
        connection = original_conn()
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(core.store, "_conn", traced_conn)
    candidates = core.store.list_workflow_approval_candidates(limit=1)

    task_page_queries = [
        statement for statement in statements
        if "FROM workflow_tasks t" in statement
    ]
    assert candidates == []
    assert len(task_page_queries) == 2
