"""E4 proof: provider substitutions use the same persisted scheduler and policy.

These tests execute in-process fake providers only; they do not establish
external scanner equivalence or authorize a real network assessment.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from whaxon.core import Core
from whaxon.core.capabilities import CapabilityManifest
from whaxon.core.providers import BoundProviderRouter
from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowPlan, WorkflowTask

_CAPABILITY = "service.http.enumerate"


class _LocalProvider:
    def __init__(self, identity: str):
        self.manifest = CapabilityManifest(
            _CAPABILITY, identity, "1", ("local_process",),
            target_types=("ip",), impact="low",
            permissions=(), side_effects=(),
        )
        self.calls: list[str] = []

    def bindings(self):
        return (self.manifest,)

    def resolve_task(self, task, *, require_installed=False):
        assert require_installed is True
        assert task.capability_id == _CAPABILITY
        return SimpleNamespace(manifest=self.manifest)

    async def dispatch(self, task):
        self.calls.append(task.id)
        return {
            "provider_id": self.manifest.provider_id,
            "provider_version": self.manifest.provider_version,
            "manifest_fingerprint": self.manifest.fingerprint,
            "evidence_kind": "synthetic-provider-contract-test",
        }

    def inventory(self):
        return []


def _setup(tmp_path, *, selected: str):
    first = _LocalProvider("trusted.alpha")
    second = _LocalProvider("trusted.beta")
    core = Core.__new__(Core)
    core.store = JobStore(tmp_path / "e4-provider-substitution.db")
    core.store.create_mission("mission", "synthetic provider-substitution lab")
    core.scope = SimpleNamespace(
        check_for_execution=lambda _target: SimpleNamespace(allowed=True),
    )
    core.providers = BoundProviderRouter(
        (first, second), preferred_providers={_CAPABILITY: selected},
    )
    task = WorkflowTask(
        "operation", _CAPABILITY, "192.0.2.10",
        impact="low", permissions=(),
    )
    chosen = core.providers.manifest_for(_CAPABILITY)
    metadata = {"provider_bindings": {
        task.id: {
            "provider_id": chosen.provider_id,
            "manifest_fingerprint": chosen.fingerprint,
        },
    }}
    core.store.save_workflow_plan(
        "plan", WorkflowPlan("mission", (task,), metadata=metadata),
    )
    return core, first, second, task


def _run(core):
    async def execute():
        scheduler = core.workflow_scheduler(plan_id="plan")
        return await scheduler.run(
            "plan", max_tasks=1, max_attempts=1, max_concurrency=1,
        )

    # Own the asyncio loop in a thread, independently of pytest plugins.
    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(lambda: asyncio.run(execute())).result(timeout=15)


def test_e4_alternate_trusted_provider_executes_with_unchanged_scheduler(tmp_path):
    core, first, second, task = _setup(tmp_path, selected="trusted.beta")
    assert core.authorize_workflow_task_for_plan("plan", task) is True
    result = _run(core)
    assert result["complete"] is True
    assert first.calls == []
    assert second.calls == ["operation"]
    assert core.store.get_workflow_progress("plan")["counts"]["succeeded"] == 1


def test_e4_primary_provider_executes_with_the_same_scheduler(tmp_path):
    core, first, second, task = _setup(tmp_path, selected="trusted.alpha")
    assert core.authorize_workflow_task_for_plan("plan", task) is True
    result = _run(core)
    assert result["complete"] is True
    assert first.calls == ["operation"]
    assert second.calls == []
    assert core.store.get_workflow_progress("plan")["counts"]["succeeded"] == 1


def test_e4_provider_preference_change_cannot_reuse_persisted_plan(tmp_path):
    core, first, second, task = _setup(tmp_path, selected="trusted.alpha")
    assert core.authorize_workflow_task_for_plan("plan", task) is True
    core.providers = BoundProviderRouter(
        (first, second),
        preferred_providers={_CAPABILITY: "trusted.beta"},
    )
    assert core.authorize_workflow_task_for_plan("plan", task) is False
    _run(core)
    assert first.calls == []
    assert second.calls == []
    assert core.store.get_workflow_progress("plan")["counts"]["blocked"] == 1


def test_e4_missing_preferred_provider_cannot_fallback_during_scheduler_run(tmp_path):
    core, first, second, task = _setup(tmp_path, selected="trusted.alpha")
    core.providers = BoundProviderRouter(
        (first, second),
        preferred_providers={_CAPABILITY: "trusted.not-installed"},
    )
    assert core.authorize_workflow_task_for_plan("plan", task) is False
    _run(core)
    assert first.calls == []
    assert second.calls == []
    assert core.store.get_workflow_progress("plan")["counts"]["blocked"] == 1
