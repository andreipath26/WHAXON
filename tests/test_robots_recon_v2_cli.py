from __future__ import annotations

import json
from types import SimpleNamespace

from whaxon.core.robots_recon_v2 import _MANIFEST, CAPABILITY_ID
from whaxon.interfaces.cli import recon_cmd, workflow_cmd


class _ProposalCore:
    def __init__(self):
        self.saved = None
        self.scope_checks = []
        self.store = SimpleNamespace(
            get_mission=lambda mission_id: {"id": mission_id} if mission_id == "mission" else None,
        )
        self.scope = SimpleNamespace(
            load=lambda: None,
            check_for_pinned_execution=self._check_scope,
        )
        self.providers = SimpleNamespace(
            manifest_for=lambda capability_id: _MANIFEST,
            resolve_task=self._resolve,
        )

    def _check_scope(self, target):
        self.scope_checks.append(target)
        return SimpleNamespace(allowed=True, reason="in scope")

    def _resolve(self, task, *, require_installed):
        assert task.capability_id == CAPABILITY_ID
        assert task.inputs == {}
        assert require_installed is True
        return SimpleNamespace(manifest=_MANIFEST)

    def capability_inventory(self):
        return [{
            "capability_id": CAPABILITY_ID,
            "provider_id": _MANIFEST.provider_id,
            "selected_for_execution": True,
            "installed": True,
            "executable": True,
        }]

    def save_workflow_plan(self, plan_id, plan):
        self.saved = (plan_id, plan)
        return True


def test_workflow_cli_proposes_and_saves_fixed_robots_plan(
    monkeypatch, capsys, tmp_path,
):
    core = _ProposalCore()
    monkeypatch.setattr(workflow_cmd, "Core", lambda *, data_dir: core)

    status = workflow_cmd.main([
        "--data-dir", str(tmp_path),
        "plan", "propose-robots-recon",
        "--mission-id", "mission",
        "--id", "robots-plan",
        "--target", "api.example.test",
        "--save",
    ])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert core.scope_checks == ["api.example.test"]
    assert output["status"] == "proposed"
    assert output["created"] is True
    assert output["approval_granted"] is False
    assert output["execution_submitted"] is False
    plan_id, plan = core.saved
    assert plan_id == "robots-plan"
    assert len(plan.tasks) == 1
    task = plan.tasks[0]
    assert task.capability_id == CAPABILITY_ID
    assert task.target == "api.example.test"
    assert task.inputs == {}
    assert plan.metadata["provider_bindings"]["robots-1"] == {
        "provider_id": _MANIFEST.provider_id,
        "manifest_fingerprint": _MANIFEST.fingerprint,
    }


def test_v2_recon_cli_executes_matching_robots_plan_and_renders_evidence(
    monkeypatch, capsys,
):
    task = {
        "id": "robots-1",
        "capability_id": CAPABILITY_ID,
        "target": "api.example.test",
        "inputs": {},
        "depends_on": [],
    }

    class _ExecutionCore:
        def __init__(self):
            self.run_calls = []
            self.direct_calls = []

        def workflow_plan_details(self, plan_id):
            assert plan_id == "robots-plan"
            return {"plan": {"tasks": [task]}}

        async def initialize(self, *, drain=False):
            assert drain is False

        async def run_workflow_plan(self, plan_id):
            self.direct_calls.append(plan_id)
            return {
                "complete": True,
                "tasks": [{"id": "robots-1", "status": "succeeded"}],
            }

        def workflow_report(self, plan_id):
            assert plan_id == "robots-plan"
            return {
                "status": "complete",
                "findings": [{
                    "severity": "info",
                    "kind": "robots_disallow",
                    "raw_line": "https://api.example.test/robots.txt: Disallow /admin",
                }],
            }

        def enqueue_workflow_run(self, plan_id):
            self.run_calls.append(plan_id)
            return {"id": "request-1", "status": "queued"}

    core = _ExecutionCore()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)

    status = recon_cmd.main([
        "api.example.test", "--engine", "v2", "--plan-id", "robots-plan",
    ])

    assert status == recon_cmd.EXIT_OK
    assert core.run_calls == ["robots-plan"]
    assert core.direct_calls == []
    output = capsys.readouterr().out
    assert "request request-1, queued" in output


def test_v2_recon_cli_rejects_robots_plan_with_dynamic_inputs_before_dispatch(
    monkeypatch, capsys,
):
    task = {
        "id": "robots-1",
        "capability_id": CAPABILITY_ID,
        "target": "api.example.test",
        "inputs": {"path": "/private"},
        "depends_on": [],
    }

    class _ExecutionCore:
        def __init__(self, _data_dir=None):
            self.run_calls = []

        def workflow_plan_details(self, _plan_id):
            return {"plan": {"tasks": [task]}}

        async def initialize(self, *, drain=False):
            pass

        async def run_workflow_plan(self, plan_id):
            self.run_calls.append(plan_id)
            return {"complete": True, "tasks": [{"status": "succeeded"}]}

        def workflow_report(self, _plan_id):
            return {"status": "complete", "findings": []}

    core = _ExecutionCore()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)

    status = recon_cmd.main([
        "api.example.test", "--engine", "v2", "--plan-id", "robots-plan",
    ])

    assert status == recon_cmd.EXIT_USAGE
    assert core.run_calls == []
    assert "must contain only fixed DNS, TLS, HTTPS, headers, redirects, robots, or security.txt tasks" in capsys.readouterr().err
