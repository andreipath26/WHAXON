from __future__ import annotations

import json
from types import SimpleNamespace

from whaxon.core.redirect_recon_v2 import _MANIFEST, CAPABILITY_ID
from whaxon.interfaces.cli import recon_cmd, workflow_cmd


class _ProposalCore:
    def __init__(self):
        self.saved = None
        self.scope_checks = []
        self.store = SimpleNamespace(
            get_mission=lambda mission_id: {"id": mission_id} if mission_id == "mission" else None,
        )
        self.scope = SimpleNamespace(load=lambda: None, check_for_pinned_execution=self._scope)
        self.providers = SimpleNamespace(
            manifest_for=lambda _capability: _MANIFEST,
            resolve_task=self._resolve,
        )

    def _scope(self, target):
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
        self.saved = plan_id, plan
        return True


def test_workflow_cli_proposes_one_unapproved_redirect_observation(
    monkeypatch, capsys, tmp_path,
):
    core = _ProposalCore()
    monkeypatch.setattr(workflow_cmd, "Core", lambda *, data_dir: core)
    status = workflow_cmd.main([
        "--data-dir", str(tmp_path), "plan", "propose-redirect-recon",
        "--mission-id", "mission", "--id", "redirect-plan",
        "--target", "api.example.test", "--save",
    ])
    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["status"] == "proposed" and output["created"] is True
    assert output["approval_granted"] is False and output["execution_submitted"] is False
    assert core.scope_checks == ["api.example.test"]
    plan_id, plan = core.saved
    assert plan_id == "redirect-plan" and len(plan.tasks) == 1
    task = plan.tasks[0]
    assert task.id == "redirect-1" and task.capability_id == CAPABILITY_ID
    assert task.inputs == {} and task.target == "api.example.test"
    assert plan.metadata["provider_bindings"]["redirect-1"] == {
        "provider_id": _MANIFEST.provider_id,
        "manifest_fingerprint": _MANIFEST.fingerprint,
    }


def test_v2_recon_cli_accepts_only_matching_single_redirect_task(monkeypatch, capsys):
    task = {
        "id": "redirect-1", "capability_id": CAPABILITY_ID,
        "target": "api.example.test", "inputs": {}, "depends_on": [],
    }

    class _ExecutionCore:
        def __init__(self):
            self.run_calls = []
            self.direct_calls = []

        def workflow_plan_details(self, plan_id):
            assert plan_id == "redirect-plan"
            return {"plan": {"tasks": [task]}}

        async def initialize(self, *, drain=False):
            assert drain is False

        async def run_workflow_plan(self, plan_id):
            self.direct_calls.append(plan_id)
            return {"complete": True, "tasks": [{"id": "redirect-1", "status": "succeeded"}]}

        def enqueue_workflow_run(self, plan_id):
            self.run_calls.append(plan_id)
            return {"id": "request-1", "status": "queued"}

        def workflow_report(self, plan_id):
            assert plan_id == "redirect-plan"
            return {"status": "complete", "findings": [{
                "severity": "info", "kind": "redirect_observation",
                "raw_line": "https://api.example.test/: HTTP 302; Location: https://login.example.test/",
            }]}

    core = _ExecutionCore()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)
    status = recon_cmd.main([
        "api.example.test", "--engine", "v2", "--plan-id", "redirect-plan",
    ])
    assert status == recon_cmd.EXIT_OK
    assert core.run_calls == ["redirect-plan"]
    assert core.direct_calls == []
    assert "request request-1, queued" in capsys.readouterr().out


def test_v2_recon_cli_rejects_dynamic_redirect_inputs_before_dispatch(monkeypatch, capsys):
    task = {
        "id": "redirect-1", "capability_id": CAPABILITY_ID,
        "target": "api.example.test", "inputs": {"follow": True}, "depends_on": [],
    }

    class _ExecutionCore:
        def __init__(self):
            self.run_calls = []

        def workflow_plan_details(self, _plan_id):
            return {"plan": {"tasks": [task]}}

        async def initialize(self, *, drain=False):
            raise AssertionError("rejected plan must not initialize or dispatch")

    core = _ExecutionCore()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)
    status = recon_cmd.main([
        "api.example.test", "--engine", "v2", "--plan-id", "redirect-plan",
    ])
    assert status == recon_cmd.EXIT_USAGE
    assert core.run_calls == []
    assert "must contain only fixed" in capsys.readouterr().err
