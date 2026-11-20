from __future__ import annotations

import json
from types import SimpleNamespace

from whaxon.core.security_txt_v2 import _MANIFEST, CAPABILITY_ID
from whaxon.interfaces.cli import recon_cmd, workflow_cmd


class _ProposalCore:
    def __init__(self):
        self.saved = None
        self.scope_checks = []
        self.store = SimpleNamespace(get_mission=lambda mid: {"id": mid} if mid == "mission" else None)
        self.scope = SimpleNamespace(load=lambda: None, check_for_pinned_execution=self._scope)
        self.providers = SimpleNamespace(manifest_for=lambda _cap: _MANIFEST, resolve_task=self._resolve)

    def _scope(self, target):
        self.scope_checks.append(target)
        return SimpleNamespace(allowed=True, reason="in scope")

    def _resolve(self, task, *, require_installed):
        assert task.capability_id == CAPABILITY_ID and task.inputs == {}
        assert require_installed is True
        return SimpleNamespace(manifest=_MANIFEST)

    def capability_inventory(self):
        return [{"capability_id": CAPABILITY_ID, "provider_id": _MANIFEST.provider_id,
                 "selected_for_execution": True, "installed": True, "executable": True}]

    def save_workflow_plan(self, plan_id, plan):
        self.saved = (plan_id, plan)
        return True


def test_workflow_cli_proposes_and_saves_fixed_security_txt_plan(monkeypatch, capsys, tmp_path):
    core = _ProposalCore()
    monkeypatch.setattr(workflow_cmd, "Core", lambda *, data_dir: core)
    status = workflow_cmd.main([
        "--data-dir", str(tmp_path), "plan", "propose-security-txt-recon",
        "--mission-id", "mission", "--id", "security-plan",
        "--target", "api.example.test", "--save",
    ])
    output = json.loads(capsys.readouterr().out)
    assert status == 0 and output["status"] == "proposed" and output["created"] is True
    assert output["approval_granted"] is False and output["execution_submitted"] is False
    assert core.scope_checks == ["api.example.test"]
    plan_id, plan = core.saved
    assert plan_id == "security-plan" and len(plan.tasks) == 1
    assert plan.tasks[0].capability_id == CAPABILITY_ID and plan.tasks[0].inputs == {}
    assert plan.metadata["provider_bindings"]["security-txt-1"] == {
        "provider_id": _MANIFEST.provider_id,
        "manifest_fingerprint": _MANIFEST.fingerprint,
    }


def test_v2_recon_cli_dispatches_matching_security_txt_plan(monkeypatch, capsys):
    task = {"id": "security-txt-1", "capability_id": CAPABILITY_ID,
            "target": "api.example.test", "inputs": {}, "depends_on": []}

    class _Core:
        def __init__(self): self.run_calls = []; self.direct_calls = []
        def workflow_plan_details(self, _plan_id): return {"plan": {"tasks": [task]}}
        async def initialize(self, *, drain=False): assert drain is False
        async def run_workflow_plan(self, plan_id):
            self.direct_calls.append(plan_id)
            return {"complete": True, "tasks": [{"status": "succeeded"}]}
        def enqueue_workflow_run(self, plan_id):
            self.run_calls.append(plan_id)
            return {"id": "request-1", "status": "queued"}
        def workflow_report(self, _plan_id):
            return {"status": "complete", "findings": [{"severity": "info",
                "kind": "security_txt", "raw_line": "Contact: mailto:security@example.test"}]}

    core = _Core()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)
    status = recon_cmd.main(["api.example.test", "--engine", "v2", "--plan-id", "security-plan"])
    assert status == recon_cmd.EXIT_OK and core.run_calls == ["security-plan"]
    assert core.direct_calls == []
    assert "request request-1, queued" in capsys.readouterr().out


def test_v2_recon_cli_rejects_security_txt_dynamic_inputs_before_dispatch(monkeypatch, capsys):
    task = {"id": "security-txt-1", "capability_id": CAPABILITY_ID,
            "target": "api.example.test", "inputs": {"path": "/elsewhere"}, "depends_on": []}

    class _Core:
        def __init__(self): self.run_calls = []
        def workflow_plan_details(self, _plan_id): return {"plan": {"tasks": [task]}}
        async def initialize(self, *, drain=False): pass
        async def run_workflow_plan(self, plan_id): self.run_calls.append(plan_id)
        def workflow_report(self, _plan_id): return {"status": "complete", "findings": []}

    core = _Core()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)
    status = recon_cmd.main(["api.example.test", "--engine", "v2", "--plan-id", "security-plan"])
    assert status == recon_cmd.EXIT_USAGE and core.run_calls == []
    assert "fixed DNS" in capsys.readouterr().err
