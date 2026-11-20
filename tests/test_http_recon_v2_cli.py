from __future__ import annotations

import json
from types import SimpleNamespace

from whaxon.core.http_recon_v2 import _MANIFEST, CAPABILITY_ID, _collect_findings
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


def test_workflow_cli_proposes_and_saves_fixed_https_recon_plan(
    monkeypatch, capsys, tmp_path,
):
    core = _ProposalCore()
    monkeypatch.setattr(workflow_cmd, "Core", lambda *, data_dir: core)

    status = workflow_cmd.main([
        "--data-dir", str(tmp_path),
        "plan", "propose-https-recon",
        "--mission-id", "mission",
        "--id", "https-plan",
        "--target", "api.acme.test",
        "--save",
    ])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert core.scope_checks == ["api.acme.test"]
    assert output["status"] == "proposed"
    assert output["created"] is True
    assert output["approval_granted"] is False
    assert output["execution_submitted"] is False
    plan_id, plan = core.saved
    assert plan_id == "https-plan"
    assert plan.tasks[0].capability_id == CAPABILITY_ID
    assert plan.tasks[0].target == "api.acme.test"
    assert plan.tasks[0].inputs == {}
    assert plan.metadata["provider_bindings"]["task-1"] == {
        "provider_id": _MANIFEST.provider_id,
        "manifest_fingerprint": _MANIFEST.fingerprint,
    }


def test_v2_recon_cli_executes_only_matching_fixed_https_plan(monkeypatch, capsys):
    task = {
        "id": "task-1",
        "capability_id": CAPABILITY_ID,
        "target": "api.acme.test",
        "inputs": {},
        "depends_on": [],
    }

    class _ExecutionCore:
        def __init__(self):
            self.run_calls = []
            self.direct_calls = []

        def workflow_plan_details(self, plan_id):
            assert plan_id == "https-plan"
            return {"plan": {"tasks": [task]}}

        async def initialize(self, *, drain=False):
            assert drain is False

        async def run_workflow_plan(self, plan_id):
            self.direct_calls.append(plan_id)
            return {
                "complete": True,
                "tasks": [{"id": "task-1", "status": "succeeded"}],
            }

        def workflow_report(self, plan_id):
            assert plan_id == "https-plan"
            return {
                "status": "complete",
                "findings": [{
                    "severity": "info",
                    "kind": "http_header_missing",
                    "raw_line": "https://api.acme.test/: missing strict-transport-security",
                }],
            }

        def enqueue_workflow_run(self, plan_id):
            self.run_calls.append(plan_id)
            return {"id": "request-1", "status": "queued"}

    core = _ExecutionCore()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)

    status = recon_cmd.main([
        "api.acme.test", "--engine", "v2", "--plan-id", "https-plan",
    ])

    assert status == recon_cmd.EXIT_OK
    assert core.run_calls == ["https-plan"]
    assert core.direct_calls == []
    assert "request request-1, queued" in capsys.readouterr().out


def test_v2_recon_cli_rejects_dynamic_https_paths_before_dispatch(monkeypatch, capsys):
    task = {
        "id": "task-1",
        "capability_id": CAPABILITY_ID,
        "target": "api.acme.test",
        "inputs": {"path": "/admin"},
        "depends_on": [],
    }

    class _ExecutionCore:
        run_calls = []

        def __init__(self, _data_dir=None):
            pass

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
        "api.acme.test", "--engine", "v2", "--plan-id", "https-plan",
    ])

    assert status == recon_cmd.EXIT_USAGE
    assert core.run_calls == []
    assert "fixed DNS, TLS, HTTPS, headers, redirects, robots, or security.txt task" in capsys.readouterr().err



def test_v2_recon_cli_queues_without_rendering_provider_output(
    monkeypatch, capsys,
):
    findings = [
        finding.to_dict()
        for finding in _collect_findings(
            "api.acme.test",
            "api.acme.test",
            [("Server", "Apache/2.4.57\x1b[31m\u202e")],
        )
    ]
    task = {
        "id": "task-1",
        "capability_id": CAPABILITY_ID,
        "target": "api.acme.test",
        "inputs": {},
        "depends_on": [],
    }

    class _ExecutionCore:
        def __init__(self):
            self.run_calls = []

        def workflow_plan_details(self, _plan_id):
            return {"plan": {"tasks": [task]}}

        async def initialize(self, *, drain=False):
            assert drain is False

        async def run_workflow_plan(self, _plan_id):
            return {
                "complete": True,
                "tasks": [{"id": "task-1", "status": "succeeded"}],
            }

        def enqueue_workflow_run(self, plan_id):
            self.run_calls.append(plan_id)
            return {"id": "request-1", "status": "queued"}

        def workflow_report(self, _plan_id):
            return {"status": "complete", "findings": findings}

    core = _ExecutionCore()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)

    status = recon_cmd.main([
        "api.acme.test", "--engine", "v2", "--plan-id", "safe-output-plan",
    ])

    output = capsys.readouterr().out
    assert status == recon_cmd.EXIT_OK
    assert core.run_calls == ["safe-output-plan"]
    assert "\x1b" not in output
    assert "\u202e" not in output
    assert "request request-1, queued" in output
