import json
import socket
from types import SimpleNamespace

from whaxon.core import Core, workflow_proposals
from whaxon.core.scope import ScopeManager
from whaxon.core.workflow import WorkflowPlan
from whaxon.interfaces.cli import workflow_cmd


class _Core:
    def __init__(self, *, allowed=True, ready=True):
        self.saved = []
        self.resolved = []
        self.store = SimpleNamespace(get_mission=lambda mission_id: {"id": mission_id})
        self.catalog = SimpleNamespace(get=lambda tool_id: {"id": tool_id})
        self.scope = SimpleNamespace(
            load=lambda: None,
            check=lambda target: SimpleNamespace(allowed=allowed, reason="blocked by scope"),
            check_for_execution=lambda target: SimpleNamespace(
                allowed=allowed, reason="blocked by scope",
            ),
        )
        self.manifest = SimpleNamespace(
            capability_id="network.services.discover", provider_id="whaxon.local.nmap",
            fingerprint="manifest-sha256", impact="moderate",
            input_schema={"properties": {}, "required": [], "additionalProperties": False},
            permissions=("network.scan",), timeout_s=90,
        )
        def resolve_task(task, **kwargs):
            self.resolved.append((task, kwargs))
            return SimpleNamespace(manifest=self.manifest)

        self.providers = SimpleNamespace(
            manifest_for=lambda capability_id: self.manifest,
            resolve_task=resolve_task,
        )
        self.capability_inventory = lambda: [{
            "capability_id": "network.services.discover", "provider_id": "whaxon.local.nmap",
            "selected_for_execution": ready, "installed": ready, "executable": ready,
        }]

    def save_workflow_plan(self, plan_id, plan):
        self.saved.append((plan_id, plan))
        return True


def test_tool_proposal_is_fixed_argument_and_provider_pinned():
    core = _Core()
    proposal = workflow_proposals.propose_tool_workflow_plan(
        core, mission_id="mission-1", plan_id="plan-1",
        tool_id="nmap", target="192.0.2.10",
    )

    assert proposal["status"] == "proposed"
    assert proposal["execution_submitted"] is False
    assert proposal["approval_granted"] is False
    task = WorkflowPlan.from_dict(proposal["plan"]).tasks[0]
    assert task.capability_id == "network.services.discover"
    assert task.inputs == {}
    assert proposal["plan"]["metadata"]["provider_bindings"]["task-1"] == {
        "provider_id": "whaxon.local.nmap",
        "manifest_fingerprint": "manifest-sha256",
    }
    assert len(core.resolved) == 1
    assert core.saved == []


def _write_scope(path, in_scope, out_scope=()):
    path.write_text(json.dumps({
        "engagement": "proposal-scope-test",
        "enabled": True,
        "in_scope": in_scope,
        "out_of_scope": list(out_scope),
        "notes": "",
    }), encoding="utf-8")


def test_tool_proposal_allows_hostname_only_scope(tmp_path):
    core = _Core()
    scope_path = tmp_path / "scope.json"
    _write_scope(scope_path, ["example.test"])
    core.scope = ScopeManager(scope_path)

    proposal = workflow_proposals.propose_tool_workflow_plan(
        core, mission_id="mission-1", plan_id="plan-hostname",
        tool_id="nmap", target="example.test",
    )

    assert proposal["status"] == "proposed"


def test_tool_proposal_reloads_scope_after_external_revocation(tmp_path):
    core = _Core()
    scope_path = tmp_path / "scope.json"
    _write_scope(scope_path, ["example.test"])
    core.scope = ScopeManager(scope_path)
    _write_scope(scope_path, [])

    proposal = workflow_proposals.propose_tool_workflow_plan(
        core, mission_id="mission-1", plan_id="plan-revoked-scope",
        tool_id="nmap", target="example.test",
    )

    assert proposal["status"] == "blocked"
    assert "outside current scope" in proposal["reason"]
    assert core.resolved == []


def test_tool_proposal_blocks_hostname_under_mixed_ip_cidr_scope(
    tmp_path, monkeypatch,
):
    core = _Core()
    scope_path = tmp_path / "scope.json"
    _write_scope(scope_path, ["example.test", "192.0.2.0/24"])
    core.scope = ScopeManager(scope_path)
    monkeypatch.setattr(
        "whaxon.core.scope.socket.getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
        ],
    )

    proposal = workflow_proposals.propose_tool_workflow_plan(
        core, mission_id="mission-1", plan_id="plan-mixed-scope",
        tool_id="nmap", target="example.test",
    )

    assert proposal["status"] == "blocked"
    assert "cannot be safely DNS-pinned" in proposal["reason"]
    assert core.resolved == []


def test_tool_proposal_allows_in_scope_ip_literal(tmp_path):
    core = _Core()
    scope_path = tmp_path / "scope.json"
    _write_scope(scope_path, ["192.0.2.0/24"])
    core.scope = ScopeManager(scope_path)

    proposal = workflow_proposals.propose_tool_workflow_plan(
        core, mission_id="mission-1", plan_id="plan-ip",
        tool_id="nmap", target="192.0.2.10",
    )

    assert proposal["status"] == "proposed"


def test_workflow_authorization_reloads_scope_revoked_after_proposal(tmp_path):
    core = _Core()
    scope_path = tmp_path / "scope.json"
    _write_scope(scope_path, ["192.0.2.10"])
    core.scope = ScopeManager(scope_path)
    proposal = workflow_proposals.propose_tool_workflow_plan(
        core, mission_id="mission-1", plan_id="plan-revoked",
        tool_id="nmap", target="192.0.2.10",
    )
    assert proposal["status"] == "proposed"
    task = WorkflowPlan.from_dict(proposal["plan"]).tasks[0]

    _write_scope(scope_path, [])
    assert Core.authorize_workflow_task(core, task) is False


def test_tool_proposal_blocks_out_of_scope_target():
    proposal = workflow_proposals.propose_tool_workflow_plan(
        _Core(allowed=False), mission_id="mission-1", plan_id="plan-1",
        tool_id="nmap", target="192.0.2.10",
    )
    assert proposal["status"] == "blocked"
    assert "outside current scope" in proposal["reason"]


def test_tool_proposal_blocks_unready_provider():
    proposal = workflow_proposals.propose_tool_workflow_plan(
        _Core(ready=False), mission_id="mission-1", plan_id="plan-1",
        tool_id="nmap", target="192.0.2.10",
    )
    assert proposal["status"] == "blocked"
    assert "not selected and ready" in proposal["reason"]


def test_finding_verification_proposal_binds_exact_source_and_kind():
    source_job_id = "0123456789ab"
    resolved = []
    manifest = SimpleNamespace(
        capability_id="tool.verify_xss", provider_id="whaxon.verifier.http",
        fingerprint="verifier-manifest", impact="moderate",
        permissions=("network.verify",), timeout_s=75,
    )
    core = SimpleNamespace(
        store=SimpleNamespace(
            get_mission=lambda _mission_id: {"id": "mission-1"},
            get=lambda job_id: {"id": job_id, "target": "http://192.0.2.10/search"},
            get_findings=lambda _job_id: [{"seq": 3, "kind": "xss"}],
        ),
        scope=SimpleNamespace(check=lambda _target: SimpleNamespace(allowed=True)),
        providers=SimpleNamespace(
            manifest_for=lambda _capability: manifest,
            resolve_task=lambda task, **kwargs: resolved.append((task, kwargs)),
        ),
    )
    proposal = workflow_proposals.propose_finding_verification_plan(
        core, mission_id="mission-1", plan_id="plan-verify",
        source_job_id=source_job_id, finding_seq=3, mode="verify",
    )

    assert proposal["status"] == "proposed"
    task = WorkflowPlan.from_dict(proposal["plan"]).tasks[0]
    assert task.capability_id == "tool.verify_xss"
    assert task.inputs == {"source_job_id": source_job_id, "finding_seq": 3}
    assert task.target == "http://192.0.2.10/search"
    assert resolved[0][1] == {"require_installed": True}
    assert proposal["execution_submitted"] is False
    assert proposal["approval_granted"] is False


def test_finding_verification_proposal_blocks_unsealed_source():
    source_job_id = "0123456789ab"
    manifest = SimpleNamespace(
        capability_id="tool.verify_sqli", provider_id="whaxon.verifier.http",
        fingerprint="verifier-manifest", impact="moderate",
        permissions=("network.verify",), timeout_s=75,
    )
    core = SimpleNamespace(
        store=SimpleNamespace(
            get_mission=lambda _mission_id: {"id": "mission-1"},
            get=lambda job_id: {"id": job_id, "target": "http://192.0.2.10/search"},
            get_findings=lambda _job_id: [{"seq": 0, "kind": "sqli"}],
        ),
        scope=SimpleNamespace(check=lambda _target: SimpleNamespace(allowed=True)),
        providers=SimpleNamespace(
            manifest_for=lambda _capability: manifest,
            resolve_task=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                ValueError("source must be a successful sealed V2 job")
            ),
        ),
    )
    proposal = workflow_proposals.propose_finding_verification_plan(
        core, mission_id="mission-1", plan_id="plan-verify",
        source_job_id=source_job_id, finding_seq=0, mode="verify",
    )
    assert proposal["status"] == "blocked"
    assert "source evidence" in proposal["reason"]


def test_cli_persists_proposal_only_when_save_is_explicit(monkeypatch, capsys, tmp_path):
    core = _Core()
    monkeypatch.setattr(workflow_cmd, "Core", lambda **kwargs: core)

    result = workflow_cmd.main([
        "--data-dir", str(tmp_path), "plan", "propose-tool",
        "--mission-id", "mission-1", "--id", "plan-1", "--tool", "nmap",
        "--target", "192.0.2.10",
    ])
    output = capsys.readouterr().out
    assert result == 0
    assert '"execution_submitted": false' in output
    assert '"approval_granted": false' in output
    assert core.saved == []

    result = workflow_cmd.main([
        "--data-dir", str(tmp_path), "plan", "propose-tool",
        "--mission-id", "mission-1", "--id", "plan-2", "--tool", "nmap",
        "--target", "192.0.2.10", "--save",
    ])
    assert result == 0
    assert len(core.saved) == 1
    assert core.saved[0][0] == "plan-2"
    assert core.saved[0][1].digest
