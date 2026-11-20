"""One-shot inspection/replay must not claim work queued by another invocation."""
from __future__ import annotations

import json

import pytest

from whaxon.core import Core
from whaxon.core.findings import Finding
from whaxon.core.recon import ReconRunner
from whaxon.core.recon_v2 import PassiveDnsReconProvider
from whaxon.core.runner import ToolRunner
from whaxon.core.validator import Validator
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.cli import coverage_cmd, recon_cmd, retest_cmd, validate_cmd


@pytest.mark.parametrize(
    ("command", "outcome", "expected"),
    [
        (coverage_cmd, "normal", 0),
        (coverage_cmd, "missing", 1),
        (validate_cmd, "normal", validate_cmd.EXIT_V2_WORKFLOW_REQUIRED),
        (validate_cmd, "missing", 1),
        (validate_cmd, "blocked", 4),
        (retest_cmd, "normal", retest_cmd.EXIT_V2_WORKFLOW_REQUIRED),
        (retest_cmd, "missing", 1),
        (retest_cmd, "blocked", 4),
        (retest_cmd, "ineligible", 3),
        (recon_cmd, "normal", 0),
        (recon_cmd, "blocked", 1),
    ],
)
def test_one_shot_preserves_unrelated_pending_jobs(
    tmp_path, monkeypatch, command, outcome, expected,
):
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    (data / "scope.json").write_text(json.dumps({
        "enabled": True, "in_scope": ["127.0.0.1"], "out_of_scope": [],
    }))
    core = Core(data)
    target = "203.0.113.9" if outcome == "blocked" else "127.0.0.1"
    core.store.create("requested")
    core.store.set_started("requested", "sqlmap", target)
    core.store.append_finding("requested", Finding(
        kind="sqli", severity="high", source="test", data={"parameter": "id"},
    ), 0)
    if outcome != "ineligible":
        core.store.update_verification("requested", 0, "verified")
    core.store.set_finished("requested", 0, 0.0)
    core.store.create_pending("unrelated", "echo", "127.0.0.1")

    dispatched = []

    async def record_dispatch(self, *args, **kwargs):
        dispatched.append(kwargs)

    # Keep actual Core initialization, claims and SQLite state. Only the final
    # external execution/replay is intercepted so this regression has no traffic.
    monkeypatch.setattr(ToolRunner, "run_tool", record_dispatch)
    monkeypatch.setattr(Validator, "validate", lambda *a, **k: ("candidate", "test"))
    monkeypatch.setattr(Validator, "revalidate", lambda *a, **k: ("inconclusive", "test"))
    monkeypatch.setattr(ReconRunner, "run", lambda *a, **k: None)

    job_id = "missing" if outcome == "missing" else "requested"
    if command is recon_cmd:
        args = [target]
    elif command is coverage_cmd:
        args = [job_id]
    else:
        args = [job_id, "0"]

    assert command.main(args) == expected
    assert dispatched == []
    assert core.store.list_pending() == [
        {"id": "unrelated", "tool": "echo", "target": "127.0.0.1"},
    ]
    assert core.store.get("unrelated")["status"] == "pending"


def test_v2_recon_cli_queues_unapproved_plan_without_draining_unrelated_jobs(
    tmp_path, monkeypatch, capsys,
):
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    (data / "scope.json").write_text(json.dumps({
        "engagement": "v2-recon-cli-isolation",
        "enabled": True,
        "in_scope": ["example.test"],
        "out_of_scope": [],
        "notes": "deterministic V2 recon CLI isolation fixture",
    }), encoding="utf-8")
    core = Core(data)
    core.scope.load()
    core.create_mission("dns-mission", "Collect scoped passive DNS evidence")
    provider = next(
        item for item in core.providers._providers
        if isinstance(item, PassiveDnsReconProvider)
    )
    monkeypatch.setattr(provider, "_readiness", lambda: True)
    manifest = core.providers.manifest_for("dns.recon.passive")
    task = WorkflowTask(
        id="task-1",
        capability_id=manifest.capability_id,
        target="example.test",
        inputs={},
        permissions=manifest.permissions,
        impact=manifest.impact,
        timeout_s=manifest.timeout_s,
        idempotency_key="v2-recon-cli-isolation",
    )
    plan = WorkflowPlan(
        mission_id="dns-mission",
        tasks=(task,),
        metadata={"provider_bindings": {"task-1": {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }}},
    )
    core.save_workflow_plan("dns-plan", plan)
    core.store.create_pending("unrelated", "echo", "127.0.0.1")

    tool_dispatches = []
    provider_dispatches = []

    async def record_tool_dispatch(self, *args, **kwargs):
        tool_dispatches.append((args, kwargs))

    async def record_provider_dispatch(self, task):
        provider_dispatches.append(task.id)
        raise AssertionError("unapproved DNS task must not dispatch")

    monkeypatch.setattr(ToolRunner, "run_tool", record_tool_dispatch)
    monkeypatch.setattr(PassiveDnsReconProvider, "dispatch", record_provider_dispatch)
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)

    status = recon_cmd.main([
        "example.test", "--engine", "v2", "--plan-id", "dns-plan",
        "--data", str(data),
    ])

    assert status == recon_cmd.EXIT_OK
    assert "queued for the supervised V2 worker" in capsys.readouterr().out
    assert core.workflow_run_queue_summary()["counts"]["queued"] == 1
    assert tool_dispatches == []
    assert provider_dispatches == []
    assert core.store.list_pending() == [
        {"id": "unrelated", "tool": "echo", "target": "127.0.0.1"},
    ]
    assert core.store.get("unrelated")["status"] == "pending"
