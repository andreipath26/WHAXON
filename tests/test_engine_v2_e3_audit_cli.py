"""E3 Core and CLI lifecycle digest parity and mismatch exit code."""
from __future__ import annotations

import json

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask
from whaxon.interfaces.cli import workflow_cmd


def _seed(tmp_path):
    core = Core(tmp_path)
    core.create_mission("mission", "E3 operational audit reference")
    core.save_workflow_plan(
        "plan", WorkflowPlan("mission", (
            WorkflowTask("task", "fixture", "192.0.2.10"),
        )),
    )
    return core


def test_audit_cli_snapshot_and_verify_use_same_core_state(tmp_path, capsys):
    core = _seed(tmp_path)
    from_core = core.workflow_audit_snapshot("plan")
    args = ["--data-dir", str(tmp_path), "plan"]
    assert workflow_cmd.main([*args, "audit-snapshot", "--id", "plan"]) == 0
    from_cli = json.loads(capsys.readouterr().out)
    assert from_cli == from_core
    assert from_cli["independent_anchor_verified"] is False
    assert workflow_cmd.main([*args,
        "audit-verify", "--id", "plan",
        "--expected-digest", from_core["digest"],
    ]) == 0
    accepted = json.loads(capsys.readouterr().out)
    assert accepted["digest_matches_reference"] is True
    assert accepted["independent_anchor_verified"] is False
    assert workflow_cmd.main([*args,
        "audit-verify", "--id", "plan",
        "--expected-digest", "0" * 64,
    ]) == 1
    rejected = json.loads(capsys.readouterr().out)
    assert rejected["digest_matches_reference"] is False


def test_cli_detects_changed_task_state_against_preserved_reference(
    tmp_path, capsys,
):
    core = _seed(tmp_path)
    expected = core.workflow_audit_snapshot("plan")["digest"]
    claim = core.store.claim_ready_workflow_task("plan", "worker")
    assert claim is not None
    assert workflow_cmd.main([
        "--data-dir", str(tmp_path), "plan", "audit-verify",
        "--id", "plan", "--expected-digest", expected,
    ]) == 1
    assert json.loads(capsys.readouterr().out)[
        "digest_matches_reference"
    ] is False
