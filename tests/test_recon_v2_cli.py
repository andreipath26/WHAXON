from __future__ import annotations

import pytest

from whaxon.core.recon_v2 import CAPABILITY_ID
from whaxon.core.tls_cert_v2 import CAPABILITY_ID as TLS_CERT_CAPABILITY_ID
from whaxon.interfaces.cli import recon_cmd


class _FakeCore:
    def __init__(self, *, tasks=None, result=None, report=None):
        self.tasks = tasks if tasks is not None else [{
            "id": "task-1",
            "capability_id": CAPABILITY_ID,
            "target": "example.test",
            "inputs": {},
            "depends_on": [],
        }]
        self.result = result or {
            "complete": True,
            "tasks": [{"id": "task-1", "status": "succeeded"}],
        }
        self.report = report or {
            "status": "complete",
            "findings": [{
                "severity": "info",
                "kind": "dns_record",
                "raw_line": "example.test A 192.0.2.1",
            }],
        }
        self.run_calls = []
        self.enqueue_calls = []
        self.legacy_calls = []

    async def initialize(self, *, drain=False):
        assert drain is False

    def workflow_plan_details(self, plan_id):
        assert plan_id == "dns-plan"
        return {"plan": {"tasks": self.tasks}}

    async def run_workflow_plan(self, plan_id):
        self.run_calls.append(plan_id)
        return self.result

    def enqueue_workflow_run(self, plan_id):
        self.enqueue_calls.append(plan_id)
        return {"id": "request-1", "plan_id": plan_id, "status": "queued"}

    def workflow_report(self, plan_id):
        assert plan_id == "dns-plan"
        return self.report


@pytest.mark.parametrize(
    "tasks",
    [
        [{
            "id": "task-1",
            "capability_id": "network.services.discover",
            "target": "example.test",
            "inputs": {},
            "depends_on": [],
        }],
        [{
            "id": "task-1",
            "capability_id": CAPABILITY_ID,
            "target": "other.test",
            "inputs": {},
            "depends_on": [],
        }],
        [
            {
                "id": "task-1",
                "capability_id": CAPABILITY_ID,
                "target": "example.test",
                "inputs": {},
                "depends_on": [],
            },
            {
                "id": "task-2",
                "capability_id": CAPABILITY_ID,
                "target": "example.test",
                "inputs": {},
                "depends_on": [],
            },
        ],
        [{
            "id": "task-1",
            "capability_id": CAPABILITY_ID,
            "target": "example.test",
            "inputs": {"record_types": ["A"]},
            "depends_on": [],
        }],
    ],
)
def test_v2_recon_rejects_non_exact_plan_before_dispatch(monkeypatch, capsys, tasks):
    core = _FakeCore(tasks=tasks)
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)

    status = recon_cmd.main([
        "example.test", "--engine", "v2", "--plan-id", "dns-plan",
    ])

    assert status == recon_cmd.EXIT_USAGE
    assert core.run_calls == []
    assert "V2 recon" in capsys.readouterr().err


def test_v2_recon_queues_approved_plan_without_inline_dispatch(
    monkeypatch, capsys,
):
    core = _FakeCore()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)

    status = recon_cmd.main([
        "example.test", "--engine", "v2", "--plan-id", "dns-plan",
    ])

    output = capsys.readouterr().out
    assert status == recon_cmd.EXIT_OK
    assert core.run_calls == []
    assert core.enqueue_calls == ["dns-plan"]
    assert "request request-1, queued" in output
    assert "queued for the supervised V2 worker" in output


@pytest.mark.parametrize("capability_id", [CAPABILITY_ID, TLS_CERT_CAPABILITY_ID])
def test_v2_recon_leaves_approval_enforcement_to_supervised_worker(
    monkeypatch, capsys, capability_id,
):
    core = _FakeCore(
        tasks=[{
            "id": "task-1",
            "capability_id": capability_id,
            "target": "example.test",
            "inputs": {},
            "depends_on": [],
        }],
        result={
            "complete": False,
            "tasks": [{"id": "task-1", "status": "failed"}],
        },
        report={"findings": []},
    )
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)

    status = recon_cmd.main([
        "example.test", "--engine", "v2", "--plan-id", "dns-plan",
    ])

    assert status == recon_cmd.EXIT_OK
    assert core.run_calls == []
    assert core.enqueue_calls == ["dns-plan"]
    assert "queued for the supervised V2 worker" in capsys.readouterr().out


def test_v2_recon_disallows_legacy_check_filter():
    assert recon_cmd.main([
        "example.test", "--engine", "v2", "--plan-id", "dns-plan",
        "--checks", "dns",
    ]) == recon_cmd.EXIT_USAGE


def test_recon_default_only_proposes_v2_plan(monkeypatch):
    core = _FakeCore()
    proposals = []
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)
    monkeypatch.setattr(
        recon_cmd, "_propose_v2",
        lambda _core, target, **kwargs: proposals.append((target, kwargs)) or 0,
    )

    status = recon_cmd.main(["example.test"])

    assert status == recon_cmd.EXIT_OK
    assert proposals == [("example.test", {
        "checks": None, "mission_id": None, "plan_id": None, "verbose": False,
    })]


def test_recon_mission_and_plan_ids_select_proposal_mode(monkeypatch):
    core = _FakeCore()
    proposals = []
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)
    monkeypatch.setattr(
        recon_cmd, "_propose_v2",
        lambda _core, target, **kwargs: proposals.append((target, kwargs)) or 0,
    )

    status = recon_cmd.main([
        "example.test", "--mission-id", "mission-1", "--plan-id", "plan-1",
    ])

    assert status == recon_cmd.EXIT_OK
    assert proposals == [("example.test", {
        "checks": None, "mission_id": "mission-1", "plan_id": "plan-1", "verbose": False,
    })]


def test_legacy_recon_requires_explicit_flag_and_opt_in(monkeypatch, capsys):
    core = _FakeCore()
    core.scope = type("Scope", (), {"check": lambda *_args: None})()
    core.recon = type("Recon", (), {
        "run": lambda *_args, **_kwargs: pytest.fail("legacy dispatch must stay blocked"),
    })()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)
    monkeypatch.delenv("WHAXON_LEGACY_RECON_ENABLED", raising=False)

    status = recon_cmd.main(["example.test", "--legacy"])

    assert status == recon_cmd.EXIT_V2_WORKFLOW_REQUIRED
    error = capsys.readouterr().err.lower()
    assert "disabled" in error
    assert "no request" not in error


def test_legacy_recon_runs_only_with_explicit_flag_and_opt_in(monkeypatch, capsys):
    core = _FakeCore()
    core.scope = type("Scope", (), {
        "check": lambda _self, _target: type("Decision", (), {
            "allowed": True, "reason": "", "matched_rule": "",
        })(),
    })()
    core.recon = type("Recon", (), {
        "run": lambda _self, target, checks=None: "legacy-job",
    })()
    core.store = type("Store", (), {"get_findings": lambda _self, _job_id: []})()
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)
    monkeypatch.setenv("WHAXON_LEGACY_RECON_ENABLED", "true")

    status = recon_cmd.main(["example.test", "--legacy"])

    assert status == recon_cmd.EXIT_OK
    assert "legacy-job" in capsys.readouterr().out


def test_v2_recon_partial_persisted_report_is_not_success(
    monkeypatch, capsys,
):
    core = _FakeCore(report={"status": "partial", "findings": [{
        "severity": "info",
        "kind": "dns_record",
        "raw_line": "example.test A 192.0.2.1",
    }]})
    monkeypatch.setattr(recon_cmd, "Core", lambda _data_dir: core)

    status = recon_cmd.main([
        "example.test", "--engine", "v2", "--plan-id", "dns-plan",
    ])

    assert status == recon_cmd.EXIT_OK
    assert core.run_calls == []
    assert core.enqueue_calls == ["dns-plan"]
    assert "partial" not in capsys.readouterr().out
