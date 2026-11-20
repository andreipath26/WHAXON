import json

import whaxon.interfaces.cli.workflow_cmd as workflow_cmd


class _FakeCore:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.created = None
        self.saved = None
        self.initialized_with_drain = None
        self.capabilities = type("Registry", (), {"list": lambda self: []})()
        self.store = type("Store", (), {
            "get_workflow_plan": lambda self, plan_id: None,
            "list_workflow_tasks": lambda self, plan_id: [],
        })()

    def create_mission(self, mission_id, objective):
        self.created = (mission_id, objective)
        return True

    def save_workflow_plan(self, plan_id, plan):
        self.saved = (plan_id, plan)
        return True

    def workflow_plan_details(self, plan_id):
        return {"plan": {"mission_id": "m"}, "tasks": [{"id": "scan"}]}

    def capability_inventory(self):
        return [{"capability_id": "tool.nmap", "executable": False}]

    def capability_portfolio_audit(self):
        return {"summary": {"bound": 0}, "execution_enabled_by_audit": False}

    def propose_workflow_followups(self, source_plan_id, *, max_tasks=16):
        plan = {"mission_id": "m", "tasks": [{"id": "followup"}]}
        return type("Proposal", (), {
            "plan_id": "proposal-1",
            "plan": plan,
            "to_dict": lambda self: {
                "source_plan_id": source_plan_id,
                "max_tasks": max_tasks,
                "plan_id": self.plan_id,
                "plan": self.plan,
            },
        })()

    def configure_mission_cost_limit(self, mission_id, *, max_cost_microusd):
        self.cost_cap = (mission_id, max_cost_microusd)

    def mission_cost_summary(self, mission_id):
        return {"mission_id": mission_id, "accounted_cost_microusd": 0}

    def record_workflow_attempt_cost(self, attempt_id, *, cost_microusd, source):
        return cost_microusd

    def configure_mission_rate_limit(self, mission_id, *, min_spacing_s):
        self.mission_rate = (mission_id, min_spacing_s)

    def mission_rate_limit(self, mission_id):
        return {"mission_id": mission_id, "min_spacing_s": getattr(self, "mission_rate", (None, None))[1]}

    def configure_mission_deadline(self, mission_id, *, deadline_at):
        self.persisted_mission_deadline = (mission_id, deadline_at)

    def mission_deadline(self, mission_id):
        return self.persisted_mission_deadline[1]

    def mission_execution_limits(self, mission_id):
        return {"mission_id": mission_id, "max_total_attempts": 2, "max_concurrency": 1}

    def configure_mission_execution_limits(
        self, mission_id, *, max_total_attempts, max_concurrency,
    ):
        self.mission_caps = (mission_id, max_total_attempts, max_concurrency)

    def missions(self, *, limit=100, after_created=0.0):
        return [{"id": "mission-1", "created_at": after_created + 1}][:limit]

    def mission_workflow_plans(self, mission_id):
        return [{"id": "p", "status": "proposed", "digest": "abc"}]

    def workflow_dispatch_reconciliation(self, plan_id):
        return [{"attempt_id": "a", "external_effect_possible": True}]

    def workflow_readiness(self, plan_id):
        return {"plan_id": plan_id, "ready_to_report_success": False}

    def workflow_evidence(self, plan_id, *, limit=100):
        return {
            "plan_id": plan_id, "all_evidence_recorded": False,
            "attempts": [], "limit_seen": limit,
        }

    def workflow_resource_summary(self, plan_id):
        return {"plan_id": plan_id, "cost_usd": None, "cost_accounting_available": False}

    def workflow_audit_integrity(self, plan_id):
        return {"plan_id": plan_id, "consistent": True, "attempts": 0}

    def workflow_attempts(self, plan_id, *, after_started=0.0, limit=100):
        return [{
            "id": "attempt-1", "task_key": "scan",
            "started_at": after_started + 1, "status": "running",
        }][:limit]

    def workflow_progress(self, plan_id):
        return {"plan_id": plan_id, "complete": False, "counts": {"pending": 1}}

    def workflow_event_inbox(self, plan_id, consumer_id, *, limit=100):
        return [{"id": 7, "event_type": "task_claimed"}][:limit]

    def acknowledge_workflow_event(self, plan_id, consumer_id, event_id):
        return event_id

    def workflow_events(self, plan_id, after_id=0, limit=100):
        return [{"plan_id": plan_id, "id": after_id + 1, "event_type": "task_claimed"}][:limit]

    def cancel_workflow_plan(self, plan_id):
        self.cancelled = plan_id
        return 1

    def reconcile_workflow_plan(self, plan_id, *, stale_after_s=60.0):
        self.reconciled = (plan_id, stale_after_s)
        return 2
    def reconcile_workflow_attempt(
        self, plan_id, attempt_id, *, disposition, actor, evidence_ref, note,
    ):
        self.reconciled_attempt = (
            plan_id, attempt_id, disposition, actor, evidence_ref, note,
        )
        return {
            "attempt_id": attempt_id, "disposition": disposition,
            "task_retryable": disposition == "no_effect_verified",
            "automatic_replay": False, "run_requests_closed": 1,
        }


    def grant_workflow_approval(
        self, plan_id, task_key, approval_id, actor, *, expires_at, policy_version="policy.v1",
    ):
        return True

    def revoke_workflow_approval(self, plan_id, approval_id, *, actor):
        return True

    def workflow_approvals(self, plan_id):
        return [{"approval_id": "approved-1", "task_key": "scan", "actor": "operator"}]

    def configure_workflow_rate_limit(self, plan_id, *, min_spacing_s):
        self.rate_limit = (plan_id, min_spacing_s)

    def configure_workflow_deadline(self, plan_id, *, deadline_at):
        self.deadline = (plan_id, deadline_at)

    def configure_workflow_limits(self, plan_id, *, max_total_attempts, max_concurrency):
        self.limits = (plan_id, max_total_attempts, max_concurrency)

    async def initialize(self, drain=True):
        self.initialized_with_drain = drain

    async def run_workflow_plan(self, plan_id, **kwargs):
        return {
            "complete": True,
            "tasks": [{"id": "scan", "status": "succeeded"}],
            "plan_id": plan_id,
        }

    def enqueue_workflow_run(self, plan_id, **kwargs):
        self.enqueued = (plan_id, kwargs)
        return {"id": "request-1", "plan_id": plan_id, "status": "queued"}



def test_tls_proposal_cli_persists_only_when_requested(monkeypatch, capsys):
    import whaxon.core.workflow_proposals as proposals

    core = _FakeCore(data_dir=None)
    monkeypatch.setattr(workflow_cmd, "Core", lambda *, data_dir: core)
    proposal_plan = {
        "mission_id": "mission-1",
        "tasks": [{
            "id": "task-1", "capability_id": "tls.certificate.inspect",
            "target": "example.test", "permissions": ["network.scan"],
            "impact": "moderate",
        }],
    }
    calls = []
    monkeypatch.setattr(
        proposals, "propose_tls_certificate_plan",
        lambda _core, **kwargs: (
            calls.append(kwargs) or {
                "status": "proposed", "plan_id": kwargs["plan_id"],
                "plan": proposal_plan, "approval_granted": False,
            }
        ),
    )

    args = [
        "plan", "propose-tls-recon", "--mission-id", "mission-1",
        "--id", "tls-plan", "--target", "example.test",
    ]
    assert workflow_cmd.main(args) == 0
    dry_result = json.loads(capsys.readouterr().out)
    assert dry_result["created"] is False
    assert core.saved is None

    assert workflow_cmd.main([*args, "--save"]) == 0
    saved_result = json.loads(capsys.readouterr().out)
    assert saved_result["created"] is True
    assert saved_result["approval_granted"] is False
    assert core.saved[0] == "tls-plan"
    assert calls == [
        {"mission_id": "mission-1", "plan_id": "tls-plan", "target": "example.test"},
        {"mission_id": "mission-1", "plan_id": "tls-plan", "target": "example.test"},
    ]
    assert core.initialized_with_drain is None

def test_workflow_cli_creates_mission(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "mission", "create", "--id", "mission-1", "--objective", "audit lab",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["created"] is True


def test_workflow_cli_capability_views_are_read_only_core_calls(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["capabilities"]) == 0
    assert json.loads(capsys.readouterr().out) == []
    assert workflow_cmd.main(["providers"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["executable"] is False
    assert workflow_cmd.main(["portfolio-audit"]) == 0
    assert json.loads(capsys.readouterr().out)["execution_enabled_by_audit"] is False


def test_workflow_cli_show_and_followups_do_not_execute_a_plan(
    monkeypatch, capsys,
):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["plan", "show", "--id", "plan-1"]) == 0
    assert json.loads(capsys.readouterr().out)["tasks"][0]["id"] == "scan"

    core = _FakeCore(data_dir=None)
    monkeypatch.setattr(workflow_cmd, "Core", lambda data_dir: core)
    assert workflow_cmd.main([
        "plan", "followups", "--source-id", "source-1",
    ]) == 0
    proposal = json.loads(capsys.readouterr().out)
    assert proposal["created"] is False
    assert core.saved is None
    assert getattr(core, "initialized_with_drain", None) is None

    assert workflow_cmd.main([
        "plan", "followups", "--source-id", "source-1", "--save",
    ]) == 0
    saved_proposal = json.loads(capsys.readouterr().out)
    assert saved_proposal["created"] is True
    assert core.saved[0] == "proposal-1"
    assert getattr(core, "initialized_with_drain", None) is None


def test_workflow_cli_validates_and_persists_plan_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps({
        "mission_id": "mission-1",
        "tasks": [{
            "id": "scan", "capability_id": "tool.nmap", "target": "192.0.2.10",
            "permissions": ["network.scan"], "impact": "moderate",
        }],
    }), encoding="utf-8")
    assert workflow_cmd.main([
        "plan", "save", "--id", "plan-1", "--file", str(plan_file),
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["plan_id"] == "plan-1"
    assert len(result["digest"]) == 64


def test_workflow_cli_runs_headless_without_draining_legacy_jobs(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["plan", "run", "--id", "plan-1"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["execution_started"] is False
    assert result["run_request"]["status"] == "queued"
    assert "serve-requests" in result["next"][1]


def test_workflow_cli_progress_and_events(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["plan", "progress", "--id", "p"]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["pending"] == 1
    assert workflow_cmd.main([
        "plan", "events", "--id", "p", "--after-id", "3", "--limit", "1",
    ]) == 0
    assert json.loads(capsys.readouterr().out)[0]["id"] == 4


def test_workflow_cli_cancel_and_limits(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["plan", "cancel", "--id", "p"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["cancellation_requested"] is True
    assert result["tasks_cancelled"] == 1
    assert workflow_cmd.main([
        "plan", "limits", "--id", "p", "--max-total-attempts", "7",
        "--max-concurrency", "2",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["max_total_attempts"] == 7


def test_workflow_cli_reconcile_marks_uncertain_without_dispatch(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "plan", "reconcile", "--id", "p", "--stale-after-seconds", "90",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["attempts_marked_uncertain"] == 2


def test_workflow_cli_exposes_read_only_attempt_diagnostics(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "plan", "attempts", "--id", "p",
        "--after-started", "4", "--limit", "1",
    ]) == 0
    attempts = json.loads(capsys.readouterr().out)
    assert attempts == [{
        "id": "attempt-1", "task_key": "scan",
        "started_at": 5.0, "status": "running",
    }]


def test_mission_plan_list_cli(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["mission", "plans", "--id", "mission-1"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["id"] == "p"


def test_workflow_cli_lists_persisted_missions(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "mission", "list", "--limit", "1", "--after-created", "2",
    ]) == 0
    assert json.loads(capsys.readouterr().out)[0]["created_at"] == 3.0


def test_workflow_cli_audit(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["plan", "audit", "--id", "p"]) == 0
    assert json.loads(capsys.readouterr().out)["consistent"] is True


def test_workflow_cli_reconciliation_report(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["plan", "reconciliation-report", "--id", "p"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["external_effect_possible"] is True


def test_workflow_cli_configures_durable_deadline(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "plan", "deadline", "--id", "p", "--unix-time", "2000000000",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["deadline_at"] == 2000000000.0


def test_workflow_cli_persists_rate_limit(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "plan", "rate-limit", "--id", "p", "--min-spacing-seconds", "4.5",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["min_spacing_s"] == 4.5


def test_workflow_cli_resources_do_not_invent_cost(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["plan", "resources", "--id", "p"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["cost_usd"] is None
    assert result["cost_accounting_available"] is False


def test_workflow_cli_readiness_fails_closed(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["plan", "readiness", "--id", "p"]) == 1
    assert json.loads(capsys.readouterr().out)["ready_to_report_success"] is False


def test_workflow_cli_approval_workflows(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "plan", "approval", "grant", "--id", "p", "--task", "scan",
        "--approval-id", "approved-1", "--actor", "operator",
        "--expires-at", "2000000000",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["created"] is True
    assert workflow_cmd.main([
        "plan", "approval", "list", "--id", "p",
    ]) == 0
    assert json.loads(capsys.readouterr().out)[0]["actor"] == "operator"
    assert workflow_cmd.main([
        "plan", "approval", "revoke", "--id", "p",
        "--approval-id", "approved-1", "--actor", "operator",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["revoked"] is True


def test_workflow_cli_event_inbox_and_checkpoint(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "plan", "event-inbox", "--id", "p", "--consumer", "reporter",
    ]) == 0
    assert json.loads(capsys.readouterr().out)[0]["id"] == 7
    assert workflow_cmd.main([
        "plan", "event-ack", "--id", "p", "--consumer", "reporter",
        "--event-id", "7",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["last_event_id"] == 7


def test_mission_limits_cli(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "mission", "limits", "--id", "m",
        "--max-total-attempts", "2", "--max-concurrency", "1",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["max_concurrency"] == 1
    assert workflow_cmd.main(["mission", "budget", "--id", "m"]) == 0
    assert json.loads(capsys.readouterr().out)["max_total_attempts"] == 2


def test_mission_deadline_cli(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "mission", "deadline", "--id", "m", "--unix-time", "2000000000",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["mission_id"] == "m"


def test_mission_cost_commands_use_shared_core(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "mission", "cost-limit", "--id", "m", "--max-cost-microusd", "99",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["mission_id"] == "m"
    assert workflow_cmd.main([
        "plan", "record-cost", "--attempt-id", "a",
        "--cost-microusd", "25", "--source", "invoice",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["cost_microusd"] == 25


def test_cli_mission_rate_config_and_query(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "mission", "rate-limit", "--id", "m", "--min-spacing-s", "5",
    ]) == 0
    configured = json.loads(capsys.readouterr().out)
    assert configured["min_spacing_s"] == 5
    assert workflow_cmd.main(["mission", "rate", "--id", "m"]) == 0
    assert json.loads(capsys.readouterr().out)["mission_id"] == "m"


def test_cli_mission_deadline_returns_persisted_cutoff_not_budget(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "mission", "deadline", "--id", "m", "--unix-time", "2000000000",
    ]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "mission_id": "m", "deadline_at": 2000000000.0,
    }


def test_workflow_cli_exposes_only_persisted_evidence(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main(["plan", "evidence", "--id", "p", "--limit", "5"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["plan_id"] == "p"
    assert data["limit_seen"] == 5
    assert data["all_evidence_recorded"] is False
    assert data["attempts"] == []


def test_e5_cli_run_snapshot_is_shared_core_contract(monkeypatch, capsys):
    class SnapshotCore(_FakeCore):
        def workflow_run_snapshot(self, request_id):
            if request_id == "missing":
                return None
            return {
                "schema_version": "whaxon.workflow-run-snapshot.v1",
                "request": {"id": request_id, "status": "uncertain"},
                "progress": {"plan_id": "p", "complete": False},
                "worker_liveness_verified": False,
                "automatic_uncertain_replay": False,
            }

    monkeypatch.setattr(workflow_cmd, "Core", SnapshotCore)
    assert workflow_cmd.main([
        "plan", "run-snapshot", "--id", "durable-request",
    ]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["request"]["id"] == "durable-request"
    assert data["request"]["status"] == "uncertain"
    assert data["worker_liveness_verified"] is False
    assert data["automatic_uncertain_replay"] is False
    assert workflow_cmd.main([
        "plan", "run-snapshot", "--id", "missing",
    ]) == 1
    assert "unknown workflow run request" in capsys.readouterr().err


def test_e5_cli_cancel_request_uses_core_barrier(monkeypatch, capsys):
    class CancelCore(_FakeCore):
        def cancel_workflow_run_request(self, request_id):
            if request_id == "missing":
                raise ValueError("unknown workflow run request")
            return {
                "run_request_id": request_id,
                "cancellation_requested": True,
                "external_effects_stopped": False,
            }

    monkeypatch.setattr(workflow_cmd, "Core", CancelCore)
    assert workflow_cmd.main([
        "plan", "cancel-request", "--id", "run-123",
    ]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["run_request_id"] == "run-123"
    assert data["external_effects_stopped"] is False
    assert workflow_cmd.main([
        "plan", "cancel-request", "--id", "missing",
    ]) == 1
    assert "unknown workflow run request" in capsys.readouterr().err



def test_workflow_cli_records_manual_attempt_reconciliation(monkeypatch, capsys):
    monkeypatch.setattr(workflow_cmd, "Core", _FakeCore)
    assert workflow_cmd.main([
        "plan", "resolve-attempt", "--id", "p", "--attempt-id", "a",
        "--disposition", "no_effect_verified", "--actor", "operator",
        "--evidence-ref", "case://cli/17", "--note", "Checked target evidence.",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["attempt_id"] == "a"
    assert payload["task_retryable"] is True
    assert payload["automatic_replay"] is False
