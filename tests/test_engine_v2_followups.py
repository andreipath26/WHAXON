"""Engine V2 E4 follows evidence into new policy-bound plans."""
from types import SimpleNamespace

import pytest

from whaxon.core.capabilities import CapabilityManifest
from whaxon.core.followups import EvidenceFollowupPlanner, FollowupRule


class Store:
    def __init__(self):
        self.row = {"mission_id": "m", "digest": "source-digest"}
        self.evidence = [{
            "task_key": "recon", "capability_id": "tool.nmap",
            "target": "192.0.2.10", "attempt_status": "succeeded",
            "integrity_status": "verified", "evidence_status": "recorded",
            "job_id": "j1",
        }]
        self.job = {
            "id": "j1", "tool": "nmap", "target": "192.0.2.10",
            "status": "finished", "exit_code": 0,
        }
        self.findings = [
            {"source": "nmap", "kind": "open_port", "seq": 0,
             "data": {"port": 443, "service": "https"}},
            {"source": "nmap", "kind": "open_port", "seq": 1,
             "data": {"port": 80, "service": "http"}},
        ]

    def get_workflow_plan(self, plan_id):
        return self.row if plan_id == "source" else None

    def get_workflow_evidence(self, plan_id, *, limit):
        return {
            "plan_id": plan_id, "mission_id": self.row["mission_id"],
            "plan_digest": self.row["digest"], "attempts": self.evidence,
            "all_evidence_recorded": True,
            "all_evidence_integrity_verified": True,
        }

    def get(self, job_id):
        return self.job if job_id == "j1" else None

    def get_findings(self, job_id):
        return self.findings if job_id == "j1" else None


class Provider:
    def __init__(self, target_types=("url",)):
        self.manifest = CapabilityManifest(
            "tool.nikto", "trusted.nikto", "1", ("local_process",),
            target_types=target_types,
            permissions=("network.scan",), impact="moderate",
        )
        self.called = 0

    def manifest_for(self, capability_id):
        assert capability_id == "tool.nikto"
        return self.manifest

    def resolve_task(self, task, *, require_installed=False):
        self.called += 1
        assert require_installed is True
        assert task.capability_id == "tool.nikto"
        assert task.target.startswith("http") or task.target == "192.0.2.10"
        return SimpleNamespace(manifest=self.manifest)


def planner(store=None, provider=None, allowed=True, rules=None):
    return EvidenceFollowupPlanner(
        store=store or Store(), providers=provider or Provider(),
        scope=SimpleNamespace(check_for_execution=lambda target: SimpleNamespace(
            allowed=allowed,
        )),
        rules=rules if rules is not None else (
            FollowupRule(
                "web.v1", ("tool.nmap",), "open_port", "tool.nikto",
                "http_origin", ports=(80, 443),
            ),
        ),
    )


def test_e4_proposal_is_deterministic_not_executable_or_approved():
    result = planner().propose("source")
    assert [task.target for task in result.plan.tasks] == [
        "https://192.0.2.10:443", "http://192.0.2.10:80",
    ]
    assert all(task.impact == "moderate" for task in result.plan.tasks)
    assert result.plan.metadata["provenance"][0]["source_job"] == "j1"
    assert result.to_dict()["execution_started"] is False
    assert result.to_dict()["approval_granted"] is False
    assert planner().propose("source").plan_id == result.plan_id


@pytest.mark.parametrize("change", ["tamper", "unknown", "running", "mismatch"])
def test_e4_unverified_source_does_not_create_plan(change):
    store = Store()
    if change == "tamper":
        store.evidence[0]["integrity_status"] = "changed"
    elif change == "unknown":
        store.evidence[0]["attempt_status"] = "uncertain"
    elif change == "running":
        store.job["status"] = "running"
    else:
        store.job["target"] = "203.0.113.8"
    assert planner(store=store).propose("source").plan is None


def test_e4_scope_blocks_followups_and_invalid_limits():
    assert planner(allowed=False).propose("source").plan is None
    with pytest.raises(ValueError, match="max_tasks"):
        planner().propose("source", max_tasks=0)
    with pytest.raises(ValueError, match="unknown source"):
        planner().propose("missing")


def test_e4_deduplicates_and_limits_task_count():
    store = Store()
    store.findings.append(dict(store.findings[0]))
    proposal = planner(store=store).propose("source", max_tasks=1)
    assert len(proposal.plan.tasks) == 1
    assert proposal.blocked


def test_e4_new_rule_uses_same_provider_resolver_without_scheduler_change():
    store = Store()
    store.findings = store.findings[:1]
    rule = FollowupRule(
        "new-rule.v1", ("tool.nmap",), "open_port", "tool.nikto", "source",
    )
    result = planner(store=store, provider=Provider(("ip",)), rules=(rule,)).propose("source")
    assert result.plan.tasks[0].target == "192.0.2.10"


def test_e4_duplicate_rule_ids_refused():
    rule = FollowupRule(
        "duplicate.v1", ("tool.nmap",), "open_port", "tool.nikto", "source",
    )
    with pytest.raises(ValueError, match="unique"):
        planner(rules=(rule, rule))


def test_e4_followup_rules_inherit_provider_permissions_without_hardcoded_scan():
    store = Store()
    store.findings = store.findings[:1]
    rule = FollowupRule(
        "read-only.v1", ("tool.nmap",), "open_port", "tool.nikto", "source",
    )
    provider = Provider(("ip",))
    provider.manifest = CapabilityManifest(
        "tool.nikto", "trusted.nikto", "2", ("local_process",),
        target_types=("ip",), permissions=(), impact="read_only",
    )
    result = planner(store=store, provider=provider, rules=(rule,)).propose("source")
    assert result.plan.tasks[0].permissions == ()
    assert result.plan.tasks[0].impact == "read_only"


def test_e4_refuses_followup_from_cancelled_source():
    store = Store()
    store.row["status"] = "cancel_requested"
    with pytest.raises(ValueError, match="cancelled"):
        planner(store=store).propose("source")


def test_e4_proposed_plan_pins_provider_fingerprint():
    proposal = planner().propose("source")
    binding = proposal.plan.metadata["provider_bindings"]["followup-1"]
    assert binding["provider_id"] == "trusted.nikto"
    assert binding["manifest_fingerprint"] == planner().providers.manifest.fingerprint



def test_e4_semantic_evidence_proposes_only_pinned_semantic_followup():
    """Semantic source evidence maps to a separate unapproved semantic plan."""
    store = Store()
    store.evidence[0]["capability_id"] = "network.services.discover"

    class SemanticProvider:
        def __init__(self):
            self.manifest = CapabilityManifest(
                "web.server.audit", "trusted.semantic.web", "1",
                ("local_process",), target_types=("url",),
                permissions=("network.scan",), impact="moderate",
            )

        def manifest_for(self, capability_id):
            assert capability_id == "web.server.audit"
            return self.manifest

        def resolve_task(self, task, *, require_installed=False):
            assert require_installed is True
            assert task.capability_id == "web.server.audit"
            return SimpleNamespace(manifest=self.manifest)

    semantic_rule = FollowupRule(
        "web-semantic.v1", ("network.services.discover",), "open_port",
        "web.server.audit", "http_origin", ports=(80, 443),
    )
    proposal = planner(
        store=store, provider=SemanticProvider(), rules=(semantic_rule,),
    ).propose("source")
    assert proposal.plan is not None
    assert all(
        task.capability_id == "web.server.audit" for task in proposal.plan.tasks
    )
    assert proposal.to_dict()["approval_granted"] is False
    assert proposal.to_dict()["execution_started"] is False
    for task in proposal.plan.tasks:
        binding = proposal.plan.metadata["provider_bindings"][task.id]
        assert binding["provider_id"] == "trusted.semantic.web"
        assert binding["manifest_fingerprint"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("sources", "tool.nmap", "source identities"),
        ("sources", ("",), "source identities"),
        ("sources", ("tool.nmap", None), "source identities"),
        ("ports", [443], "port"),
        ("ports", (True,), "port"),
        ("services", "https", "service names"),
        ("services", (None,), "service names"),
        ("id", 123, "identity"),
        ("finding_kind", None, "identity"),
    ],
)
def test_e4_rule_contract_rejects_ambiguous_or_malformed_inputs(
    field, value, message,
):
    """No string membership aliases or malformed matching rules are admitted."""
    fields = {
        "id": "web.v1",
        "sources": ("tool.nmap",),
        "finding_kind": "open_port",
        "capability_id": "tool.nikto",
        "target_mode": "http_origin",
        "ports": (443,),
        "services": ("https",),
    }
    fields[field] = value
    with pytest.raises(ValueError, match=message):
        FollowupRule(**fields)


def test_e4_source_match_requires_exact_capability_identity():
    rule = FollowupRule(
        "web.v1", ("tool.nmap",), "open_port",
        "tool.nikto", "http_origin", ports=(443,),
    )
    finding = {"kind": "open_port", "data": {"port": 443}}
    assert rule.match("tool.nmap", finding)
    assert not rule.match("tool.nma", finding)
    assert not rule.match("tool.nmap.extra", finding)


def test_e4_followup_planner_blocks_resolver_manifest_drift():
    """Resolver identity cannot drift after the planner selects its provider."""
    class DriftingProvider(Provider):
        def resolve_task(self, task, *, require_installed=False):
            from whaxon.core.capabilities import CapabilityManifest

            incompatible = CapabilityManifest(
                "tool.nikto", "untrusted.replacement", "1",
                ("local_process",), target_types=("url",),
                permissions=("network.scan",), impact="moderate",
            )
            return SimpleNamespace(manifest=incompatible)

    proposal = planner(provider=DriftingProvider()).propose("source")
    assert proposal.plan is None
    assert proposal.plan_id is None
    assert proposal.blocked
    assert all(
        entry["reason"] == "provider_or_scope_blocked"
        for entry in proposal.blocked
    )


def test_e4_followup_planner_rejects_missing_or_wrong_resolver_contract():
    class MissingIdentityProvider(Provider):
        def resolve_task(self, task, *, require_installed=False):
            return SimpleNamespace()

    proposal = planner(provider=MissingIdentityProvider()).propose("source")
    assert proposal.plan is None
    assert proposal.blocked
    assert all(
        entry["error_type"] == "AttributeError"
        for entry in proposal.blocked
    )


@pytest.mark.parametrize("aggregate_field", [
    "all_evidence_recorded", "all_evidence_integrity_verified",
])
@pytest.mark.parametrize("aggregate_value", [False, None])
def test_e4_aggregate_evidence_must_be_complete_before_followup(
    aggregate_field, aggregate_value,
):
    """Verified individual rows must not bypass an incomplete evidence view."""
    class IncompleteStore(Store):
        def get_workflow_evidence(self, plan_id, *, limit):
            evidence = super().get_workflow_evidence(plan_id, limit=limit)
            if aggregate_value is None:
                evidence.pop(aggregate_field)
            else:
                evidence[aggregate_field] = aggregate_value
            return evidence

    provider = Provider()
    result = planner(store=IncompleteStore(), provider=provider).propose("source")
    assert result.plan is None
    assert result.plan_id is None
    assert result.blocked == ({
        "source_task": None, "reason": "source_evidence_incomplete",
    },)
    assert provider.called == 0
    assert result.to_dict()["execution_started"] is False
    assert result.to_dict()["approval_granted"] is False


@pytest.mark.parametrize(("field", "value"), [
    ("plan_id", "another-plan"),
    ("mission_id", "another-mission"),
    ("plan_digest", "another-digest"),
    ("plan_id", None),
    ("mission_id", None),
    ("plan_digest", None),
])
def test_e4_followup_rejects_mismatched_evidence_envelope(field, value):
    class MismatchedStore(Store):
        def get_workflow_evidence(self, plan_id, *, limit):
            evidence = super().get_workflow_evidence(plan_id, limit=limit)
            evidence[field] = value
            return evidence

    provider = Provider()
    result = planner(store=MismatchedStore(), provider=provider).propose("source")
    assert result.plan is None
    assert result.plan_id is None
    assert result.blocked[0]["reason"] == "source_evidence_incomplete"
    assert provider.called == 0


@pytest.mark.parametrize("legacy_shape", [[], None, "invalid"])
def test_e4_followup_rejects_unsealed_legacy_evidence_shape(legacy_shape):
    class LegacyStore(Store):
        def get_workflow_evidence(self, plan_id, *, limit):
            return legacy_shape

    provider = Provider()
    result = planner(store=LegacyStore(), provider=provider).propose("source")
    assert result.plan is None
    assert result.plan_id is None
    assert result.blocked[0]["reason"] == "source_evidence_incomplete"
    assert provider.called == 0


@pytest.mark.parametrize("attempts", [None, {}, "invalid", [None], [42],
                                      [{"task_key": "invalid"}, None]])
def test_e4_rejects_malformed_attempt_collection_before_provider_resolution(attempts):
    class MalformedStore(Store):
        def get_workflow_evidence(self, plan_id, *, limit):
            evidence = super().get_workflow_evidence(plan_id, limit=limit)
            evidence["attempts"] = attempts
            return evidence

    provider = Provider()
    result = planner(store=MalformedStore(), provider=provider).propose("source")
    assert result.plan is None
    assert result.plan_id is None
    assert result.blocked == ({"source_task": None, "reason": "evidence_unavailable"},)
    assert provider.called == 0
    assert result.to_dict()["execution_started"] is False
    assert result.to_dict()["approval_granted"] is False
