from __future__ import annotations

import pytest

import whaxon.core.installer as installer
import whaxon.core.remediation as remediation


def _plan(dependency_ids, plan_id="plan-approved"):
    return {
        "plan_id": plan_id,
        "unknown_dependency_ids": [],
        "actions": [
            {
                "dependency_id": dependency_id,
                "options": [{
                    "kind": "python-package",
                    "automated_execution_supported": True,
                }],
            }
            for dependency_id in dependency_ids
        ],
    }


def test_batch_rejects_stale_or_unapproved_plan(monkeypatch):
    monkeypatch.setattr(
        remediation, "build_remediation_plan",
        lambda **kwargs: _plan(kwargs["dependency_ids"]),
    )
    with pytest.raises(ValueError, match="does not match"):
        installer.apply_approved_dependency_batch(["alpha"], "plan-stale")


def test_batch_rejects_manual_or_external_dependencies(monkeypatch):
    def plan(**kwargs):
        result = _plan(kwargs["dependency_ids"])
        result["actions"][0]["options"][0]["kind"] = "manual"
        return result

    monkeypatch.setattr(remediation, "build_remediation_plan", plan)
    with pytest.raises(ValueError, match="without a trusted automated"):
        installer.apply_approved_dependency_batch(["nmap"], "plan-approved")


def test_batch_installs_sequentially_and_stops_after_failure(monkeypatch):
    def plan(**kwargs):
        return _plan(kwargs["dependency_ids"])

    calls = []
    def apply(dependency_id, plan_id, **kwargs):
        calls.append(dependency_id)
        return {"status": "VERIFIED" if dependency_id == "alpha" else "INSTALL_FAILED"}

    monkeypatch.setattr(remediation, "build_remediation_plan", plan)
    monkeypatch.setattr(installer, "apply_approved_dependency_plan", apply)
    result = installer.apply_approved_dependency_batch(
        ["alpha", "beta", "gamma"], "plan-approved"
    )
    assert result["status"] == "PARTIAL_FAILURE"
    assert calls == ["alpha", "beta"]
    assert result["remaining"] == ["gamma"]


def test_batch_reports_verified_only_when_every_action_verifies(monkeypatch):
    monkeypatch.setattr(
        remediation, "build_remediation_plan",
        lambda **kwargs: _plan(kwargs["dependency_ids"]),
    )
    calls = []
    monkeypatch.setattr(
        installer, "apply_approved_dependency_plan",
        lambda dependency_id, *_args, **_kwargs: (
            calls.append(dependency_id) or {"status": "VERIFIED"}
        ),
    )
    result = installer.apply_approved_dependency_batch(
        ["alpha", "beta"], "plan-approved"
    )
    assert result["status"] == "VERIFIED"
    assert calls == ["alpha", "beta"]
    assert result["remaining"] == []


def test_batch_preserves_cancellation_status(monkeypatch):
    monkeypatch.setattr(
        remediation, "build_remediation_plan",
        lambda **kwargs: _plan(kwargs["dependency_ids"]),
    )
    monkeypatch.setattr(
        installer, "apply_approved_dependency_plan",
        lambda *_args, **_kwargs: {"status": "CANCELLED"},
    )
    result = installer.apply_approved_dependency_batch(
        ["alpha", "beta"], "plan-approved"
    )
    assert result["status"] == "CANCELLED"
    assert result["remaining"] == ["beta"]
