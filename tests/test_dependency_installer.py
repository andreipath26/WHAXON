from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from whaxon.core.installer import apply_approved_dependency_batch, apply_approved_dependency_plan
from whaxon.core.remediation import build_remediation_plan


def test_install_requires_current_explicit_plan_approval():
    plan = build_remediation_plan(dependency_ids=["textual"])
    if not plan["actions"]:
        pytest.skip("Textual is already ready in this test environment")
    with pytest.raises(ValueError, match="Approval does not match"):
        apply_approved_dependency_plan("textual", "wrong-plan-id")


def test_install_refuses_external_tools():
    plan = build_remediation_plan(dependency_ids=["nmap"])
    if not plan["actions"]:
        pytest.skip("Nmap is already detected")
    with pytest.raises(ValueError, match="No supported automated installation"):
        apply_approved_dependency_plan("nmap", plan["plan_id"])


def test_audit_redaction():
    from whaxon.core.installer import _redact

    value = _redact("api_key=abc123 Bearer secretvalue")
    assert "abc123" not in value
    assert "secretvalue" not in value
    json.dumps({"output": value})


def test_install_refuses_non_virtual_environment(monkeypatch):
    from whaxon.core.installer import apply_approved_dependency_plan

    # Bind approval to the same non-venv environment being tested.
    monkeypatch.setattr(sys, "prefix", "/usr")
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    plan = build_remediation_plan()
    candidates = [action for action in plan["actions"]
                  if action["options"][0]["kind"] == "python-package"]
    if not candidates:
        pytest.skip("No missing Python package to install")
    dependency_id = candidates[0]["dependency_id"]
    focused = build_remediation_plan(dependency_ids=[dependency_id])
    with pytest.raises(ValueError, match="virtual environment"):
        apply_approved_dependency_plan(dependency_id, focused["plan_id"])


def test_approved_install_uses_fixed_pypi_wheel_command(monkeypatch, tmp_path):
    import whaxon.core.installer as installer

    monkeypatch.setattr(sys, "prefix", "/tmp/whaxon-test-venv")
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    plan = build_remediation_plan()
    candidates = [action for action in plan["actions"]
                  if action["options"][0]["kind"] == "python-package"]
    if not candidates:
        pytest.skip("No missing Python package to install")
    dependency_id = candidates[0]["dependency_id"]
    focused = build_remediation_plan(dependency_ids=[dependency_id])
    calls = []

    class FakeProcess:
        returncode = 0

        def poll(self):
            return self.returncode

        def communicate(self, timeout=None):
            return "installed", ""

    installed = {"value": False}
    original_version = installer.importlib.metadata.version

    def fake_popen(argv, **kwargs):
        calls.append((argv, kwargs))
        installed["value"] = True
        return FakeProcess()

    def fake_version(name):
        return "99.0" if installed["value"] else original_version(name)

    monkeypatch.setattr(installer.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(installer.importlib.metadata, "version", fake_version)
    monkeypatch.setattr(installer.importlib, "import_module", lambda _name: object())
    monkeypatch.setattr(installer, "_audit_path", lambda: tmp_path / "audit.jsonl")

    result = installer.apply_approved_dependency_plan(dependency_id, focused["plan_id"])
    assert result["status"] == "VERIFIED"
    argv, kwargs = calls[0]
    assert kwargs["shell"] is False
    assert "--only-binary=:all:" in argv
    assert argv[argv.index("--index-url") + 1] == "https://pypi.org/simple"
    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [record["event_type"] for record in records] == ["PLAN_CREATED", "APPROVAL_ACCEPTED", "ACTION_STARTED", "ACTION_FINISHED"]


def test_timeout_is_audited_and_returns_recovery(monkeypatch, tmp_path):
    import whaxon.core.installer as installer

    monkeypatch.setattr(sys, "prefix", "/tmp/whaxon-test-venv")
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    plan = build_remediation_plan()
    candidates = [action for action in plan["actions"]
                  if action["options"][0]["kind"] == "python-package"]
    if not candidates:
        pytest.skip("No missing Python package to install")
    dependency_id = candidates[0]["dependency_id"]
    focused = build_remediation_plan(dependency_ids=[dependency_id])

    class TimeoutProcess:
        returncode = None

        def poll(self):
            return None if self.returncode is None else self.returncode

        def communicate(self, timeout=None):
            return "", ""

        def terminate(self):
            self.returncode = -15

        def kill(self):
            pass

    monkeypatch.setattr(installer, "INSTALL_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(installer.subprocess, "Popen", lambda *_args, **_kwargs: TimeoutProcess())
    monkeypatch.setattr(installer, "_audit_path", lambda: tmp_path / "audit.jsonl")
    result = installer.apply_approved_dependency_plan(dependency_id, focused["plan_id"])
    assert result["status"] == "TIMED_OUT"
    assert "recreate the virtual environment" in result["recovery"]
    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [record["event_type"] for record in records] == ["PLAN_CREATED", "APPROVAL_ACCEPTED", "ACTION_STARTED", "ACTION_FINISHED"]


def test_final_audit_failure_does_not_claim_install_was_not_started(monkeypatch):
    import whaxon.core.installer as installer

    monkeypatch.setattr(sys, "prefix", "/tmp/whaxon-test-venv")
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    plan = build_remediation_plan()
    candidates = [action for action in plan["actions"]
                  if action["options"][0]["kind"] == "python-package"]
    if not candidates:
        pytest.skip("No missing Python package to install")
    dependency_id = candidates[0]["dependency_id"]
    focused = build_remediation_plan(dependency_ids=[dependency_id])
    writes = {"count": 0}

    def audit(_record):
        writes["count"] += 1
        if writes["count"] == 4:
            raise OSError("disk full")

    monkeypatch.setattr(installer, "_append_audit", audit)
    installed = {"value": False}
    original_version = installer.importlib.metadata.version

    def fake_popen(*_args, **_kwargs):
        installed["value"] = True
        return type(
            "FakeProcess",
            (),
            {"returncode": 0, "poll": lambda self: 0, "communicate": lambda self, timeout=None: ("", "")},
        )()

    def fake_version(name):
        return "99.0" if installed["value"] else original_version(name)

    monkeypatch.setattr(installer.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(installer.importlib.metadata, "version", fake_version)
    monkeypatch.setattr(installer.importlib, "import_module", lambda _name: object())
    result = installer.apply_approved_dependency_plan(dependency_id, focused["plan_id"])
    assert result["status"] == "AUDIT_FAILED"
    assert result["original_status"] == "VERIFIED"
    assert "operation ran" in result["recovery"]


def test_cancel_before_start_never_spawns_package_manager(monkeypatch, tmp_path):
    import whaxon.core.installer as installer

    monkeypatch.setattr(sys, "prefix", "/tmp/whaxon-test-venv")
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    plan = build_remediation_plan()
    candidates = [action for action in plan["actions"]
                  if action["options"][0]["kind"] == "python-package"]
    if not candidates:
        pytest.skip("No missing Python package to install")
    dependency_id = candidates[0]["dependency_id"]
    focused = build_remediation_plan(dependency_ids=[dependency_id])
    monkeypatch.setattr(
        installer.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("Popen must not be called"),
    )
    monkeypatch.setattr(installer, "_audit_path", lambda: tmp_path / "audit.jsonl")
    result = installer.apply_approved_dependency_plan(
        dependency_id,
        focused["plan_id"],
        cancel_requested=lambda: True,
    )
    assert result["status"] == "CANCELLED"
    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [record["event_type"] for record in records] == ["PLAN_CREATED", "APPROVAL_ACCEPTED", "ACTION_STARTED", "ACTION_FINISHED"]


def test_installer_enforces_manifest_automatic_install_policy(monkeypatch):
    import whaxon.core.installer as installer

    monkeypatch.setattr(sys, "prefix", "/tmp/whaxon-test-venv")
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    monkeypatch.setattr(
        installer,
        "build_remediation_plan",
        lambda **kwargs: {
            "plan_id": "plan-0123456789abcdef",
            "unknown_dependency_ids": [],
            "actions": [{
                "dependency_id": "textual",
                "options": [{"kind": "python-package"}],
            }],
        },
    )
    original = installer.load_dependency_manifest
    monkeypatch.setattr(
        installer,
        "load_dependency_manifest",
        lambda: {
            **original(),
            "policy": {
                "automatic_installation_enabled": False,
                "automatic_installation_kinds": [],
            },
        },
    )
    with pytest.raises(ValueError, match="disabled by the dependency policy"):
        installer.apply_approved_dependency_plan(
            "textual", "plan-0123456789abcdef"
        )


def test_audit_refuses_symlinked_whaxon_root(tmp_path, monkeypatch):
    import whaxon.core.installer as installer

    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".whaxon").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(installer.Path, "home", classmethod(lambda cls: tmp_path))
    with pytest.raises(OSError, match="audit root must not be a symlink"):
        installer._append_audit({"status": "STARTED"})
    assert list(outside.iterdir()) == []


def test_audit_refuses_symlinked_log_file(tmp_path, monkeypatch):
    import whaxon.core.installer as installer

    root = tmp_path / ".whaxon"
    audit = root / "audit"
    audit.mkdir(parents=True)
    outside = tmp_path / "outside.jsonl"
    outside.write_text("untouched")
    (audit / "dependency-install.jsonl").symlink_to(outside)
    monkeypatch.setattr(installer.Path, "home", classmethod(lambda cls: tmp_path))
    with pytest.raises(OSError, match="audit log must not be a symlink"):
        installer._append_audit({"status": "STARTED"})
    assert outside.read_text() == "untouched"


def test_dependency_audit_hash_chain_detects_tampering(tmp_path, monkeypatch):
    import whaxon.core.installer as installer

    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(installer, "_audit_path", lambda: path)
    installer._append_audit({"event_type": "PLAN_CREATED", "plan_id": "plan-one"})
    installer._append_audit({"event_type": "APPROVAL_ACCEPTED", "plan_id": "plan-one"})
    verified = installer.verify_dependency_audit(path)
    assert verified["valid"] is True
    assert verified["events_checked"] == 2

    records = [json.loads(line) for line in path.read_text().splitlines()]
    records[0]["plan_id"] = "plan-tampered"
    path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in records))
    verified = installer.verify_dependency_audit(path)
    assert verified["valid"] is False
    assert verified["reason"] == "hash_mismatch"


def test_dependency_audit_chain_serializes_concurrent_writers(tmp_path, monkeypatch):
    import whaxon.core.installer as installer

    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(installer, "_audit_path", lambda: path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: installer._append_audit({"event_type": "TEST", "index": i}), range(40)))
    result = installer.verify_dependency_audit(path)
    assert result["valid"] is True
    assert result["events_checked"] == 40


def test_profile_batch_audits_parent_approval_and_terminal_result(monkeypatch):
    import whaxon.core.installer as installer
    import whaxon.core.remediation as remediation

    monkeypatch.setattr(
        remediation,
        "build_remediation_plan",
        lambda **kwargs: {
            "plan_id": "plan-0123456789abcdef",
            "unknown_dependency_ids": [],
            "actions": [{
                "dependency_id": "textual",
                "options": [{"kind": "python-package", "automated_execution_supported": True}],
            }],
        },
    )
    events = []
    monkeypatch.setattr(installer, "_append_audit", lambda record: events.append(record))
    monkeypatch.setattr(
        installer,
        "apply_approved_dependency_plan",
        lambda dependency_id, plan_id, **kwargs: {"status": "VERIFIED", "dependency_id": dependency_id},
    )
    result = apply_approved_dependency_batch(
        ["textual"], "plan-0123456789abcdef"
    )
    assert result["status"] == "VERIFIED"
    assert [item["event_type"] for item in events] == [
        "PROFILE_BATCH_APPROVAL_ACCEPTED",
        "PROFILE_BATCH_FINISHED",
    ]
    assert events[0]["plan_id"] == "plan-0123456789abcdef"
    assert events[0]["dependency_ids"] == ["textual"]


def test_profile_batch_audit_failure_never_claims_verified(monkeypatch):
    import whaxon.core.installer as installer
    import whaxon.core.remediation as remediation

    monkeypatch.setattr(
        remediation,
        "build_remediation_plan",
        lambda **kwargs: {
            "plan_id": "plan-0123456789abcdef",
            "unknown_dependency_ids": [],
            "actions": [{
                "dependency_id": "textual",
                "options": [{"kind": "python-package", "automated_execution_supported": True}],
            }],
        },
    )
    calls = {"count": 0}

    def audit(_record):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("disk full")

    monkeypatch.setattr(installer, "_append_audit", audit)
    monkeypatch.setattr(
        installer,
        "apply_approved_dependency_plan",
        lambda dependency_id, plan_id, **kwargs: {"status": "VERIFIED", "dependency_id": dependency_id},
    )
    result = apply_approved_dependency_batch(
        ["textual"], "plan-0123456789abcdef"
    )
    assert result["status"] == "AUDIT_FAILED"
    assert result["original_status"] == "VERIFIED"
    assert "audit event could not be persisted" in result["recovery"]
