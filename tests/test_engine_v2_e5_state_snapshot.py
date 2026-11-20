"""E5 cold state recovery includes evidence/config and rejects tampering."""
import shutil
import sqlite3
import time
from pathlib import Path

import pytest

from whaxon.core import Core
from whaxon.core.state_snapshot import (
    create_offline_snapshot,
    restore_offline_snapshot,
    verify_offline_snapshot,
)
from whaxon.core.workflow import WorkflowPlan, WorkflowTask


def _make_state(root: Path):
    core = Core(root)
    core.create_mission("cold-restore", "restoration test")
    core.save_workflow_plan(
        "cold-plan",
        WorkflowPlan("cold-restore", (
            WorkflowTask("task", "unsupported.fixture", "192.0.2.10"),
        )),
    )
    request = core.enqueue_workflow_run("cold-plan")
    (root / "scope.json").write_text('{"enabled":false,"in_scope":[]}', encoding="utf-8")
    evidence = root / "evidence" / "proof.bin"
    evidence.parent.mkdir()
    evidence.write_bytes(b"controlled-e5-evidence\x00\xff")
    return request


def test_e5_offline_snapshot_restores_queue_scope_and_evidence(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    request = _make_state(original)
    backup = tmp_path / "snapshot"
    report = create_offline_snapshot(original, backup)
    assert report["files_verified"] is True
    assert report["external_anchor_verified"] is False
    assert (backup / "scope.json").read_bytes() == (original / "scope.json").read_bytes()
    assert (backup / "evidence" / "proof.bin").read_bytes() == (
        original / "evidence" / "proof.bin"
    ).read_bytes()
    restored_dir = tmp_path / "restored"
    assert restore_offline_snapshot(backup, restored_dir)["files_verified"]
    restored = Core(restored_dir)
    assert restored.workflow_run_request(request["id"])["status"] == "queued"
    assert restored.store.verify_workflow_plan_integrity("cold-plan")["digest"] == (
        request["plan_digest"]
    )
    assert (restored_dir / "scope.json").read_bytes() == (original / "scope.json").read_bytes()
    assert (restored_dir / "evidence" / "proof.bin").read_bytes() == b"controlled-e5-evidence\x00\xff"


def test_e5_snapshot_integrity_rejects_changed_evidence_and_refuses_restore(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    _make_state(original)
    backup = tmp_path / "snapshot"
    create_offline_snapshot(original, backup)
    (backup / "evidence" / "proof.bin").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_offline_snapshot(backup)
    with pytest.raises(ValueError, match="checksum mismatch"):
        restore_offline_snapshot(backup, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_e5_snapshot_rejects_symlink_and_never_overwrites_state(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    _make_state(original)
    outside = tmp_path / "outside-secret"
    outside.write_text("secret", encoding="utf-8")
    (original / "external").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        create_offline_snapshot(original, tmp_path / "snapshot")
    (original / "external").unlink()
    create_offline_snapshot(original, tmp_path / "snapshot")
    with pytest.raises(ValueError, match="destination must be new"):
        create_offline_snapshot(original, tmp_path / "snapshot")
    with pytest.raises(ValueError, match="restore destination must be new"):
        restore_offline_snapshot(tmp_path / "snapshot", original)


def test_e5_snapshot_refuses_destination_hidden_under_symlink_parent(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    _make_state(original)
    (tmp_path / "alias").symlink_to(original, target_is_directory=True)
    with pytest.raises(ValueError, match="outside source state"):
        create_offline_snapshot(original, tmp_path / "alias" / "hidden-backup")
    assert not (original / "hidden-backup").exists()


def test_e5_externally_retained_manifest_hash_detects_manifest_replacement(tmp_path):
    root = tmp_path / "original"
    root.mkdir()
    _make_state(root)
    snapshot = tmp_path / "snapshot"
    created = create_offline_snapshot(root, snapshot)
    expected = created["manifest_sha256"]
    verified = verify_offline_snapshot(
        snapshot, expected_manifest_sha256=expected,
    )
    assert verified["external_anchor_verified"] is True
    assert restore_offline_snapshot(
        snapshot, tmp_path / "restored",
        expected_manifest_sha256=expected,
    )["external_anchor_verified"] is True
    manifest = snapshot / "e5-snapshot-manifest.json"
    modified = manifest.read_text(encoding="utf-8").replace(
        '"external_anchor_verified": false',
        '"external_anchor_verified": true',
    )
    assert modified != manifest.read_text(encoding="utf-8")
    manifest.write_text(modified, encoding="utf-8")
    with pytest.raises(ValueError, match="independently retained manifest digest mismatch"):
        verify_offline_snapshot(snapshot, expected_manifest_sha256=expected)


def test_e5_snapshot_rejects_broken_database(tmp_path):
    root = tmp_path / "invalid"
    root.mkdir()
    (root / "whaxon.db").write_bytes(b"not a sqlite database")
    with pytest.raises(sqlite3.DatabaseError):
        create_offline_snapshot(root, tmp_path / "snapshot")
    assert not (tmp_path / "snapshot").exists()


def test_e5_full_state_restore_fences_inflight_worker_without_automatic_replay(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    request = _make_state(original)
    source = Core(original)
    claimed = source.workflow_requests.claim("worker-before-crash")
    assert claimed is not None and claimed["id"] == request["id"]
    conn = source.store._conn()
    try:
        conn.execute(
            "UPDATE workflow_run_requests SET heartbeat_at=? WHERE id=?",
            (time.time() - 500, request["id"]),
        )
    finally:
        conn.close()
    backup = tmp_path / "snapshot"
    created = create_offline_snapshot(original, backup)
    recovered_dir = tmp_path / "recovered"
    restore_offline_snapshot(
        backup, recovered_dir,
        expected_manifest_sha256=created["manifest_sha256"],
    )
    recovered = Core(recovered_dir)
    assert recovered.workflow_run_request(request["id"])["status"] == "running"
    assert recovered.workflow_requests.reconcile_stale(older_than_s=60) == 1
    state = recovered.workflow_run_request(request["id"])
    assert state["status"] == "uncertain"
    assert "lease_token" not in state
    assert recovered.workflow_requests.claim("worker-after-restore") is None
    assert not recovered.workflow_requests.finish(
        request["id"], claimed["lease_token"], status="completed",
    )
    assert (recovered_dir / "scope.json").read_bytes() == (
        original / "scope.json"
    ).read_bytes()
    assert (recovered_dir / "evidence" / "proof.bin").read_bytes() == (
        original / "evidence" / "proof.bin"
    ).read_bytes()


def test_e5_snapshot_rejects_inventory_addition_or_missing_file(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    _make_state(original)
    first = tmp_path / "first"
    create_offline_snapshot(original, first)
    (first / "unexpected-artifact").write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="inventory mismatch"):
        verify_offline_snapshot(first)
    second = tmp_path / "second"
    create_offline_snapshot(original, second)
    (second / "evidence" / "proof.bin").unlink()
    with pytest.raises(ValueError, match="inventory mismatch"):
        restore_offline_snapshot(second, tmp_path / "should-not-exist")
    assert not (tmp_path / "should-not-exist").exists()


def test_e5_restore_detects_snapshot_file_changed_after_initial_verification(tmp_path, monkeypatch):
    original = tmp_path / "original"
    original.mkdir()
    _make_state(original)
    snapshot = tmp_path / "snapshot"
    create_offline_snapshot(original, snapshot)
    destination = tmp_path / "restored"

    copyfile = shutil.copyfile

    def tamper_while_copying(source, target):
        source = Path(source)
        if source.name == "proof.bin":
            source.write_bytes(b"changed after the initial verification")
        return copyfile(source, target)

    monkeypatch.setattr("whaxon.core.state_snapshot.shutil.copyfile", tamper_while_copying)
    with pytest.raises(ValueError, match=r"snapshot checksum mismatch: evidence/proof\.bin"):
        restore_offline_snapshot(snapshot, destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".whaxon-e5-restore-*"))


def test_e5_snapshot_copy_failure_cleans_temporary_stage(tmp_path, monkeypatch):
    original = tmp_path / "original"
    original.mkdir()
    _make_state(original)
    destination = tmp_path / "snapshot"

    copyfile = shutil.copyfile
    calls = 0

    def fail_during_copy(source, target):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated snapshot copy interruption")
        return copyfile(source, target)

    monkeypatch.setattr("whaxon.core.state_snapshot.shutil.copyfile", fail_during_copy)
    with pytest.raises(OSError, match="simulated snapshot copy interruption"):
        create_offline_snapshot(original, destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".whaxon-e5-*"))


def test_e5_restore_copy_failure_cleans_temporary_stage(tmp_path, monkeypatch):
    original = tmp_path / "original"
    original.mkdir()
    _make_state(original)
    snapshot = tmp_path / "snapshot"
    create_offline_snapshot(original, snapshot)
    destination = tmp_path / "restored"

    copyfile = shutil.copyfile
    calls = 0

    def fail_during_copy(source, target):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated restore copy interruption")
        return copyfile(source, target)

    monkeypatch.setattr("whaxon.core.state_snapshot.shutil.copyfile", fail_during_copy)
    with pytest.raises(OSError, match="simulated restore copy interruption"):
        restore_offline_snapshot(snapshot, destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".whaxon-e5-restore-*"))
