from __future__ import annotations

import json

import pytest

from whaxon.core.dependency_history import (
    compare_with_latest,
    read_snapshots,
    record_snapshot,
)


def _report(status="READY", version="1.0"):
    return {
        "schema_version": 1,
        "overall_status": status,
        "summary": {"total": 1, "ready": 1 if status == "READY" else 0},
        "environment": {
            "os": "Linux",
            "os_release": "test",
            "architecture": "x86_64",
            "python": "3.12.0",
            "python_executable": "/venv/bin/python",
            "cwd": "/private/user/path",
        },
        "dependencies": [{
            "id": "demo",
            "status": status,
            "detected_version": version,
            "detected_path": None,
            "required": True,
            "capabilities": ["core"],
        }],
    }


def test_snapshot_round_trip_and_private_permissions(tmp_path):
    snapshot = record_snapshot(_report(), tmp_path)
    assert snapshot["fingerprint"]
    path = tmp_path / ".whaxon" / "dependency-readiness.json"
    payload = json.loads(path.read_text())
    assert payload["schema_version"] == 1
    assert len(read_snapshots(tmp_path)) == 1
    assert "cwd" not in path.read_text()
    assert "/private/user/path" not in path.read_text()
    assert "/venv/bin/python" not in path.read_text()
    assert path.stat().st_mode & 0o077 == 0


def test_drift_detects_status_and_version_changes(tmp_path):
    record_snapshot(_report(), tmp_path)
    drift = compare_with_latest(_report(status="DEGRADED", version="0.9"), tmp_path)
    assert drift["baseline_available"] is True
    assert drift["changed"] is True
    assert drift["changes"][0]["dependency_id"] == "demo"


def test_drift_without_baseline_is_explicit(tmp_path):
    drift = compare_with_latest(_report(), tmp_path)
    assert drift["baseline_available"] is False
    assert drift["changed"] is False


def test_history_limit_is_bounded(tmp_path):
    with pytest.raises(ValueError, match="limit"):
        read_snapshots(tmp_path, limit=101)


def test_history_rejects_malformed_json_shape(tmp_path):
    state_dir = tmp_path / ".whaxon"
    state_dir.mkdir()
    (state_dir / "dependency-readiness.json").write_text("[]")
    with pytest.raises(RuntimeError, match="unsupported schema"):
        read_snapshots(tmp_path)


def test_history_rejects_symlinked_state_file(tmp_path):
    state_dir = tmp_path / ".whaxon"
    state_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"schema_version": 1, "snapshots": []}')
    (state_dir / "dependency-readiness.json").symlink_to(outside)
    with pytest.raises(ValueError, match="must not be a symlink"):
        read_snapshots(tmp_path)
