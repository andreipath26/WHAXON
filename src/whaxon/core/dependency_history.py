"""Local, bounded dependency-readiness history and drift snapshots."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HISTORY_SCHEMA_VERSION = 1
MAX_SNAPSHOTS = 100
_DEFAULT_LIMIT = 20
_LOCK = threading.RLock()


def _history_path(data_dir: Path) -> Path:
    root = Path(data_dir).expanduser().resolve()
    state_dir = root / ".whaxon"
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved = state_dir.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("dependency history path escapes the WHAXON data directory")
    if state_dir.is_symlink():
        raise ValueError("dependency history directory must not be a symlink")
    path = resolved / "dependency-readiness.json"
    if path.is_symlink():
        raise ValueError("dependency readiness history file must not be a symlink")
    return path


def _path_fingerprint(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _snapshot(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("schema_version") != 1 or not isinstance(report.get("dependencies"), list):
        raise ValueError("unsupported dependency report schema")
    dependencies = []
    for item in report["dependencies"]:
        dependencies.append({
            "id": item["id"],
            "status": item["status"],
            "version": item.get("detected_version"),
            "path_fingerprint": _path_fingerprint(item.get("detected_path")),
            "required": bool(item.get("required")),
            "capabilities": list(item.get("capabilities") or []),
        })
    dependencies.sort(key=lambda item: item["id"])
    environment = report.get("environment") or {}
    fingerprint_data = {
        "environment": {
            "os": environment.get("os"),
            "os_release": environment.get("os_release"),
            "architecture": environment.get("architecture"),
            "python": environment.get("python"),
            "python_executable_fingerprint": _path_fingerprint(environment.get("python_executable")),
        },
        "dependencies": dependencies,
    }
    fingerprint = hashlib.sha256(
        json.dumps(fingerprint_data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "recorded_at": datetime.now(UTC).isoformat(),
        "fingerprint": fingerprint,
        "overall_status": report.get("overall_status", "UNKNOWN"),
        "summary": report.get("summary", {}),
        "environment": fingerprint_data["environment"],
        "dependencies": dependencies,
    }


def read_snapshots(data_dir: Path, limit: int = _DEFAULT_LIMIT) -> list[dict[str, Any]]:
    if not 1 <= limit <= MAX_SNAPSHOTS:
        raise ValueError(f"limit must be between 1 and {MAX_SNAPSHOTS}")
    path = _history_path(data_dir)
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("dependency readiness history is unreadable") from exc
    if (
        not isinstance(raw, dict)
        or raw.get("schema_version") != HISTORY_SCHEMA_VERSION
        or not isinstance(raw.get("snapshots"), list)
        or len(raw["snapshots"]) > MAX_SNAPSHOTS
        or any(
            not isinstance(item, dict)
            or not isinstance(item.get("fingerprint"), str)
            or not isinstance(item.get("dependencies"), list)
            or not isinstance(item.get("environment"), dict)
            for item in raw["snapshots"]
        )
    ):
        raise RuntimeError("dependency readiness history has an unsupported schema")
    return raw["snapshots"][-limit:]


def record_snapshot(report: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    """Persist one bounded, redacted readiness snapshot using atomic replacement."""
    snapshot = _snapshot(report)
    path = _history_path(data_dir)
    with _LOCK:
        if path.exists():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if (
                    not isinstance(raw, dict)
                    or raw.get("schema_version") != HISTORY_SCHEMA_VERSION
                    or not isinstance(raw.get("snapshots"), list)
                    or len(raw["snapshots"]) > MAX_SNAPSHOTS
                    or any(
                        not isinstance(item, dict)
                        or not isinstance(item.get("fingerprint"), str)
                        or not isinstance(item.get("dependencies"), list)
                        or not isinstance(item.get("environment"), dict)
                        for item in raw["snapshots"]
                    )
                ):
                    raise RuntimeError("dependency readiness history has an unsupported schema")
                snapshots = raw["snapshots"]
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError("dependency readiness history is unreadable") from exc
        else:
            snapshots = []
        snapshots.append(snapshot)
        payload = {
            "schema_version": HISTORY_SCHEMA_VERSION,
            "snapshots": snapshots[-MAX_SNAPSHOTS:],
        }
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".dependency-readiness-", suffix=".tmp", dir=path.parent
        )
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            else:
                os.chmod(temporary_name, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, path)
        except Exception:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise
    return snapshot


def compare_with_latest(report: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    current = _snapshot(report)
    previous_items = read_snapshots(data_dir, limit=1)
    if not previous_items:
        return {
            "baseline_available": False,
            "changed": False,
            "changes": [],
            "current_fingerprint": current["fingerprint"],
        }
    previous = previous_items[0]
    before = {item["id"]: item for item in previous["dependencies"]}
    after = {item["id"]: item for item in current["dependencies"]}
    changes = []
    for dependency_id in sorted(set(before) | set(after)):
        old = before.get(dependency_id)
        new = after.get(dependency_id)
        if old != new:
            changes.append({
                "dependency_id": dependency_id,
                "before": old,
                "after": new,
            })
    return {
        "baseline_available": True,
        "changed": bool(changes) or previous["environment"] != current["environment"],
        "changes": changes,
        "environment_changed": previous["environment"] != current["environment"],
        "previous_fingerprint": previous["fingerprint"],
        "current_fingerprint": current["fingerprint"],
    }
