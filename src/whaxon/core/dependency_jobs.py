"""Background installation operations with durable polling and cancellation markers."""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from whaxon.core.dependencies import load_dependency_manifest
from whaxon.core.installer import apply_approved_dependency_plan
from whaxon.core.remediation import build_remediation_plan

_OPERATION_ID = re.compile(r"^[0-9a-f]{32}$")
_DEPENDENCY_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
_LOCK = threading.RLock()
_ACTIVE_THREADS: dict[str, threading.Thread] = {}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _operations_dir(data_dir: Path) -> Path:
    root = Path(data_dir).expanduser().resolve()
    state_dir = root / ".whaxon"
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_dir.is_symlink() or not state_dir.resolve().is_relative_to(root):
        raise ValueError("dependency operation state directory is unsafe")
    operations = state_dir / "dependency-operations"
    operations.mkdir(mode=0o700, exist_ok=True)
    if operations.is_symlink() or not operations.resolve().is_relative_to(root):
        raise ValueError("dependency operation directory is unsafe")
    return operations.resolve()


def _operation_path(data_dir: Path, operation_id: str) -> Path:
    if not _OPERATION_ID.fullmatch(operation_id):
        raise ValueError("invalid dependency operation ID")
    path = _operations_dir(data_dir) / f"{operation_id}.json"
    if path.is_symlink():
        raise ValueError("dependency operation state file must not be a symlink")
    return path


def _write_state(path: Path, state: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".dependency-operation-", suffix=".tmp", dir=path.parent
    )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            os.chmod(temporary_name, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(state, stream, sort_keys=True, indent=2)
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


def get_install_operation(data_dir: Path, operation_id: str) -> dict[str, Any] | None:
    path = _operation_path(data_dir, operation_id)
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("dependency operation state is unreadable") from exc
    if not isinstance(state, dict):
        raise RuntimeError("dependency operation state is malformed or has an unsupported schema")
    if (
        state.get("schema_version") != 1
        or state.get("operation_id") != operation_id
        or not isinstance(state.get("status"), str)
        or not isinstance(state.get("updated_at"), str)
    ):
        raise RuntimeError("dependency operation state is malformed or has an unsupported schema")
    if state.get("status") in {"QUEUED", "INSTALLING", "VERIFYING"}:
        try:
            updated = datetime.fromisoformat(state["updated_at"])
            stale = (datetime.now(UTC) - updated).total_seconds() > 90
        except (KeyError, TypeError, ValueError):
            stale = True
        if stale:
            state.update({
                "status": "INTERRUPTED",
                "step": "INTERRUPTED",
                "message": "No worker heartbeat was received; run doctor to verify the environment before retrying.",
                "updated_at": _now(),
            })
            _write_state(path, state)
    return state


def _claim_dependency_lock(operations: Path, dependency_id: str, operation_id: str) -> Path:
    lock_path = operations / f"{dependency_id}.lock"
    if lock_path.exists():
        try:
            previous_id = lock_path.read_text(encoding="utf-8").strip()
            if not _OPERATION_ID.fullmatch(previous_id):
                raise ValueError("invalid operation ID in lock file")
            previous_path = operations / f"{previous_id}.json"
            previous = json.loads(previous_path.read_text(encoding="utf-8"))
            if (
                not isinstance(previous, dict)
                or previous.get("schema_version") != 1
                or not isinstance(previous.get("status"), str)
                or not isinstance(previous.get("updated_at"), str)
            ):
                raise ValueError("invalid operation state schema")
            updated = datetime.fromisoformat(previous["updated_at"])
            stale = (datetime.now(UTC) - updated).total_seconds() > 90
            terminal = previous.get("status") not in {"QUEUED", "INSTALLING", "VERIFYING"}
            if stale and not terminal:
                previous.update({
                    "status": "INTERRUPTED",
                    "step": "INTERRUPTED",
                    "message": "The worker stopped updating this operation; its package state must be re-checked.",
                    "updated_at": _now(),
                })
                _write_state(previous_path, previous)
            if terminal or stale:
                lock_path.unlink(missing_ok=True)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            # An unreadable lock is not safe to steal automatically.
            pass
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(
            f"An installation operation for {dependency_id} is already active."
        ) from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(operation_id)
    return lock_path


def start_install_operation(
    dependency_id: str,
    approved_plan_id: str,
    data_dir: Path,
) -> dict[str, Any]:
    """Validate approval synchronously, then run the allowlisted install in a worker."""
    if not _DEPENDENCY_ID.fullmatch(dependency_id):
        raise ValueError("invalid dependency ID")
    manifest = load_dependency_manifest()
    entry = next(
        (item for item in manifest["dependencies"] if item["id"] == dependency_id),
        None,
    )
    if not entry or entry.get("kind") != "python-package":
        raise ValueError("only manifest-listed Python packages can be installed automatically")
    policy = manifest.get("policy", {})
    if (
        policy.get("automatic_installation_enabled") is not True
        or "python-package" not in policy.get("automatic_installation_kinds", [])
    ):
        raise ValueError("automatic Python-package installation is disabled by the dependency policy")
    if sys.prefix == getattr(sys, "base_prefix", sys.prefix):
        raise ValueError("automatic installation requires an active virtual environment")
    plan = build_remediation_plan(dependency_ids=[dependency_id], data_dir=data_dir)
    if plan["plan_id"] != approved_plan_id:
        raise ValueError("approval does not match the current plan; regenerate and review it")
    action = next(
        (item for item in plan["actions"] if item["dependency_id"] == dependency_id),
        None,
    )
    if (
        not action
        or action["options"][0]["kind"] != "python-package"
        or action["options"][0].get("automated_execution_supported") is not True
    ):
        raise ValueError("dependency does not have an eligible automated installation plan")
    operation_id = uuid.uuid4().hex
    operations = _operations_dir(data_dir)
    lock_path = _claim_dependency_lock(operations, dependency_id, operation_id)
    state_path = operations / f"{operation_id}.json"
    state = {
        "schema_version": 1,
        "operation_id": operation_id,
        "dependency_id": dependency_id,
        "plan_id": approved_plan_id,
        "status": "QUEUED",
        "progress": 0,
        "step": "QUEUED",
        "message": "Approved installation queued.",
        "created_at": _now(),
        "updated_at": _now(),
        "cancel_requested": False,
        "worker_pid": os.getpid(),
    }
    try:
        _write_state(state_path, state)
    except Exception:
        lock_path.unlink(missing_ok=True)
        raise

    cancel_path = operations / f"{operation_id}.cancel"

    def update_progress(status: str, message: str) -> None:
        try:
            current = get_install_operation(data_dir, operation_id) or state
            current.update({
                "status": status,
                "step": status,
                "message": message,
                "progress": 35 if status == "INSTALLING" else 80 if status == "VERIFYING" else 100,
                "updated_at": _now(),
            })
            _write_state(state_path, current)
        except (OSError, RuntimeError, ValueError):
            # The installer continues its own audit trail; polling will report
            # unreadable state rather than falsely inventing a successful result.
            return

    def worker() -> None:
        try:
            update_progress("INSTALLING", "Starting the approved package operation.")
            result = apply_approved_dependency_plan(
                dependency_id,
                approved_plan_id,
                data_dir=data_dir,
                progress_callback=update_progress,
                cancel_requested=cancel_path.exists,
            )
            current = get_install_operation(data_dir, operation_id) or state
            current.update({
                "status": result["status"],
                "step": result["status"],
                "progress": 100,
                "message": result.get("verification") or result.get("recovery") or result["status"],
                "result": result,
                "updated_at": _now(),
            })
            _write_state(state_path, current)
        except Exception as exc:
            current = get_install_operation(data_dir, operation_id) or state
            current.update({
                "status": "FAILED",
                "step": "FAILED",
                "progress": 100,
                "message": f"Installation operation failed ({type(exc).__name__}).",
                "updated_at": _now(),
            })
            try:
                _write_state(state_path, current)
            except OSError:
                pass
        finally:
            cancel_path.unlink(missing_ok=True)
            lock_path.unlink(missing_ok=True)
            with _LOCK:
                _ACTIVE_THREADS.pop(operation_id, None)

    thread = threading.Thread(target=worker, name=f"whaxon-dependency-{operation_id[:8]}", daemon=True)
    with _LOCK:
        _ACTIVE_THREADS[operation_id] = thread
    try:
        thread.start()
    except Exception as exc:
        state.update({
            "status": "FAILED",
            "step": "FAILED",
            "progress": 100,
            "message": "Installation worker could not be started.",
            "updated_at": _now(),
        })
        try:
            _write_state(state_path, state)
        finally:
            lock_path.unlink(missing_ok=True)
            with _LOCK:
                _ACTIVE_THREADS.pop(operation_id, None)
        raise RuntimeError("dependency installation worker could not be started") from exc
    return state



def start_install_batch_operation(
    dependency_ids: list[str],
    approved_plan_id: str,
    data_dir: Path,
) -> dict[str, Any]:
    """Queue an exact-plan-approved profile batch with per-dependency locks."""
    from whaxon.core.installer import apply_approved_dependency_batch

    if not isinstance(dependency_ids, list) or not dependency_ids:
        raise ValueError("at least one dependency ID is required")
    if len(dependency_ids) > 64 or len(set(dependency_ids)) != len(dependency_ids):
        raise ValueError("dependency IDs must be unique and contain at most 64 entries")
    if any(not isinstance(item, str) or not _DEPENDENCY_ID.fullmatch(item) for item in dependency_ids):
        raise ValueError("invalid dependency ID")
    manifest = load_dependency_manifest()
    entries = {item["id"]: item for item in manifest["dependencies"]}
    unknown = sorted(set(dependency_ids) - set(entries))
    if unknown:
        raise ValueError("unknown dependency IDs: " + ", ".join(unknown))
    policy = manifest.get("policy", {})
    if policy.get("automatic_installation_enabled") is not True or "python-package" not in policy.get("automatic_installation_kinds", []):
        raise ValueError("automatic Python-package installation is disabled by policy")
    if sys.prefix == getattr(sys, "base_prefix", sys.prefix):
        raise ValueError("automatic installation requires an active virtual environment")
    plan = build_remediation_plan(dependency_ids=dependency_ids, data_dir=data_dir)
    if plan["plan_id"] != approved_plan_id:
        raise ValueError("approval does not match the current setup plan; regenerate and review it")
    if plan.get("unknown_dependency_ids"):
        raise ValueError("setup plan contains unknown dependencies")
    actions = plan.get("actions", [])
    if not actions:
        raise ValueError("the approved profile has no missing dependencies to install")
    unsupported = [
        action.get("dependency_id", "unknown")
        for action in actions
        if len(action.get("options", [])) != 1
        or action["options"][0].get("kind") != "python-package"
        or action["options"][0].get("automated_execution_supported") is not True
    ]
    if unsupported:
        raise ValueError("profile contains dependencies without a trusted automated installer: " + ", ".join(unsupported))
    operation_id = uuid.uuid4().hex
    operations = _operations_dir(data_dir)
    lock_paths: list[Path] = []
    try:
        for action in actions:
            lock_paths.append(_claim_dependency_lock(operations, action["dependency_id"], operation_id))
    except Exception:
        for lock_path in lock_paths:
            lock_path.unlink(missing_ok=True)
        raise
    state_path = operations / f"{operation_id}.json"
    state: dict[str, Any] = {
        "schema_version": 1,
        "operation_id": operation_id,
        "dependency_ids": [action["dependency_id"] for action in actions],
        "plan_id": approved_plan_id,
        "status": "QUEUED",
        "progress": 0,
        "step": "QUEUED",
        "message": "Approved profile installation queued.",
        "created_at": _now(),
        "updated_at": _now(),
        "cancel_requested": False,
        "worker_pid": os.getpid(),
    }
    cancel_path = operations / f"{operation_id}.cancel"
    try:
        _write_state(state_path, state)
    except Exception:
        for lock_path in lock_paths:
            lock_path.unlink(missing_ok=True)
        raise

    def progress(dependency_id: str, message: str) -> None:
        try:
            current = get_install_operation(data_dir, operation_id) or state
            match = re.search(r"Installing (\d+)/(\d+)", message)
            if match:
                completed = int(match.group(1))
                total = max(1, int(match.group(2)))
                progress_value = min(95, 10 + int(80 * completed / total))
            else:
                progress_value = max(10, min(95, int(current.get("progress", 10))))
            current.update({
                "status": "INSTALLING",
                "step": dependency_id,
                "message": message,
                "progress": progress_value,
                "updated_at": _now(),
            })
            _write_state(state_path, current)
        except (OSError, RuntimeError, ValueError):
            return

    def worker() -> None:
        try:
            current = get_install_operation(data_dir, operation_id) or state
            current.update({"status": "INSTALLING", "message": "Installing approved profile packages.", "updated_at": _now()})
            _write_state(state_path, current)
            result = apply_approved_dependency_batch(
                dependency_ids,
                approved_plan_id,
                data_dir=data_dir,
                progress_callback=progress,
                cancel_requested=cancel_path.exists,
            )
            current = get_install_operation(data_dir, operation_id) or state
            current.update({
                "status": result["status"],
                "step": result["status"],
                "progress": 100,
                "message": result.get("message", result["status"]),
                "result": result,
                "updated_at": _now(),
            })
            _write_state(state_path, current)
        except Exception as exc:
            current = get_install_operation(data_dir, operation_id) or state
            current.update({
                "status": "FAILED",
                "step": "FAILED",
                "progress": 100,
                "message": f"Profile installation failed ({type(exc).__name__}).",
                "updated_at": _now(),
            })
            try:
                _write_state(state_path, current)
            except OSError:
                pass
        finally:
            cancel_path.unlink(missing_ok=True)
            for lock_path in lock_paths:
                lock_path.unlink(missing_ok=True)
            with _LOCK:
                _ACTIVE_THREADS.pop(operation_id, None)

    thread = threading.Thread(target=worker, name=f"whaxon-dependency-batch-{operation_id[:8]}", daemon=True)
    with _LOCK:
        _ACTIVE_THREADS[operation_id] = thread
    try:
        thread.start()
    except Exception as exc:
        state.update({"status": "FAILED", "step": "FAILED", "progress": 100, "message": "Profile worker could not be started.", "updated_at": _now()})
        try:
            _write_state(state_path, state)
        finally:
            for lock_path in lock_paths:
                lock_path.unlink(missing_ok=True)
            with _LOCK:
                _ACTIVE_THREADS.pop(operation_id, None)
        raise RuntimeError("profile installation worker could not be started") from exc
    return state


def cancel_install_operation(data_dir: Path, operation_id: str) -> dict[str, Any] | None:
    state = get_install_operation(data_dir, operation_id)
    if state is None:
        return None
    if state.get("status") not in {"QUEUED", "INSTALLING", "VERIFYING"}:
        return state
    operations = _operations_dir(data_dir)
    cancel_path = operations / f"{operation_id}.cancel"
    flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(cancel_path, flags, 0o600)
    except FileExistsError:
        # A previous cancellation request is already pending.
        pass
    else:
        os.close(descriptor)
    state["cancel_requested"] = True
    state["updated_at"] = _now()
    _write_state(_operation_path(data_dir, operation_id), state)
    return state
