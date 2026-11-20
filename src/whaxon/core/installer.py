"""Explicitly approved, allowlisted Python-package installation transactions.

This module is intentionally narrow: no shell, no OS package manager, no
privilege escalation, and no manifest-supplied executable or argument strings.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
import re
import stat
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from whaxon.core.dependencies import _version_tuple, load_dependency_manifest
from whaxon.core.remediation import build_python_package_argv, build_remediation_plan

INSTALL_TIMEOUT_SECONDS = 900
_AUDIT_LOCK = threading.RLock()
_AUDIT_GENESIS = "0" * 64
_SECRET_PATTERNS = (
    re.compile(r"(?i)(token|password|secret|api[_-]?key)(\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
)


def _redact(value: str, limit: int = 12000) -> str:
    clean = value[:limit]
    clean = _SECRET_PATTERNS[0].sub(r"\1\2[REDACTED]", clean)
    clean = _SECRET_PATTERNS[1].sub(r"\1[REDACTED]", clean)
    return clean


def _audit_path() -> Path:
    root = Path.home() / ".whaxon"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink():
        raise OSError("WHAXON audit root must not be a symlink")
    audit_dir = root / "audit"
    audit_dir.mkdir(mode=0o700, exist_ok=True)
    if audit_dir.is_symlink() or not audit_dir.resolve().is_relative_to(root.resolve()):
        raise OSError("WHAXON audit directory is unsafe")
    path = audit_dir / "dependency-install.jsonl"
    if path.is_symlink():
        raise OSError("WHAXON audit log must not be a symlink")
    return path


def _canonical_audit_record(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@contextmanager
def _audit_process_lock(path: Path):
    """Serialize writers across processes on POSIX and Windows."""
    lock_path = path.with_suffix(path.suffix + ".lock")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("dependency audit lock must be a regular file")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        if os.name == "nt":
            import msvcrt
            locking_name = "locking"
            lock_mode_name = "LK_LOCK"
            unlock_mode_name = "LK_UNLCK"
            locking = getattr(msvcrt, locking_name)
            lock_mode = getattr(msvcrt, lock_mode_name)
            unlock_mode = getattr(msvcrt, unlock_mode_name)
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            locking(descriptor, lock_mode, 1)
            try:
                yield
            finally:
                os.lseek(descriptor, 0, os.SEEK_SET)
                locking(descriptor, unlock_mode, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _append_audit(record: dict[str, Any]) -> None:
    """Append SHA-256-linked events. A local chain is tamper-evident, not immutable."""
    import hashlib

    path = _audit_path()
    with _AUDIT_LOCK, _audit_process_lock(path):
        if path.exists():
            integrity = _verify_dependency_audit_unlocked(path)
            if integrity.get("valid") is not True:
                raise OSError("dependency audit chain integrity check failed; refusing to append")
        previous = _AUDIT_GENESIS
        sequence = 1
        if path.exists():
            if path.is_symlink():
                raise OSError("WHAXON audit log must not be a symlink")
            with path.open("r", encoding="utf-8") as existing:
                for line in existing:
                    if line.strip():
                        previous_record = json.loads(line)
                        previous = str(previous_record.get("event_hash", ""))
                        sequence += 1
        event = {**record, "sequence": sequence, "previous_hash": previous}
        event["event_hash"] = hashlib.sha256(
            bytes.fromhex(previous) + _canonical_audit_record(event)
        ).hexdigest()
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("dependency audit target is not a regular file")
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(json.dumps(event, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def record_dependency_install_event(event: dict[str, Any]) -> None:
    """Append a setup-install event to the local tamper-evident audit chain."""
    if not isinstance(event, dict) or not isinstance(event.get("event_type"), str):
        raise ValueError("audit event must include an event_type")
    _append_audit(event)


def _verify_dependency_audit_unlocked(path: Path | None = None) -> dict[str, Any]:
    """Verify sequence and links; cannot detect an attacker rewriting the whole chain."""
    import hashlib

    target = path or _audit_path()
    if target.is_symlink():
        return {"valid": False, "events_checked": 0, "reason": "symlink_rejected"}
    previous = _AUDIT_GENESIS
    count = 0
    try:
        with target.open("r", encoding="utf-8") as stream:
            for expected_sequence, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                event = json.loads(line)
                supplied_hash = event.pop("event_hash")
                if event.get("sequence") != expected_sequence or event.get("previous_hash") != previous:
                    return {"valid": False, "events_checked": count, "reason": "sequence_or_link_mismatch"}
                calculated = hashlib.sha256(
                    bytes.fromhex(previous) + _canonical_audit_record(event)
                ).hexdigest()
                if supplied_hash != calculated:
                    return {"valid": False, "events_checked": count, "reason": "hash_mismatch"}
                previous = supplied_hash
                count += 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return {"valid": False, "events_checked": count, "reason": "unreadable_or_malformed"}
    return {"valid": True, "events_checked": count, "head_hash": previous}


def verify_dependency_audit(path: Path | None = None) -> dict[str, Any]:
    """Verify the audit chain under the same cross-process lock used by writers."""
    target = path or _audit_path()
    try:
        with _AUDIT_LOCK, _audit_process_lock(target):
            return _verify_dependency_audit_unlocked(target)
    except OSError:
        return {"valid": False, "events_checked": 0, "reason": "lock_or_file_error"}


def _finish_audit(result: dict[str, Any]) -> dict[str, Any]:
    """Never misreport an executed install if its final audit write fails."""
    try:
        _append_audit({**result, "event_type": result.get("event_type", "ACTION_FINISHED")})
    except OSError as exc:
        return {
            **result,
            "original_status": result["status"],
            "status": "AUDIT_FAILED",
            "audit_error": type(exc).__name__,
            "recovery": (
                "The operation ran but its final audit record could not be written. "
                "Run whaxon doctor to establish current state and inspect the local audit directory."
            ),
        }
    return result


def apply_approved_dependency_plan(
    dependency_id: str,
    approved_plan_id: str,
    *,
    data_dir: Path | None = None,
    progress_callback: Callable[[str, str], None] | None = None,
    cancel_requested: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Install exactly one manifest-declared Python package after plan-ID approval."""
    plan = build_remediation_plan(dependency_ids=[dependency_id], data_dir=data_dir)
    if plan["unknown_dependency_ids"]:
        raise ValueError(f"Unknown dependency: {dependency_id}")
    if plan["plan_id"] != approved_plan_id:
        raise ValueError("Approval does not match the current remediation plan; regenerate and review it.")
    actions = [action for action in plan["actions"] if action["dependency_id"] == dependency_id]
    if len(actions) != 1:
        raise ValueError("Dependency does not require an automated installation.")
    options = actions[0]["options"]
    if len(options) != 1 or options[0]["kind"] != "python-package":
        raise ValueError("No supported automated installation is available for this dependency.")
    if sys.prefix == getattr(sys, "base_prefix", sys.prefix):
        raise ValueError(
            "Automatic Python-package installation requires an active virtual environment. "
            "Create and activate a venv, then run doctor and review a fresh plan."
        )

    manifest = load_dependency_manifest()
    policy = manifest.get("policy", {})
    if (
        policy.get("automatic_installation_enabled") is not True
        or "python-package" not in policy.get("automatic_installation_kinds", [])
    ):
        raise ValueError("automatic Python-package installation is disabled by the dependency policy")
    entry = next((item for item in manifest["dependencies"] if item["id"] == dependency_id), None)
    if not entry or entry.get("kind") != "python-package":
        raise ValueError("Dependency is not an allowlisted Python package.")
    argv = build_python_package_argv(entry)
    operation_id = str(uuid.uuid4())
    started = datetime.now(UTC).isoformat()
    base = {
        "schema_version": 1,
        "operation_id": operation_id,
        "dependency_id": dependency_id,
        "plan_id": approved_plan_id,
        "manifest_schema_version": manifest["schema_version"],
        "started_at": started,
        "interpreter": sys.executable,
        "command": argv,
        "privilege_escalation": False,
        "shell": False,
    }
    # Persist the plan and approval decision before starting a consequential action.
    # The current interface does not provide a verified human identity.
    _append_audit({
        "event_type": "PLAN_CREATED",
        "plan_id": approved_plan_id,
        "dependency_id": dependency_id,
        "plan_digest": approved_plan_id.removeprefix("plan-"),
        "manifest_schema_version": manifest["schema_version"],
        "action": actions[0],
        "created_at": datetime.now(UTC).isoformat(),
    })
    _append_audit({
        "event_type": "APPROVAL_ACCEPTED",
        "plan_id": approved_plan_id,
        "dependency_id": dependency_id,
        "approval_mechanism": "explicit_current_plan_id_submission",
        "actor_identity": "not_available_from_current_interface",
        "approved_at": datetime.now(UTC).isoformat(),
    })
    _append_audit({**base, "event_type": "ACTION_STARTED", "status": "STARTED"})
    if cancel_requested and cancel_requested():
        result = {
            **base,
            "status": "CANCELLED",
            "exit_code": None,
            "output": "Installation was cancelled before the package manager started.",
            "recovery": "No package-manager command was started. Re-run doctor and create a new plan if needed.",
            "finished_at": datetime.now(UTC).isoformat(),
        }
        return _finish_audit(result)
    if progress_callback:
        progress_callback("INSTALLING", "Installing the approved Python package.")
    process = None
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        started_monotonic = time.monotonic()
        last_progress = started_monotonic
        while True:
            if cancel_requested and cancel_requested() and process.poll() is None:
                if process.poll() is None:
                    process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                result = {
                    **base,
                    "status": "CANCELLED",
                    "exit_code": process.returncode,
                    "output": _redact((stdout or "") + "\n" + (stderr or "")),
                    "recovery": "The package operation was terminated; package state may be partial. Re-run whaxon doctor and recreate the virtual environment if inconsistent.",
                    "finished_at": datetime.now(UTC).isoformat(),
                }
                result = _finish_audit(result)
                return result
            elapsed = time.monotonic() - started_monotonic
            if progress_callback and elapsed - last_progress >= 5:
                progress_callback("INSTALLING", f"Package manager running for {int(elapsed)} seconds.")
                last_progress = elapsed
            if elapsed >= INSTALL_TIMEOUT_SECONDS and process.poll() is None:
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                result = {
                    **base,
                    "status": "TIMED_OUT",
                    "exit_code": process.returncode,
                    "output": _redact((stdout or "") + "\n" + (stderr or "")),
                    "recovery": "The package manager was terminated after timeout. Re-run whaxon doctor; recreate the virtual environment if package state is uncertain.",
                    "finished_at": datetime.now(UTC).isoformat(),
                }
                result = _finish_audit(result)
                return result
            try:
                stdout, stderr = process.communicate(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                continue
        exit_code = process.returncode
        output = _redact((stdout or "") + "\n" + (stderr or ""))
        if exit_code != 0:
            result = {**base, "status": "INSTALL_FAILED", "exit_code": exit_code,
                      "output": output, "recovery": "No automatic rollback was attempted. Re-run whaxon doctor; if the environment is inconsistent, recreate the virtual environment and reinstall from the approved lock/profile.", "finished_at": datetime.now(UTC).isoformat()}
            result = _finish_audit(result)
            return result
    except OSError as exc:
        result = {**base, "status": "INSTALL_FAILED", "exit_code": None,
                  "output": _redact(str(exc)), "recovery": "The package manager could not be started. No successful installation is confirmed.", "finished_at": datetime.now(UTC).isoformat()}
        result = _finish_audit(result)
        return result
    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        result = {**base, "status": "INTERRUPTED", "exit_code": None,
                  "output": "Installation interrupted by user.",
                  "recovery": "The package manager may have partially changed the virtual environment. Re-run whaxon doctor and recreate the venv if state is inconsistent.",
                  "finished_at": datetime.now(UTC).isoformat()}
        _finish_audit(result)
        raise

    if progress_callback:
        progress_callback("VERIFYING", "Checking installed package version and import availability.")
    try:
        version = importlib.metadata.version(entry["id"])
        importlib.import_module(entry.get("import_name", entry["id"]))
        verified = _version_tuple(version) >= _version_tuple(entry["minimum_version"])
        verification_reason = (
            "Installed distribution meets the minimum version and import check succeeded."
            if verified else "Installed version is below the declared minimum."
        )
    except Exception as exc:
        version = None
        verified = False
        verification_reason = f"Post-install verification failed ({type(exc).__name__})."
    result = {
        **base,
        "status": "VERIFIED" if verified else "VERIFICATION_FAILED",
        "exit_code": 0,
        "installed_version": version,
        "verification": verification_reason,
        "output": output,
        "finished_at": datetime.now(UTC).isoformat(),
    }
    result = _finish_audit(result)
    if progress_callback:
        progress_callback(result["status"], result.get("verification", result.get("recovery", "Installation finished.")))
    return result


def apply_approved_dependency_batch(
    dependency_ids: list[str],
    approved_plan_id: str,
    *,
    data_dir: Path | None = None,
    progress_callback: Callable[[str, str], None] | None = None,
    cancel_requested: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Apply a reviewed multi-package plan sequentially; never elevates privileges.

    The batch plan hash binds the exact dependency selection and environment.
    Each package is then re-planned and passed through the existing single-item
    installer, preserving its allowlist, verification and audit behaviour.
    """
    from whaxon.core.remediation import build_remediation_plan

    plan = build_remediation_plan(dependency_ids=dependency_ids, data_dir=data_dir)
    if plan["plan_id"] != approved_plan_id:
        raise ValueError("Approval does not match the current setup plan; regenerate and review it.")
    if plan["unknown_dependency_ids"]:
        raise ValueError("Setup plan contains unknown dependencies.")
    actions = plan["actions"]
    unsupported = [
        action["dependency_id"]
        for action in actions
        if len(action.get("options", [])) != 1
        or action["options"][0].get("kind") != "python-package"
        or action["options"][0].get("automated_execution_supported") is not True
    ]
    if unsupported:
        raise ValueError(
            "Batch contains dependencies without a trusted automated Python installer: "
            + ", ".join(unsupported)
        )

    # Record approval of the exact profile plan before the first package action.
    # A batch's child package plans are regenerated for safe sequential execution;
    # this event preserves the operator-approved parent selection in the audit chain.
    _append_audit({
        "event_type": "PROFILE_BATCH_APPROVAL_ACCEPTED",
        "plan_id": approved_plan_id,
        "dependency_ids": list(dependency_ids),
        "status": "APPROVED",
    })

    def finish_batch(result: dict[str, Any]) -> dict[str, Any]:
        try:
            _append_audit({
                "event_type": "PROFILE_BATCH_FINISHED",
                "plan_id": approved_plan_id,
                "dependency_ids": list(dependency_ids),
                "status": result.get("status", "UNKNOWN"),
            })
        except (OSError, RuntimeError, ValueError) as exc:
            return {
                **result,
                "original_status": result.get("status"),
                "status": "AUDIT_FAILED",
                "recovery": (
                    "The profile operation ran, but its terminal audit event could not be persisted. "
                    "Inspect the environment with whaxon doctor and verify the local audit chain "
                    f"before retrying ({type(exc).__name__})."
                ),
            }
        return result

    completed: list[dict[str, Any]] = []
    for index, action in enumerate(actions, start=1):
        dependency_id = action["dependency_id"]
        if cancel_requested and cancel_requested():
            return finish_batch({
                "status": "CANCELLED",
                "completed": completed,
                "remaining": [item["dependency_id"] for item in actions[index - 1:]],
                "message": "Cancellation requested; completed package operations were not rolled back.",
            })
        if progress_callback:
            progress_callback(dependency_id, f"Installing {index}/{len(actions)}")
        single = build_remediation_plan(
            dependency_ids=[dependency_id], data_dir=data_dir
        )
        result = apply_approved_dependency_plan(
            dependency_id,
            single["plan_id"],
            data_dir=data_dir,
            progress_callback=progress_callback,
            cancel_requested=cancel_requested,
        )
        completed.append({"dependency_id": dependency_id, "result": result})
        if result.get("status") != "VERIFIED":
            remaining = [item["dependency_id"] for item in actions[index:]]
            status = "CANCELLED" if result.get("status") == "CANCELLED" else "PARTIAL_FAILURE"
            return finish_batch({
                "status": status,
                "completed": completed,
                "remaining": remaining,
                "message": (
                    "Cancellation requested; completed package operations were not rolled back."
                    if status == "CANCELLED"
                    else "Stopped after the first failed or unverified package. Review doctor output before retrying."
                ),
            })
    return finish_batch({
        "status": "VERIFIED",
        "completed": completed,
        "remaining": [],
        "message": "All approved Python package actions completed and passed their post-install checks.",
    })
