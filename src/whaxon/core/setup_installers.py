"""Explicitly approved installation of curated external security tools.

Only fixed package IDs are executable. Catalog data and user input never become
package-manager arguments. Unsupported host/package combinations stay manual.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from whaxon.core.dependencies import collect_dependency_report
from whaxon.core.setup_environment import detect_setup_environment

# These mappings are deliberately conservative. No arbitrary package names,
# URLs, shell fragments, or manifest-provided commands are accepted.
_PACKAGE_MAP: dict[str, dict[str, str]] = {
    "apt": {"nmap": "nmap", "gobuster": "gobuster", "sqlmap": "sqlmap", "ffuf": "ffuf"},
    "brew": {"nmap": "nmap", "gobuster": "gobuster", "sqlmap": "sqlmap", "ffuf": "ffuf", "nuclei": "nuclei"},
}
_MANAGER_COMMANDS = {
    "apt": ("install", "-y", "--no-install-recommends"),
    "dnf": ("install", "-y"),
    "yum": ("install", "-y"),
    "pacman": ("-S", "--needed", "--noconfirm"),
    "zypper": ("--non-interactive", "install"),
    "apk": ("add", "--no-progress"),
    "brew": ("install",),
}
_PRIVILEGED_MANAGERS = {"apt", "dnf", "yum", "pacman", "zypper", "apk"}


def build_external_tool_plan(
    tool_ids: list[str],
    *,
    system: str | None = None,
    data_dir: Path | None = None,
    which: Callable[[str], str | None] = shutil.which,
    is_root: bool | None = None,
) -> dict[str, Any]:
    """Build a deterministic preview for supported, missing external tools."""
    if not isinstance(tool_ids, list) or not tool_ids or len(tool_ids) > 32:
        raise ValueError("select between 1 and 32 external tool IDs")
    if any(not isinstance(item, str) or not item.isidentifier() for item in tool_ids):
        raise ValueError("invalid external tool ID")
    if len(set(tool_ids)) != len(tool_ids):
        raise ValueError("external tool IDs must be unique")
    host = detect_setup_environment(system=system, which=which)
    # apt package names are only curated for Debian-family distributions we
    # explicitly support. An apt binary alone is not enough to infer package
    # compatibility on arbitrary Linux distributions.
    supported_managers = []
    for item in host["package_managers"]:
        manager_id = item["id"]
        if manager_id not in _PACKAGE_MAP:
            continue
        if manager_id not in host.get("supported_installers", []):
            continue
        supported_managers.append(item)
    manager = supported_managers[0] if supported_managers else None
    manager_id = None if manager is None else manager["id"]
    # Preview only resolves executable paths. Trusted version probes are subprocesses
    # and are deferred until the operator explicitly submits the approved plan.
    report = collect_dependency_report(data_dir=data_dir, verify_external=False)
    observed = {item["id"]: item for item in report["dependencies"] if item["kind"] == "external-tool"}
    actions: list[dict[str, Any]] = []
    manual: list[dict[str, str]] = []
    for tool_id in sorted(tool_ids):
        current = observed.get(tool_id)
        if current is None:
            manual.append({"tool_id": tool_id, "reason": "Tool is not present in the trusted WHAXON catalog."})
            continue
        if current["status"] in {"READY", "DETECTED"}:
            actions.append({
                "tool_id": tool_id,
                "status": current["status"],
                "package_id": None,
                "binary": current.get("detected_path") or current.get("id"),
            })
            continue
        package_id = _PACKAGE_MAP.get(manager_id or "", {}).get(tool_id)
        if not package_id:
            manual.append({
                "tool_id": tool_id,
                "reason": f"No curated package mapping for {tool_id} on {host['system']} using {manager_id or 'an available manager'}.",
            })
            continue
        # A package mapping can only exist when a supported manager was selected.
        # Narrow both optional values explicitly for static type checkers.
        assert manager is not None and manager_id is not None
        requires_privilege = (
            manager_id in _PRIVILEGED_MANAGERS
            and not (
                os.geteuid() == 0
                if is_root is None and hasattr(os, "geteuid")
                else bool(is_root)
            )
        )
        command_argv = [
            manager["executable"], *_MANAGER_COMMANDS[manager_id], package_id
        ]
        if requires_privilege:
            sudo_path = which("sudo")
            if not sudo_path:
                manual.append({
                    "tool_id": tool_id,
                    "reason": "This package manager requires root privileges and sudo is unavailable; install from an administrator/root shell.",
                })
                continue
            # The preview must disclose the exact non-interactive elevation argv
            # that will be executed after the separate elevation consent.
            command_argv = [sudo_path, "-n", *command_argv]
        actions.append({
            "tool_id": tool_id,
            "status": "MISSING",
            "package_manager": manager_id,
            "package_id": package_id,
            "binary": current.get("detected_path") or current.get("id"),
            "command_argv": command_argv,
            "source": (
                "configured operating-system package repositories"
                if manager_id == "apt"
                else "Homebrew formula repository"
            ),
            "network_access_required": True,
            "expected_impact": (
                "Installs the selected package and any dependencies resolved by "
                "the host package manager; exact download and disk sizes depend "
                "on the configured repositories and are reported by that manager."
            ),
            "requires_privilege": requires_privilege,
        })
    basis = {
        "system": host["system"],
        "architecture": host["architecture"],
        "distribution_id": host.get("distribution_id", ""),
        "wsl": bool(host.get("wsl", False)),
        "support_status": host.get("support_status", ""),
        "manager": manager,
        "actions": actions,
        "manual": manual,
    }
    plan_id = "tools-" + hashlib.sha256(
        json.dumps(basis, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    return {
        "plan_id": plan_id,
        "environment": host,
        "actions": actions,
        "manual": manual,
        "safety": {
            "read_only": True,
            "commands_executed": False,
            "network_accessed": False,
            "privilege_escalation_attempted": False,
        },
    }


def _finish_external_result(result: dict[str, Any]) -> dict[str, Any]:
    """Persist the terminal event; never claim success if the audit write fails."""
    from whaxon.core.installer import record_dependency_install_event

    try:
        record_dependency_install_event({
            **result,
            "event_type": "EXTERNAL_TOOL_BATCH_FINISHED",
        })
    except OSError as exc:
        return {
            **result,
            "original_status": result["status"],
            "status": "AUDIT_FAILED",
            "audit_error": type(exc).__name__,
            "recovery": (
                "The package operation may have run, but its terminal audit event "
                "could not be persisted. Re-run WHAXON diagnostics and inspect "
                "~/.whaxon/audit before retrying."
            ),
        }
    return result


def _command_for_action(
    action: dict[str, Any],
    manager_path: str,
    *,
    allow_elevation: bool,
    which: Callable[[str], str | None] | None = None,
) -> list[str]:
    manager = action["package_manager"]
    package = action["package_id"]
    # Bind the package ID to the selected tool, not merely to any package
    # allowed for this manager. This prevents a malformed/stale action from
    # substituting (for example) sqlmap for nmap while passing a broad allowlist.
    if (
        manager not in _MANAGER_COMMANDS
        or not isinstance(action.get("tool_id"), str)
        or _PACKAGE_MAP.get(manager, {}).get(action["tool_id"]) != package
    ):
        raise ValueError("package action is not in the trusted tool-to-package allowlist")
    argv = [manager_path, *_MANAGER_COMMANDS[manager], package]
    if manager in _PRIVILEGED_MANAGERS and os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        if not allow_elevation:
            raise ValueError("system package installation requires explicit --allow-elevation consent")
        sudo = (which or shutil.which)("sudo")
        if not sudo:
            raise ValueError("sudo is unavailable; run WHAXON from an administrator/root shell")
        argv = [sudo, "-n", *argv]
    if action.get("command_argv") != argv:
        raise ValueError("package command does not match the reviewed plan")
    return argv


def _run_bounded_package_command(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run one package-manager command and stop its child on timeout or Ctrl-C."""
    timeout = float(kwargs.pop("timeout", 1800))
    process = subprocess.Popen(argv, **kwargs)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(
            argv, timeout, output=stdout, stderr=stderr
        ) from exc
    except KeyboardInterrupt:
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
        raise
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def apply_approved_external_tool_plan(
    tool_ids: list[str],
    approved_plan_id: str,
    *,
    allow_system_changes: bool = False,
    allow_elevation: bool = False,
    data_dir: Path | None = None,
    runner: Callable[..., Any] | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> dict[str, Any]:
    """Install exact reviewed tool actions, then verify each binary's trusted version probe."""
    if not allow_system_changes:
        raise ValueError("system changes require explicit --allow-system-changes consent")
    plan = build_external_tool_plan(tool_ids, data_dir=data_dir, which=which)
    if plan["plan_id"] != approved_plan_id:
        raise ValueError("tool approval does not match the current plan; regenerate and review it")
    if plan["manual"]:
        raise ValueError("selected tools include unsupported manual installations: " + ", ".join(x["tool_id"] for x in plan["manual"]))
    pending = [item for item in plan["actions"] if item["status"] == "MISSING"]
    if any(action.get("requires_privilege") for action in pending) and not allow_elevation:
        raise ValueError("system package installation requires explicit --allow-elevation consent")
    if not pending:
        verified = collect_dependency_report(data_dir=data_dir, verify_external=True)
        states = {
            item["id"]: item["status"]
            for item in verified["dependencies"]
            if item["kind"] == "external-tool"
        }
        failures = [tool_id for tool_id in tool_ids if states.get(tool_id) != "READY"]
        return {
            "status": "VERIFIED" if not failures else "VERIFICATION_FAILED",
            "installed": [],
            "already_present": [item["tool_id"] for item in plan["actions"]],
            "commands_executed": True,
            "network_accessed": False,
            "package_installation_attempted": False,
            "privilege_escalation_attempted": False,
            "verification_failures": failures,
            "message": (
                "Every selected tool passed its trusted version probe."
                if not failures
                else "Existing executables were detected but did not pass trusted version verification."
            ),
        }

    elevation_attempted = bool(
        allow_elevation and any(action.get("requires_privilege") for action in pending)
    )

    def finish_external(result: dict[str, Any]) -> dict[str, Any]:
        return _finish_external_result({
            **result,
            "commands_executed": True,
            "network_accessed": True,
            "package_installation_attempted": True,
            "privilege_escalation_attempted": elevation_attempted,
        })

    manager_id = pending[0]["package_manager"]
    manager = next((item for item in plan["environment"]["package_managers"] if item["id"] == manager_id), None)
    if not manager:
        raise ValueError("the approved package manager is no longer available")
    from whaxon.core.installer import record_dependency_install_event

    record_dependency_install_event({
        "event_type": "EXTERNAL_TOOL_APPROVAL_ACCEPTED",
        "plan_id": approved_plan_id,
        "tool_ids": list(tool_ids),
        "actions": pending,
        "system_changes_consented": True,
        "elevation_consented": bool(allow_elevation),
        "actor_identity": "not_available_from_current_interface",
    })
    installed: list[str] = []
    for action in pending:
        argv = _command_for_action(
            action, manager["executable"],
            allow_elevation=allow_elevation, which=which,
        )
        record_dependency_install_event({
            "event_type": "EXTERNAL_TOOL_ACTION_STARTED",
            "plan_id": approved_plan_id,
            "tool_id": action["tool_id"],
            "package_manager": manager_id,
            "package_id": action["package_id"],
            "command": argv,
            "shell": False,
        })
        try:
            command_runner = runner or _run_bounded_package_command
            completed = command_runner(
                argv, shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1800,
            )
        except subprocess.TimeoutExpired:
            return finish_external({
                "status": "FAILED",
                "installed": installed,
                "failed_tool": action["tool_id"],
                "message": "Package manager exceeded the 30-minute timeout. Completed installs are retained; inspect the host before retrying.",
            })
        except KeyboardInterrupt:
            return finish_external({
                "status": "INTERRUPTED",
                "installed": installed,
                "failed_tool": action["tool_id"],
                "message": "Package-manager process was stopped after user interruption. System package state may be partial; inspect it before retrying.",
                "recovery": "Re-run WHAXON diagnostics and inspect the package manager's transaction log before retrying.",
            })
        except OSError as exc:
            return _finish_external_result({
                "status": "FAILED",
                "installed": installed,
                "failed_tool": action["tool_id"],
                "commands_executed": False,
                "network_accessed": False,
                "package_installation_attempted": False,
                "privilege_escalation_attempted": False,
                "message": f"Package manager could not execute ({type(exc).__name__}).",
            })
        if completed.returncode != 0:
            return finish_external({
                "status": "FAILED",
                "installed": installed,
                "failed_tool": action["tool_id"],
                "exit_code": completed.returncode,
                "message": "Package manager failed. Completed installs are retained; inspect the host before retrying.",
            })
        installed.append(action["tool_id"])
    verified = collect_dependency_report(data_dir=data_dir, verify_external=True)
    states = {item["id"]: item["status"] for item in verified["dependencies"] if item["kind"] == "external-tool"}
    failures = [tool_id for tool_id in tool_ids if states.get(tool_id) != "READY"]
    return finish_external({
        "status": "FAILED" if failures else "VERIFIED",
        "installed": installed,
        "already_present": [
            item["tool_id"] for item in plan["actions"]
            if item["status"] in {"READY", "DETECTED"}
        ],
        "verification_failures": failures,
        "message": "Every selected tool passed its trusted version probe." if not failures else "Installation commands completed, but one or more selected tools failed version verification.",
    })
