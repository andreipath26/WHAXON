"""Deterministic, read-only remediation planning for dependency diagnostics."""
from __future__ import annotations

import hashlib
import json
import platform
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from whaxon.core.dependencies import collect_dependency_report, load_dependency_manifest

PLAN_SCHEMA_VERSION = 1


def build_python_package_argv(entry: dict[str, Any]) -> list[str]:
    """Return the exact fixed pip argument vector shown in plans and executed."""
    requirement = f"{entry['id']}>={entry['minimum_version']}"
    return [
        sys.executable, "-m", "pip", "--isolated", "install",
        "--disable-pip-version-check", "--no-input", "--quiet",
        "--progress-bar", "off", "--only-binary=:all:",
        "--index-url", "https://pypi.org/simple", requirement,
    ]


def _python_package_option(
    entry: dict[str, Any], *, automatic_installation_enabled: bool
) -> dict[str, Any]:
    requirement = f"{entry['id']}>={entry['minimum_version']}"
    description = f"Install or upgrade {entry['id']} in the active interpreter."
    argv = build_python_package_argv(entry)
    return {
        "id": f"pip:{entry['id']}",
        "kind": "python-package",
        "title": description,
        "command": argv,
        "display_command": (
            subprocess.list2cmdline(argv)
            if platform.system() == "Windows"
            else shlex.join(argv)
        ),
        "package_source": "https://pypi.org/simple",
        "package_specifier": requirement,
        "may_install_transitive_dependencies": True,
        "requires_network": True,
        "requires_privilege": False,
        "system_wide": False,
        "requires_virtual_environment": True,
        "automated_execution_supported": automatic_installation_enabled,
        "approval_required": True,
        "warning": "Preview only. This plan does not execute pip or resolve/install packages. After approval, pip may install or update transitive dependencies from the configured PyPI index; binary wheels only, no source builds.",
    }


def build_remediation_plan(*, dependency_ids: list[str] | None = None,
                           data_dir: Path | None = None) -> dict[str, Any]:
    """Build a deterministic plan from the packaged manifest and current read-only state."""
    manifest = load_dependency_manifest()
    report = collect_dependency_report(data_dir=data_dir)
    entries = {entry["id"]: entry for entry in manifest["dependencies"]}
    policy = manifest.get("policy", {})
    automatic_installation_enabled = (
        policy.get("automatic_installation_enabled") is True
        and "python-package" in policy.get("automatic_installation_kinds", [])
    )
    observed = {entry["id"]: entry for entry in report["dependencies"]}
    selected = set(observed) if dependency_ids is None else set(dependency_ids)
    unknown = sorted(selected - set(observed))
    actions: list[dict[str, Any]] = []
    for dep_id in sorted(selected & set(observed)):
        result = observed[dep_id]
        if result["status"] in {"READY", "DETECTED"}:
            continue
        manifest_entry = entries.get(dep_id)
        if manifest_entry and manifest_entry.get("kind") == "python-package":
            actions.append({
                "dependency_id": dep_id,
                "current_status": result["status"],
                "options": [_python_package_option(
                    manifest_entry,
                    automatic_installation_enabled=automatic_installation_enabled,
                )],
            })
        elif dep_id == "python":
            actions.append({
                "dependency_id": dep_id,
                "current_status": result["status"],
                "options": [{
                    "id": "manual:python-runtime",
                    "kind": "manual",
                    "title": "Install a supported Python 3.11+ runtime using the official distribution for this operating system.",
                    "command": None,
                    "display_command": None,
                    "requires_network": None,
                    "requires_privilege": "depends-on-install-method",
                    "system_wide": "depends-on-install-method",
                    "automated_execution_supported": False,
                    "approval_required": False,
                    "warning": "WHAXON cannot safely choose a Python installer for this host yet.",
                }],
            })
        else:
            actions.append({
                "dependency_id": dep_id,
                "current_status": result["status"],
                "options": [{
                    "id": f"manual:{dep_id}",
                    "kind": "manual",
                    "title": result.get("remediation") or "Consult the official project installation instructions.",
                    "command": None,
                    "display_command": None,
                    "requires_network": None,
                    "requires_privilege": "unknown",
                    "system_wide": "unknown",
                    "automated_execution_supported": False,
                    "approval_required": False,
                    "warning": "No trusted platform-specific installer is configured for this dependency.",
                }],
            })
    plan_basis = {
        "selected": sorted(selected),
        "environment": report["environment"],
        "manifest": manifest,
        "actions": actions,
    }
    plan_id = "plan-" + hashlib.sha256(
        json.dumps(plan_basis, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "plan_id": plan_id,
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "overall_status": report["overall_status"],
        "actions": actions,
        "unknown_dependency_ids": unknown,
        "safety": {
            "read_only": True,
            "commands_executed": False,
            "network_accessed": False,
            "installation_attempted": False,
            "privilege_escalation_attempted": False,
            "approval_granted": False,
        },
        "notice": "A plan is not authorization. No command in this document has been executed.",
    }
