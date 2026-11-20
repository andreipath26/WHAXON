"""whaxon setup: inspect the host and produce a reviewable first-run plan."""
from __future__ import annotations

import argparse
import json
import shlex
import sys
import venv
from pathlib import Path

from whaxon.core.dependencies import load_dependency_manifest
from whaxon.core.installer import apply_approved_dependency_batch
from whaxon.core.remediation import build_remediation_plan
from whaxon.core.setup_environment import detect_setup_environment
from whaxon.core.setup_installers import apply_approved_external_tool_plan, build_external_tool_plan

_PROFILE_CAPABILITIES = {
    "core": ("core",),
    "standard": ("core", "tui", "web"),
    "full": ("core", "tui", "web", "gui", "metasploit"),
}


def build_setup_plan(profile: str = "core", capabilities: list[str] | None = None) -> dict:
    manifest = load_dependency_manifest()
    known = set(manifest.get("profiles", {}))
    if profile == "custom":
        selected = tuple(dict.fromkeys(capabilities or ()))
        if not selected:
            raise ValueError("custom profile requires at least one --capability")
    else:
        selected = _PROFILE_CAPABILITIES[profile]
    unknown = sorted(set(selected) - known)
    if unknown:
        raise ValueError(f"unknown capabilities: {', '.join(unknown)}")

    dependency_ids = {"python"}
    for capability in selected:
        dependency_ids.update(manifest["profiles"].get(capability, []))
    # External security tools remain optional and are never installed by this planner.
    plan = build_remediation_plan(dependency_ids=sorted(dependency_ids))
    return {
        "schema_version": 1,
        "profile": profile,
        "capabilities": list(selected),
        "environment": detect_setup_environment(),
        "dependency_plan": plan,
        "execution": {
            "status": "PREVIEW_ONLY",
            "commands_executed": False,
            "network_accessed": False,
            "privilege_escalation_attempted": False,
            "automated_os_package_installation": False,
        },
        "limitations": [
            "The profile batch installs only manifest-approved Python packages.",
            "External-tool installation is a separate opt-in CLI flow with curated apt/Homebrew mappings; unsupported combinations remain manual.",
            "This preview does not create a virtual environment or change the Python environment.",
        ],
    }


def create_virtual_environment(destination: str | Path = ".venv") -> Path:
    """Create a new isolated venv without overwriting existing user data."""
    target = Path(destination).expanduser()
    if target.exists() or target.is_symlink():
        raise ValueError(
            f"Refusing to overwrite existing path: {target}. "
            "Choose a new --venv-path or move the existing directory yourself."
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    venv.EnvBuilder(with_pip=True, clear=False, symlinks=(sys.platform != "win32")).create(target)
    return target.resolve()


def _activation_instructions(venv_path: Path, *, platform_name: str | None = None) -> list[str]:
    """Return copy/paste activation commands for the detected shell platform."""
    current = platform_name or sys.platform
    if current == "win32":
        scripts = venv_path / "Scripts"
        powershell_activation = str(scripts / "Activate.ps1").replace("'", "''")
        return [
            f". '{powershell_activation}'  # PowerShell",
            f'"{scripts / "activate.bat"}"  # cmd.exe',
        ]
    # Quote paths so virtual environments created beneath directories with
    # spaces or shell metacharacters can be activated by copy/paste.
    return [f"source {shlex.quote(str(venv_path / 'bin' / 'activate'))}"]


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="whaxon setup",
        description=("Inspect and prepare a WHAXON environment. Previews are read-only; "
                     "environment creation and package installation require explicit flags and approval."),
    )
    parser.add_argument("--profile", choices=("core", "standard", "full", "custom"), default="core")
    parser.add_argument("--capability", action="append", default=[],
                        help="Capability for --profile custom; may be repeated.")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--create-venv", action="store_true",
                        help="Create a new isolated .venv; refuses to overwrite an existing path.")
    parser.add_argument("--venv-path", default=".venv",
                        help="Destination for --create-venv (default: .venv).")
    parser.add_argument("--install", action="store_true",
                        help="Execute the reviewed Python-package plan; requires --approve.")
    parser.add_argument("--approve", metavar="PLAN_ID",
                        help="Exact Python package plan ID printed by the preview you reviewed.")
    parser.add_argument("--tool", action="append", default=[],
                        help="External tool ID to include in the curated OS-package plan; may be repeated.")
    parser.add_argument("--install-tools", action="store_true",
                        help="Install selected curated external tools after explicit approval.")
    parser.add_argument("--approve-tools", metavar="PLAN_ID",
                        help="Exact external-tool plan ID printed by the preview you reviewed.")
    parser.add_argument("--allow-system-changes", action="store_true",
                        help="Explicitly consent to system package changes and network access.")
    parser.add_argument("--allow-elevation", action="store_true",
                        help="Explicitly allow non-interactive sudo for OS package managers that require root.")
    ns = parser.parse_args(args)
    if ns.create_venv and (ns.install or ns.approve):
        parser.error("--create-venv cannot be combined with --install/--approve")
    if ns.install and not ns.approve:
        parser.error("--install requires --approve PLAN_ID")
    if ns.approve and not ns.install:
        parser.error("--approve can only be used with --install")
    if ns.install_tools and (not ns.tool or not ns.approve_tools or not ns.allow_system_changes):
        parser.error("--install-tools requires --tool, --approve-tools PLAN_ID and --allow-system-changes")
    if ns.approve_tools and not ns.install_tools:
        parser.error("--approve-tools can only be used with --install-tools")
    if ns.allow_elevation and not ns.install_tools:
        parser.error("--allow-elevation can only be used with --install-tools")
    if ns.install and ns.install_tools:
        parser.error("Python package and OS tool installation must be approved in separate operations")
    if ns.tool and ns.create_venv:
        parser.error("--tool cannot be combined with --create-venv")
    try:
        if ns.create_venv:
            created = create_virtual_environment(ns.venv_path)
            print(f"Created virtual environment: {created}")
            for activation in _activation_instructions(created):
                print(f"Activate it with: {activation}")
            print("Install WHAXON into the new environment: python -m pip install --upgrade whaxon")
            print("Then run: whaxon doctor")
            return 0
        result = build_setup_plan(ns.profile, ns.capability)
        if ns.tool:
            result["external_tool_plan"] = build_external_tool_plan(
                ns.tool, data_dir=Path(result["environment"].get("data_dir", ".")) if result["environment"].get("data_dir") else None
            )
            if ns.install_tools:
                result["external_tool_installation"] = apply_approved_external_tool_plan(
                    ns.tool,
                    ns.approve_tools,
                    allow_system_changes=ns.allow_system_changes,
                    allow_elevation=ns.allow_elevation,
                )
                tool_result = result["external_tool_installation"]
                commands_executed = bool(
                    tool_result.get("commands_executed", tool_result.get("installed"))
                )
                result["execution"] = {
                    **result["execution"],
                    "status": tool_result["status"],
                    "commands_executed": commands_executed,
                    "network_accessed": bool(
                        tool_result.get("network_accessed", bool(tool_result.get("installed")))
                    ),
                    "privilege_escalation_attempted": bool(
                        tool_result.get(
                            "privilege_escalation_attempted",
                            ns.allow_elevation and any(
                                action.get("requires_privilege")
                                for action in result["external_tool_plan"]["actions"]
                            ),
                        )
                    ),
                    "automated_os_package_installation": bool(
                        tool_result.get("package_installation_attempted", tool_result.get("installed"))
                    ),
                }
        if ns.install:
            dependency_ids = {"python"}
            manifest = load_dependency_manifest()
            for capability in result["capabilities"]:
                dependency_ids.update(manifest["profiles"].get(capability, []))
            result["installation"] = apply_approved_dependency_batch(
                sorted(dependency_ids), ns.approve
            )
            result["execution"] = {
                **result["execution"],
                "status": result["installation"]["status"],
                "commands_executed": True,
            }
    except (OSError, ValueError) as exc:
        print(f"Setup operation failed: {exc}", file=sys.stderr)
        return 2
    if ns.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        env = result["environment"]
        print(f"WHAXON setup preview — {result['profile']} profile")
        print(f"Host: {env['system']} {env['release']} ({env['architecture']})")
        print(f"Package managers: {', '.join(item['id'] for item in env['package_managers']) or 'none detected'}")
        print(f"Capabilities: {', '.join(result['capabilities'])}")
        print(f"Approval ID: {result['dependency_plan']['plan_id']}")
        print("Python package installs require an active virtual environment.")
        print()
        for action in result["dependency_plan"]["actions"]:
            option = action["options"][0]
            print(f"- {action['dependency_id']}: {option['title']}")
            if option.get("display_command"):
                print(f"  Preview: {option['display_command']}")
        print()
        if ns.install:
            print(f"Installation result: {result['installation']['status']}")
            print("Only explicitly approved, allowlisted Python packages are eligible for installation.")
        else:
            print("Preview only. No commands, network requests, or privilege escalation were performed.")
        if ns.tool:
            tool_plan = result["external_tool_plan"]
            print(f"External-tool approval ID: {tool_plan['plan_id']}")
            for action in tool_plan["actions"]:
                print(f"- {action['tool_id']}: {action['status']} {action.get('package_id') or ''}")
                if action.get("command_argv"):
                    print(f"  Command: {shlex.join(action['command_argv'])}")
                if action.get("source"):
                    print(f"  Source: {action['source']}")
                if action.get("network_access_required"):
                    print("  Network: required; package and dependency downloads may occur")
                if action.get("requires_privilege"):
                    print("  Privilege: administrator/root required; separate --allow-elevation consent is required")
                if action.get("expected_impact"):
                    print(f"  Impact: {action['expected_impact']}")
            for item in tool_plan["manual"]:
                print(f"- {item['tool_id']}: manual installation ({item['reason']})")
            if ns.install_tools:
                print(f"External-tool installation result: {result['external_tool_installation']['status']}")
        else:
            print("External security tools are optional; use --tool TOOL_ID to plan curated OS-package installation.")
        print("Unsupported host/package combinations remain manual; WHAXON never guesses package IDs.")
    if ns.install and result["installation"]["status"] != "VERIFIED":
        return 1
    if ns.install_tools and result["external_tool_installation"]["status"] != "VERIFIED":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
