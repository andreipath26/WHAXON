from __future__ import annotations

import json

import pytest

from whaxon.interfaces.cli import setup_cmd


def test_core_profile_contains_required_runtime_and_packages(monkeypatch):
    monkeypatch.setattr(
        setup_cmd, "detect_setup_environment",
        lambda: {"system": "Linux", "package_managers": [], "safety": {"read_only": True}},
    )
    result = setup_cmd.build_setup_plan("core")
    assert result["capabilities"] == ["core"]
    assert result["execution"]["status"] == "PREVIEW_ONLY"
    assert result["execution"]["commands_executed"] is False
    assert result["limitations"]


def test_custom_profile_requires_capability():
    with pytest.raises(ValueError, match="requires at least one"):
        setup_cmd.build_setup_plan("custom")


def test_custom_profile_rejects_unknown_capability():
    with pytest.raises(ValueError, match="unknown capabilities"):
        setup_cmd.build_setup_plan("custom", ["made-up"])


def test_setup_cli_json_is_valid_and_preview_only(capsys, monkeypatch):
    monkeypatch.setattr(
        setup_cmd, "detect_setup_environment",
        lambda: {"system": "Linux", "release": "test", "architecture": "x86_64",
                 "package_managers": [], "support_status": "linux-manual", "wsl": False,
                 "safety": {"read_only": True}},
    )
    assert setup_cmd.main(["--profile", "core", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["execution"]["status"] == "PREVIEW_ONLY"
    assert result["execution"]["commands_executed"] is False


@pytest.mark.parametrize(
    ("profile", "expected"),
    [
        ("standard", {"core", "tui", "web"}),
        ("full", {"core", "tui", "web", "gui", "metasploit"}),
    ],
)
def test_named_profiles_expand_to_known_capabilities(profile, expected):
    result = setup_cmd.build_setup_plan(profile)
    assert set(result["capabilities"]) == expected


def test_custom_profile_deduplicates_capabilities():
    result = setup_cmd.build_setup_plan("custom", ["core", "core"])
    assert result["capabilities"] == ["core"]


def test_create_virtual_environment_creates_isolated_python(tmp_path):
    target = setup_cmd.create_virtual_environment(tmp_path / "fresh-venv")
    assert (target / "pyvenv.cfg").is_file()
    if __import__("os").name == "nt":
        assert (target / "Scripts" / "python.exe").is_file()
    else:
        assert (target / "bin" / "python").is_file()


def test_create_virtual_environment_refuses_to_overwrite(tmp_path):
    target = tmp_path / "existing"
    target.mkdir()
    sentinel = target / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        setup_cmd.create_virtual_environment(target)
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_setup_cli_create_venv_prints_activation_instructions(tmp_path, capsys):
    target = tmp_path / "new-venv"
    assert setup_cmd.main(["--create-venv", "--venv-path", str(target)]) == 0
    output = capsys.readouterr().out
    assert "Created virtual environment" in output
    assert "Activate it with" in output
    assert "whaxon doctor" in output


def test_setup_install_returns_failure_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(
        setup_cmd, "build_setup_plan",
        lambda *_args: {
            "profile": "core",
            "capabilities": ["core"],
            "environment": {"system": "Linux", "release": "test", "architecture": "x86_64",
                            "package_managers": []},
            "dependency_plan": {"plan_id": "plan-reviewed", "actions": []},
            "execution": {"status": "PREVIEW_ONLY"},
        },
    )
    monkeypatch.setattr(
        setup_cmd, "load_dependency_manifest",
        lambda: {"profiles": {"core": ["platformdirs"]}},
    )
    monkeypatch.setattr(
        setup_cmd, "apply_approved_dependency_batch",
        lambda *_args: {"status": "PARTIAL_FAILURE", "completed": [], "remaining": ["platformdirs"]},
    )
    assert setup_cmd.main(["--install", "--approve", "plan-reviewed"]) == 1
    assert "PARTIAL_FAILURE" in capsys.readouterr().out


def test_create_virtual_environment_refuses_dangling_symlink(tmp_path):
    target = tmp_path / "venv-link"
    target.symlink_to(tmp_path / "not-created", target_is_directory=True)
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        setup_cmd.create_virtual_environment(target)
    assert target.is_symlink()


def test_windows_activation_instructions_cover_powershell_and_cmd(tmp_path):
    commands = setup_cmd._activation_instructions(tmp_path / "venv", platform_name="win32")
    assert len(commands) == 2
    assert "Activate.ps1" in commands[0]
    assert "activate.bat" in commands[1]


def test_posix_activation_instructions_use_source(tmp_path):
    commands = setup_cmd._activation_instructions(tmp_path / "venv", platform_name="linux")
    assert commands == [f"source {tmp_path / 'venv'}/bin/activate"]


def test_posix_activation_instructions_quote_paths_with_spaces(tmp_path):
    import shlex

    venv_path = tmp_path / "venv with spaces"
    command = setup_cmd._activation_instructions(venv_path, platform_name="linux")[0]
    assert command.startswith("source ")
    assert shlex.split(command.removeprefix("source ")) == [
        str(venv_path / "bin" / "activate")
    ]


def test_powershell_activation_escapes_single_quotes_in_paths(tmp_path):
    venv_path = tmp_path / "andrei's venv"
    command = setup_cmd._activation_instructions(venv_path, platform_name="win32")[0]
    assert "andrei''s venv" in command


def test_setup_install_passes_exact_selected_profile_dependencies(monkeypatch, capsys):
    plan = {
        "profile": "custom",
        "capabilities": ["core", "web"],
        "environment": {"system": "Linux", "release": "test", "architecture": "x86_64",
                        "package_managers": []},
        "dependency_plan": {"plan_id": "plan-custom-reviewed", "actions": []},
        "execution": {"status": "PREVIEW_ONLY"},
    }
    monkeypatch.setattr(setup_cmd, "build_setup_plan", lambda *_args: plan)
    monkeypatch.setattr(
        setup_cmd, "load_dependency_manifest",
        lambda: {"profiles": {"core": ["python", "platformdirs"], "web": ["flask"]}},
    )
    calls = []
    def apply(ids, plan_id):
        calls.append((ids, plan_id))
        return {"status": "VERIFIED", "completed": [], "remaining": []}
    monkeypatch.setattr(setup_cmd, "apply_approved_dependency_batch", apply)
    assert setup_cmd.main([
        "--profile", "custom", "--capability", "core", "--capability", "web",
        "--install", "--approve", "plan-custom-reviewed",
    ]) == 0
    assert calls == [(["flask", "platformdirs", "python"], "plan-custom-reviewed")]
    assert "Installation result: VERIFIED" in capsys.readouterr().out



def test_setup_cli_external_tool_preview_is_read_only(monkeypatch, capsys):
    monkeypatch.setattr(
        setup_cmd, "build_setup_plan",
        lambda *_args: {
            "profile": "core",
            "capabilities": ["core"],
            "environment": {"system": "Darwin", "release": "test", "architecture": "arm64",
                            "package_managers": []},
            "dependency_plan": {"plan_id": "plan-0123456789abcdef", "actions": []},
            "execution": {"status": "PREVIEW_ONLY"},
        },
    )
    monkeypatch.setattr(
        setup_cmd, "build_external_tool_plan",
        lambda ids, **kwargs: {
            "plan_id": "tools-0123456789abcdef",
            "actions": [{
                "tool_id": "nmap", "status": "MISSING", "package_id": "nmap",
                "command_argv": ["/opt/homebrew/bin/brew", "install", "nmap"],
                "source": "Homebrew formula repository",
                "network_access_required": True,
                "requires_privilege": False,
                "expected_impact": "package and dependencies",
            }],
            "manual": [],
        },
    )
    assert setup_cmd.main(["--tool", "nmap", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["external_tool_plan"]["plan_id"] == "tools-0123456789abcdef"
    assert result["external_tool_plan"]["actions"][0]["package_id"] == "nmap"

    assert setup_cmd.main(["--tool", "nmap"]) == 0
    output = capsys.readouterr().out
    assert "Command: /opt/homebrew/bin/brew install nmap" in output
    assert "Source: Homebrew formula repository" in output
    assert "Network: required" in output
    assert "Impact: package and dependencies" in output


def test_setup_cli_reports_verify_only_commands_without_network(monkeypatch, capsys):
    monkeypatch.setattr(
        setup_cmd, "build_setup_plan",
        lambda *_args: {
            "profile": "core",
            "capabilities": ["core"],
            "environment": {"system": "Darwin", "release": "test", "architecture": "arm64",
                            "package_managers": []},
            "dependency_plan": {"plan_id": "plan-0123456789abcdef", "actions": []},
            "execution": {"status": "PREVIEW_ONLY"},
        },
    )
    monkeypatch.setattr(
        setup_cmd, "build_external_tool_plan",
        lambda ids, **kwargs: {"plan_id": "tools-0123456789abcdef", "actions": [
            {"tool_id": "nmap", "status": "DETECTED", "package_id": None}
        ], "manual": []},
    )
    monkeypatch.setattr(
        setup_cmd, "apply_approved_external_tool_plan",
        lambda *args, **kwargs: {
            "status": "VERIFIED", "installed": [], "commands_executed": True,
            "network_accessed": False, "package_installation_attempted": False,
            "privilege_escalation_attempted": False,
        },
    )
    assert setup_cmd.main([
        "--tool", "nmap", "--install-tools",
        "--approve-tools", "tools-0123456789abcdef", "--allow-system-changes", "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["execution"]["commands_executed"] is True
    assert payload["execution"]["network_accessed"] is False
    assert payload["execution"]["automated_os_package_installation"] is False


def test_setup_cli_external_tool_install_requires_explicit_flags(capsys):
    with pytest.raises(SystemExit) as error:
        setup_cmd.main(["--tool", "nmap", "--install-tools"])
    assert error.value.code == 2
    assert "--approve-tools PLAN_ID" in capsys.readouterr().err


def test_setup_cli_external_tool_install_uses_exact_plan_and_consents(monkeypatch, capsys):
    monkeypatch.setattr(
        setup_cmd, "build_setup_plan",
        lambda *_args: {
            "profile": "core",
            "capabilities": ["core"],
            "environment": {"system": "Darwin", "release": "test", "architecture": "arm64",
                            "package_managers": []},
            "dependency_plan": {"plan_id": "plan-0123456789abcdef", "actions": []},
            "execution": {"status": "PREVIEW_ONLY"},
        },
    )
    monkeypatch.setattr(
        setup_cmd, "build_external_tool_plan",
        lambda ids, **kwargs: {"plan_id": "tools-0123456789abcdef", "actions": [], "manual": []},
    )
    calls = []
    monkeypatch.setattr(
        setup_cmd, "apply_approved_external_tool_plan",
        lambda ids, plan_id, **kwargs: calls.append((ids, plan_id, kwargs)) or {"status": "VERIFIED"},
    )
    assert setup_cmd.main([
        "--tool", "nmap", "--install-tools",
        "--approve-tools", "tools-0123456789abcdef",
        "--allow-system-changes", "--allow-elevation",
    ]) == 0
    assert calls == [(
        ["nmap"], "tools-0123456789abcdef",
        {"allow_system_changes": True, "allow_elevation": True},
    )]
    assert "External-tool installation result: VERIFIED" in capsys.readouterr().out
