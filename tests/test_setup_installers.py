from __future__ import annotations

from types import SimpleNamespace

import pytest

import whaxon.core.setup_installers as installers


@pytest.fixture(autouse=True)
def isolate_external_install_audit(monkeypatch):
    monkeypatch.setattr(
        "whaxon.core.installer.record_dependency_install_event",
        lambda event: None,
    )


def _host():
    return {
        "system": "Darwin",
        "architecture": "arm64",
        "package_managers": [{"id": "brew", "executable": "/opt/homebrew/bin/brew"}],
        "support_status": "macos-curated-installer-available",
        "supported_installers": ["brew"],
        "wsl": False,
        "safety": {"read_only": True, "commands_executed": False},
    }


def _report(status: str):
    return {
        "dependencies": [{
            "id": "nmap",
            "kind": "external-tool",
            "status": status,
            "detected_path": "/opt/homebrew/bin/nmap" if status == "READY" else None,
        }]
    }


def test_external_tool_plan_is_read_only_and_uses_curated_mapping(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    report_calls = []

    def report(**kwargs):
        report_calls.append(kwargs)
        return _report("MISSING")

    monkeypatch.setattr(installers, "collect_dependency_report", report)
    plan = installers.build_external_tool_plan(["nmap"], which=lambda _: "/opt/homebrew/bin/brew")
    assert report_calls[0]["verify_external"] is False
    assert plan["actions"] == [{
        "tool_id": "nmap",
        "status": "MISSING",
        "package_manager": "brew",
        "package_id": "nmap",
        "binary": "nmap",
        "command_argv": ["/opt/homebrew/bin/brew", "install", "nmap"],
        "source": "Homebrew formula repository",
        "network_access_required": True,
        "expected_impact": (
            "Installs the selected package and any dependencies resolved by "
            "the host package manager; exact download and disk sizes depend "
            "on the configured repositories and are reported by that manager."
        ),
        "requires_privilege": False,
    }]
    assert plan["safety"]["read_only"] is True
    assert plan["safety"]["commands_executed"] is False


def test_external_tool_plan_rejects_duplicate_and_unknown_selection():
    with pytest.raises(ValueError, match="unique"):
        installers.build_external_tool_plan(["nmap", "nmap"])
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    monkeypatch.setattr(installers, "collect_dependency_report", lambda **kwargs: {"dependencies": []})
    plan = installers.build_external_tool_plan(["unknown_tool"], which=lambda _: "/opt/homebrew/bin/brew")
    assert plan["manual"][0]["tool_id"] == "unknown_tool"
    monkeypatch.undo()


def test_external_tool_preview_does_not_run_version_probe_for_detected_binary(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    calls = []

    def report(**kwargs):
        calls.append(kwargs["verify_external"])
        return {
            "dependencies": [{
                "id": "nmap",
                "kind": "external-tool",
                "status": "DETECTED",
                "detected_path": "/opt/homebrew/bin/nmap",
            }]
        }

    monkeypatch.setattr(installers, "collect_dependency_report", report)
    plan = installers.build_external_tool_plan(["nmap"], which=lambda _: "/opt/homebrew/bin/brew")
    assert calls == [False]
    assert plan["actions"] == [{
        "tool_id": "nmap",
        "status": "DETECTED",
        "package_id": None,
        "binary": "/opt/homebrew/bin/nmap",
    }]
    assert plan["safety"]["commands_executed"] is False


def test_detected_external_tool_is_verified_only_after_explicit_approval(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    calls = []

    def report(**kwargs):
        calls.append(kwargs["verify_external"])
        return {
            "dependencies": [{
                "id": "nmap",
                "kind": "external-tool",
                "status": "READY" if kwargs["verify_external"] else "DETECTED",
                "detected_path": "/opt/homebrew/bin/nmap",
            }]
        }

    monkeypatch.setattr(installers, "collect_dependency_report", report)
    preview = installers.build_external_tool_plan(["nmap"], which=lambda _: "/opt/homebrew/bin/brew")
    assert calls == [False]
    result = installers.apply_approved_external_tool_plan(
        ["nmap"], preview["plan_id"], allow_system_changes=True,
        which=lambda _: "/opt/homebrew/bin/brew",
    )
    assert result["status"] == "VERIFIED"
    assert result["installed"] == []
    assert calls == [False, False, True]


def test_external_tool_install_requires_exact_approval_and_explicit_consent(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    monkeypatch.setattr(installers, "collect_dependency_report", lambda **kwargs: _report("MISSING"))
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0)
    with pytest.raises(ValueError, match="explicit --allow-system-changes"):
        installers.apply_approved_external_tool_plan(
            ["nmap"], "tools-0000000000000000", runner=runner
        )
    with pytest.raises(ValueError, match="does not match"):
        installers.apply_approved_external_tool_plan(
            ["nmap"], "tools-0000000000000000",
            allow_system_changes=True, runner=runner,
        )
    assert calls == []


def test_external_tool_install_executes_fixed_argv_and_verifies(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    states = iter(("MISSING", "MISSING", "READY"))
    monkeypatch.setattr(
        installers, "collect_dependency_report",
        lambda **kwargs: _report(next(states)),
    )
    preview = installers.build_external_tool_plan(["nmap"], which=lambda _: "/opt/homebrew/bin/brew")
    commands = []
    def runner(argv, **kwargs):
        commands.append((argv, kwargs))
        return SimpleNamespace(returncode=0)
    result = installers.apply_approved_external_tool_plan(
        ["nmap"], preview["plan_id"],
        allow_system_changes=True, runner=runner,
        which=lambda _: "/opt/homebrew/bin/brew",
    )
    assert result["status"] == "VERIFIED"
    assert result["installed"] == ["nmap"]
    assert commands[0][0] == ["/opt/homebrew/bin/brew", "install", "nmap"]
    assert commands[0][1]["shell"] is False
    assert commands[0][1]["timeout"] == 1800


def test_external_tool_install_stops_after_package_manager_failure(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    monkeypatch.setattr(installers, "collect_dependency_report", lambda **kwargs: _report("MISSING"))
    preview = installers.build_external_tool_plan(["nmap"], which=lambda _: "/opt/homebrew/bin/brew")
    result = installers.apply_approved_external_tool_plan(
        ["nmap"], preview["plan_id"], allow_system_changes=True,
        runner=lambda *args, **kwargs: SimpleNamespace(returncode=1),
        which=lambda _: "/opt/homebrew/bin/brew",
    )
    assert result["status"] == "FAILED"
    assert result["installed"] == []
    assert result["failed_tool"] == "nmap"



def test_external_tool_install_reports_timeout_without_claiming_success(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    monkeypatch.setattr(installers, "collect_dependency_report", lambda **kwargs: _report("MISSING"))
    preview = installers.build_external_tool_plan(["nmap"], which=lambda _: "/opt/homebrew/bin/brew")

    def timeout_runner(*args, **kwargs):
        raise installers.subprocess.TimeoutExpired(args[0], 1800)

    result = installers.apply_approved_external_tool_plan(
        ["nmap"], preview["plan_id"], allow_system_changes=True,
        runner=timeout_runner, which=lambda _: "/opt/homebrew/bin/brew",
    )
    assert result["status"] == "FAILED"
    assert result["installed"] == []
    assert "30-minute timeout" in result["message"]



def test_external_tool_install_audits_approval_action_and_terminal_result(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    states = iter(("MISSING", "MISSING", "READY"))
    monkeypatch.setattr(
        installers, "collect_dependency_report",
        lambda **kwargs: _report(next(states)),
    )
    events = []
    monkeypatch.setattr(
        "whaxon.core.installer.record_dependency_install_event",
        lambda event: events.append(event),
    )
    preview = installers.build_external_tool_plan(["nmap"], which=lambda _: "/opt/homebrew/bin/brew")

    def runner(argv, **kwargs):
        return SimpleNamespace(returncode=0)

    result = installers.apply_approved_external_tool_plan(
        ["nmap"], preview["plan_id"], allow_system_changes=True,
        runner=runner, which=lambda _: "/opt/homebrew/bin/brew",
    )
    assert result["status"] == "VERIFIED"
    assert [event["event_type"] for event in events] == [
        "EXTERNAL_TOOL_APPROVAL_ACCEPTED",
        "EXTERNAL_TOOL_ACTION_STARTED",
        "EXTERNAL_TOOL_BATCH_FINISHED",
    ]
    assert events[0]["plan_id"] == preview["plan_id"]


def test_external_tool_install_refuses_to_run_when_approval_audit_fails(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    monkeypatch.setattr(installers, "collect_dependency_report", lambda **kwargs: _report("MISSING"))
    monkeypatch.setattr(
        "whaxon.core.installer.record_dependency_install_event",
        lambda event: (_ for _ in ()).throw(OSError("audit unavailable")),
    )
    preview = installers.build_external_tool_plan(["nmap"], which=lambda _: "/opt/homebrew/bin/brew")
    commands = []

    def runner(argv, **kwargs):
        commands.append(argv)
        return SimpleNamespace(returncode=0)

    with pytest.raises(OSError, match="audit unavailable"):
        installers.apply_approved_external_tool_plan(
            ["nmap"], preview["plan_id"], allow_system_changes=True,
            runner=runner, which=lambda _: "/opt/homebrew/bin/brew",
        )
    assert commands == []


def test_external_tool_install_does_not_claim_verified_when_final_audit_fails(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    states = iter(("MISSING", "MISSING", "READY"))
    monkeypatch.setattr(
        installers, "collect_dependency_report",
        lambda **kwargs: _report(next(states)),
    )
    events = []

    def audit(event):
        events.append(event)
        if event["event_type"] == "EXTERNAL_TOOL_BATCH_FINISHED":
            raise OSError("audit unavailable")

    monkeypatch.setattr("whaxon.core.installer.record_dependency_install_event", audit)
    preview = installers.build_external_tool_plan(["nmap"], which=lambda _: "/opt/homebrew/bin/brew")

    def runner(argv, **kwargs):
        return SimpleNamespace(returncode=0)

    result = installers.apply_approved_external_tool_plan(
        ["nmap"], preview["plan_id"], allow_system_changes=True,
        runner=runner, which=lambda _: "/opt/homebrew/bin/brew",
    )
    assert result["status"] == "AUDIT_FAILED"
    assert result["original_status"] == "VERIFIED"



def test_command_builder_rejects_package_substitution_within_manager():
    action = {
        "tool_id": "nmap",
        "package_manager": "brew",
        "package_id": "sqlmap",
    }
    with pytest.raises(ValueError, match="tool-to-package allowlist"):
        installers._command_for_action(action, "/opt/homebrew/bin/brew", allow_elevation=False)


def test_command_builder_rejects_unknown_manager_and_package_pair():
    action = {
        "tool_id": "nmap",
        "package_manager": "winget",
        "package_id": "nmap",
    }
    with pytest.raises(ValueError, match="tool-to-package allowlist"):
        installers._command_for_action(action, "winget", allow_elevation=False)



def test_apt_mapping_requires_an_explicitly_supported_linux_distribution(monkeypatch):
    host = {
        "system": "Linux",
        "architecture": "x86_64",
        "distribution_id": "arch",
        "package_managers": [{"id": "apt", "executable": "/usr/bin/apt-get"}],
        "support_status": "linux-manual",
        "supported_installers": [],
        "wsl": False,
        "safety": {"read_only": True, "commands_executed": False},
    }
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: host)
    monkeypatch.setattr(installers, "collect_dependency_report", lambda **kwargs: _report("MISSING"))
    unsupported = installers.build_external_tool_plan(
        ["nmap"], system="Linux", which=lambda _: "/usr/bin/apt-get"
    )
    assert unsupported["actions"] == []
    assert unsupported["manual"][0]["tool_id"] == "nmap"
    assert "No curated package mapping" in unsupported["manual"][0]["reason"]

    host["distribution_id"] = "debian"
    host["supported_installers"] = ["apt"]
    supported = installers.build_external_tool_plan(
        ["nmap"], system="Linux", which=lambda _: "/usr/bin/apt-get", is_root=True
    )
    assert supported["actions"][0]["package_manager"] == "apt"
    assert supported["actions"][0]["package_id"] == "nmap"



def test_external_tool_plan_id_binds_linux_distribution(monkeypatch):
    host = {
        "system": "Linux",
        "architecture": "x86_64",
        "distribution_id": "debian",
        "package_managers": [{"id": "apt", "executable": "/usr/bin/apt-get"}],
        "support_status": "linux-curated-installer-available",
        "supported_installers": ["apt"],
        "wsl": False,
        "safety": {"read_only": True, "commands_executed": False},
    }
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: host)
    monkeypatch.setattr(installers, "collect_dependency_report", lambda **kwargs: _report("MISSING"))

    def which(_name):
        return "/usr/bin/apt-get"

    debian = installers.build_external_tool_plan(
        ["nmap"], system="Linux", which=which, is_root=True
    )
    host["distribution_id"] = "ubuntu"
    ubuntu = installers.build_external_tool_plan(
        ["nmap"], system="Linux", which=which, is_root=True
    )
    assert debian["plan_id"] != ubuntu["plan_id"]


def test_apt_plan_discloses_exact_sudo_command_when_elevation_is_required(monkeypatch):
    host = {
        "system": "Linux",
        "architecture": "x86_64",
        "distribution_id": "debian",
        "package_managers": [{"id": "apt", "executable": "/usr/bin/apt-get"}],
        "support_status": "linux-curated-installer-available",
        "supported_installers": ["apt"],
        "wsl": False,
        "safety": {"read_only": True, "commands_executed": False},
    }
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: host)
    monkeypatch.setattr(installers, "collect_dependency_report", lambda **kwargs: _report("MISSING"))

    def which(name):
        return {
            "apt-get": "/usr/bin/apt-get",
            "sudo": "/usr/bin/sudo",
        }.get(name)

    plan = installers.build_external_tool_plan(
        ["nmap"], system="Linux", which=which, is_root=False
    )
    action = plan["actions"][0]
    assert action["requires_privilege"] is True
    assert action["command_argv"] == [
        "/usr/bin/sudo", "-n", "/usr/bin/apt-get",
        "install", "-y", "--no-install-recommends", "nmap",
    ]


def test_apt_install_requires_separate_elevation_consent_before_audit(monkeypatch):
    monkeypatch.setattr(installers.os, "geteuid", lambda: 1000)
    host = {
        "system": "Linux",
        "architecture": "x86_64",
        "distribution_id": "debian",
        "package_managers": [{"id": "apt", "executable": "/usr/bin/apt-get"}],
        "support_status": "linux-curated-installer-available",
        "supported_installers": ["apt"],
        "wsl": False,
        "safety": {"read_only": True, "commands_executed": False},
    }
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: host)
    states = iter(("MISSING", "MISSING"))
    monkeypatch.setattr(
        installers, "collect_dependency_report",
        lambda **kwargs: _report(next(states)),
    )
    events = []
    monkeypatch.setattr(
        "whaxon.core.installer.record_dependency_install_event",
        lambda event: events.append(event),
    )

    def which(name):
        return {
            "apt-get": "/usr/bin/apt-get",
            "sudo": "/usr/bin/sudo",
        }.get(name)
    preview = installers.build_external_tool_plan(
        ["nmap"], system="Linux", which=which, is_root=False
    )
    with pytest.raises(ValueError, match="explicit --allow-elevation"):
        installers.apply_approved_external_tool_plan(
            ["nmap"], preview["plan_id"], allow_system_changes=True,
            allow_elevation=False, which=which,
        )
    assert events == []


def test_apt_plan_stays_manual_when_sudo_is_unavailable(monkeypatch):
    host = {
        "system": "Linux",
        "architecture": "x86_64",
        "distribution_id": "debian",
        "package_managers": [{"id": "apt", "executable": "/usr/bin/apt-get"}],
        "support_status": "linux-curated-installer-available",
        "supported_installers": ["apt"],
        "wsl": False,
        "safety": {"read_only": True, "commands_executed": False},
    }
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: host)
    monkeypatch.setattr(installers, "collect_dependency_report", lambda **kwargs: _report("MISSING"))
    plan = installers.build_external_tool_plan(
        ["nmap"], system="Linux",
        which=lambda name: "/usr/bin/apt-get" if name == "apt-get" else None,
        is_root=False,
    )
    assert plan["actions"] == []
    assert "sudo is unavailable" in plan["manual"][0]["reason"]


def test_command_builder_requires_exact_reviewed_elevation_argv(monkeypatch):
    monkeypatch.setattr(installers.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(installers.shutil, "which", lambda name: "/usr/bin/sudo")
    action = {
        "tool_id": "nmap",
        "package_manager": "apt",
        "package_id": "nmap",
        "command_argv": [
            "/usr/bin/sudo", "-n", "/usr/bin/apt-get",
            "install", "-y", "--no-install-recommends", "nmap",
        ],
    }
    assert installers._command_for_action(
        action, "/usr/bin/apt-get", allow_elevation=True,
        which=lambda name: "/usr/bin/sudo",
    ) == action["command_argv"]
    action["command_argv"] = ["/usr/bin/apt-get", "install", "nmap"]
    with pytest.raises(ValueError, match="reviewed plan"):
        installers._command_for_action(
            action, "/usr/bin/apt-get", allow_elevation=True
        )


def test_external_tool_install_records_interruption_and_does_not_claim_success(monkeypatch):
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: _host())
    monkeypatch.setattr(installers, "collect_dependency_report", lambda **kwargs: _report("MISSING"))
    preview = installers.build_external_tool_plan(
        ["nmap"], which=lambda _: "/opt/homebrew/bin/brew"
    )

    def interrupted_runner(*args, **kwargs):
        raise KeyboardInterrupt

    result = installers.apply_approved_external_tool_plan(
        ["nmap"], preview["plan_id"], allow_system_changes=True,
        runner=interrupted_runner, which=lambda _: "/opt/homebrew/bin/brew",
    )
    assert result["status"] == "INTERRUPTED"
    assert result["installed"] == []
    assert "partial" in result["message"]



def test_bounded_package_runner_terminates_child_on_keyboard_interrupt(monkeypatch):
    class FakeProcess:
        def __init__(self, *_args, **_kwargs):
            self.returncode = None
            self.terminated = False
        def communicate(self, timeout=None):
            if not self.terminated:
                raise KeyboardInterrupt
            return ("", "")
        def poll(self):
            return self.returncode
        def terminate(self):
            self.terminated = True
            self.returncode = -15
        def kill(self):
            self.returncode = -9

    process = FakeProcess()
    monkeypatch.setattr(installers.subprocess, "Popen", lambda *args, **kwargs: process)
    with pytest.raises(KeyboardInterrupt):
        installers._run_bounded_package_command(
            ["brew", "install", "nmap"],
            shell=False, stdout=installers.subprocess.PIPE,
            stderr=installers.subprocess.PIPE, text=True, timeout=10,
        )
    assert process.terminated is True



def test_offline_host_without_package_manager_gets_manual_plan_without_side_effects(monkeypatch):
    host = {
        "system": "Linux",
        "architecture": "x86_64",
        "distribution_id": "debian",
        "package_managers": [],
        "support_status": "linux-manual",
        "supported_installers": [],
        "wsl": False,
        "safety": {
            "read_only": True,
            "commands_executed": False,
            "network_accessed": False,
            "privilege_escalation_attempted": False,
        },
    }
    monkeypatch.setattr(installers, "detect_setup_environment", lambda **kwargs: host)
    monkeypatch.setattr(
        installers, "collect_dependency_report",
        lambda **kwargs: _report("MISSING"),
    )
    events = []
    monkeypatch.setattr(
        "whaxon.core.installer.record_dependency_install_event",
        lambda event: events.append(event),
    )
    plan = installers.build_external_tool_plan(
        ["nmap"], which=lambda _name: None,
    )
    assert plan["actions"] == []
    assert plan["manual"][0]["tool_id"] == "nmap"
    assert "No curated package mapping" in plan["manual"][0]["reason"]
    assert plan["safety"] == {
        "read_only": True,
        "commands_executed": False,
        "network_accessed": False,
        "privilege_escalation_attempted": False,
    }
    with pytest.raises(ValueError, match="unsupported manual installations"):
        installers.apply_approved_external_tool_plan(
            ["nmap"], plan["plan_id"], allow_system_changes=True,
            runner=lambda *_args, **_kwargs: pytest.fail("offline plan must not execute"),
            which=lambda _name: None,
        )
    assert events == []
