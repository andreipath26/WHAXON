from __future__ import annotations

import json

from whaxon.interfaces.cli import doctor_cmd


def test_focused_doctor_preserves_required_blocker_status(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(
        doctor_cmd,
        "collect_dependency_report",
        lambda **kwargs: {
            "environment": {"os": "Linux", "os_release": "test", "architecture": "x86_64",
                            "python": "3.12", "python_executable": "/venv/bin/python",
                            "virtual_environment": True},
            "overall_status": "BLOCKED",
            "summary": {"total": 1, "ready": 0, "required_blockers": 1},
            "dependencies": [{
                "id": "python", "status": "INCOMPATIBLE", "required": True,
                "detected_version": "3.10", "reason": "too old",
            }],
        },
    )
    result = doctor_cmd.main(["--check", "python", "--json", "--data", str(tmp_path)])
    report = json.loads(capsys.readouterr().out)
    assert result == 1
    assert report["overall_status"] == "BLOCKED"
    assert report["summary"]["required_blockers"] == 1


def test_focused_doctor_optional_degradation_does_not_block(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(
        doctor_cmd,
        "collect_dependency_report",
        lambda **kwargs: {
            "environment": {"os": "Linux", "os_release": "test", "architecture": "x86_64",
                            "python": "3.12", "python_executable": "/venv/bin/python",
                            "virtual_environment": True},
            "overall_status": "DEGRADED",
            "summary": {"total": 1, "ready": 0, "optional_degraded": 1},
            "dependencies": [{
                "id": "textual", "status": "MISSING", "required": False,
                "reason": "optional",
            }],
        },
    )
    result = doctor_cmd.main(["--check", "textual", "--json", "--data", str(tmp_path)])
    report = json.loads(capsys.readouterr().out)
    assert result == 0
    assert report["overall_status"] == "DEGRADED"
    assert report["summary"]["optional_degraded"] == 1


import pytest


@pytest.mark.parametrize(
    "arguments",
    [
        ["--plan", "--verify"],
        ["--plan", "--snapshot"],
        ["--plan", "--drift"],
        ["--plan", "--install", "--check", "textual", "--approve", "plan-0123456789abcdef"],
        ["--verify", "--core-only"],
        ["--install", "--snapshot", "--check", "textual", "--approve", "plan-0123456789abcdef"],
    ],
)
def test_doctor_rejects_conflicting_modes(arguments, capsys):
    with pytest.raises(SystemExit) as error:
        doctor_cmd.main(arguments)
    assert error.value.code == 2
    assert "cannot be combined" in capsys.readouterr().err
