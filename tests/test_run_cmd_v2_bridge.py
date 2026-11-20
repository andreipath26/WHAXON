"""The CLI V2 bridge must not invent authorization or fall back to ToolRunner."""
import pytest

from whaxon.interfaces.cli import run_cmd, workflow_cmd


def test_explicit_v2_plan_delegates_to_workflow_service(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(workflow_cmd, "main", lambda args: calls.append(args) or 0)
    monkeypatch.setattr(run_cmd, "Core", lambda **kwargs: pytest.fail("legacy Core initialized"))
    run_cmd.main(["--v2-plan", "existing-plan", "--data", str(tmp_path)])
    assert calls == [["--data-dir", str(tmp_path), "plan", "run", "--id", "existing-plan"]]


@pytest.mark.parametrize("arguments", [
    ["--extra", "-sV"], ["--allow-out-of-scope"],
    ["--extra", "-sV", "--allow-out-of-scope"],
    ["--timeout", "30"], ["--quiet"], ["--json"], ["--verbose"],
])
def test_v2_plan_rejects_legacy_overrides(monkeypatch, tmp_path, arguments):
    monkeypatch.setattr(workflow_cmd, "main", lambda args: pytest.fail("V2 invoked"))
    monkeypatch.setattr(run_cmd, "Core", lambda **kwargs: pytest.fail("legacy Core initialized"))
    with pytest.raises(SystemExit) as exc:
        run_cmd.main(["--v2-plan", "existing-plan", "--data", str(tmp_path), *arguments])
    assert exc.value.code == run_cmd.EXIT_USAGE


def test_v2_plan_propagates_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(workflow_cmd, "main", lambda args: 1)
    with pytest.raises(SystemExit) as exc:
        run_cmd.main(["--v2-plan", "existing-plan", "--data", str(tmp_path)])
    assert exc.value.code == 1
