"""CLI approvals + --approvals subcommand."""
from __future__ import annotations

from pathlib import Path

from whaxon.core import Core
from whaxon.interfaces.cli.ai_cmd import _run_show_approvals


def _core(tmp_path: Path) -> Core:
    data = tmp_path / 'data'
    data.mkdir()
    (data / 'tools.json').write_text('{"tools":[]}')
    return Core(data_dir=data)


def test_run_show_approvals_empty(tmp_path: Path, capsys) -> None:
    core = _core(tmp_path)
    core.store.create_ai_run('ai-x', 'goal')
    _run_show_approvals('ai-x', tmp_path / 'data')
    out = capsys.readouterr().out
    assert 'no approvals' in out


def test_run_show_approvals_lists_rows(tmp_path: Path, capsys) -> None:
    core = _core(tmp_path)
    core.store.create_ai_run('ai-x', 'goal')
    core.store.add_approval('ai-x', 1, 'alice', 'y', 'ok')
    core.store.add_approval('ai-x', 2, 'bob', 'n', 'no')
    _run_show_approvals('ai-x', tmp_path / 'data')
    out = capsys.readouterr().out
    assert 'alice' in out
    assert 'bob' in out
    assert 'answer=y' in out
    assert 'answer=n' in out


def test_run_show_approvals_missing_run(tmp_path: Path) -> None:
    import pytest
    _core(tmp_path)
    with pytest.raises(SystemExit):
        _run_show_approvals('nope', tmp_path / 'data')


def test_run_resume_records_approval(tmp_path: Path, monkeypatch) -> None:
    from whaxon.interfaces.cli import ai_cmd
    import pytest
    core = _core(tmp_path)
    core.store.create_ai_run('ai-r', 'goal')
    core.store.append_ai_run_step('ai-r', 1,
        {'kind': 'ask_human', 'rationale': 'q'},
        {'ok': True, 'summary': 'q'})
    # Monkeypatch executor run so we do not actually run tools.
    async def fake_run(self, goal, job_id_prefix='ai', target_lock=None, initial_history=None, resume_state=None):
        from whaxon.ai.actions import Action, ActionResult
        return [ActionResult(action=Action.stop('done', ai_source='test'), ok=True)]
    from whaxon.ai.executor import Executor
    monkeypatch.setattr(Executor, 'run', fake_run)
    monkeypatch.setenv('WHAXON_AI_ENABLED', 'false')
    ai_cmd._run_resume('ai-r', tmp_path / 'data', 5, 'y', user='alice')
    rows = core.store.list_approvals('ai-r')
    assert len(rows) == 1
    assert rows[0]['user'] == 'alice'
    assert rows[0]['answer'] == 'y'

