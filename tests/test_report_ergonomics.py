"""Tests for report ergonomics: --open, --clipboard, --all-findings.

The --open and --clipboard tests mock the underlying subprocess calls
so they don't depend on X11/Wayland being available in CI. The
--all-findings test constructs a synthetic engagement with medium/low
findings and asserts the extra sections appear.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from whaxon.core.report import to_markdown
from tests.conftest import make_report_dict
from whaxon.interfaces.cli import report_cmd


def _seed(tmp_path: Path) -> None:
    repo_data = Path(__file__).resolve().parents[1] / "data"
    if (repo_data / "tools.json").exists():
        shutil.copy(repo_data / "tools.json", tmp_path / "tools.json")


def _seed_all_severities(store):
    """One finding per severity, distinct ports so dedup keeps all five."""
    store.create("j1")
    store.set_started("j1", "nmap", "10.0.0.5")
    for i, (sev, port) in enumerate([
        ("critical", 22), ("high", 443), ("medium", 8080),
        ("low", 8081), ("info", 9000),
    ]):
        store.append_finding("j1", {
            "kind": "open_port", "severity": sev, "source": "nmap",
            "data": {"port": port}, "raw_line": str(port) + "/tcp",
        }, i)
    store.set_finished("j1", 0, 0.0)


# ---------------------------------------------------------------- to_markdown flag

def test_to_markdown_default_shows_only_critical_and_high(tmp_path):
    md = to_markdown(make_report_dict(tmp_path, _seed_all_severities))
    assert "### Critical (" in md
    assert "### High (" in md
    assert "### Medium (" not in md
    assert "### Low (" not in md
    assert "### Info (" not in md


def test_to_markdown_all_findings_shows_every_severity(tmp_path):
    md = to_markdown(make_report_dict(tmp_path, _seed_all_severities), all_findings=True)
    assert "### Critical (" in md
    assert "### High (" in md
    assert "### Medium (" in md
    assert "### Low (" in md
    assert "### Info (" in md


# ---------------------------------------------------------------- --all-findings CLI

def test_cli_all_findings_flag_accepted(tmp_path, capsys):
    _seed(tmp_path)
    out = tmp_path / "r.md"
    report_cmd.main(["--all", "--format", "md", "--out", str(out),
                     "--all-findings", "--data", str(tmp_path)])
    # If we got here without SystemExit, the flag was accepted
    assert out.exists()


# ---------------------------------------------------------------- --open mocking

def test_open_calls_xdg_open(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    calls: list = []

    def fake_popen(cmd, **kw):
        calls.append(cmd)
        class _P:
            pass
        return _P()

    import shutil as _sh
    monkeypatch.setattr(_sh, "which", lambda name: f"/usr/bin/{name}" if name == "xdg-open" else None)
    import subprocess as _sp
    monkeypatch.setattr(_sp, "Popen", fake_popen)

    out = tmp_path / "r.md"
    report_cmd.main(["--all", "--format", "md", "--out", str(out),
                     "--open", "--data", str(tmp_path)])
    assert calls, "xdg-open was not invoked"
    assert calls[0][0].endswith("xdg-open")


def test_open_warns_when_no_opener(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    import shutil as _sh
    monkeypatch.setattr(_sh, "which", lambda name: None)

    out = tmp_path / "r.md"
    report_cmd.main(["--all", "--format", "md", "--out", str(out),
                     "--open", "--data", str(tmp_path)])
    err = capsys.readouterr().err
    assert "open:" in err


# ---------------------------------------------------------------- --clipboard mocking

def test_clipboard_calls_xclip(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    calls: list = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw.get("input")))
        class _R:
            returncode = 0
        return _R()

    import shutil as _sh
    monkeypatch.setattr(_sh, "which", lambda name: "/usr/bin/xclip" if name == "xclip" else None)
    import subprocess as _sp
    monkeypatch.setattr(_sp, "run", fake_run)

    out = tmp_path / "r.md"
    report_cmd.main(["--all", "--format", "md", "--out", str(out),
                     "--clipboard", "--data", str(tmp_path)])
    assert calls, "xclip was not invoked"
    assert calls[0][0][0].endswith("xclip")
    assert b"WHAXON Engagement Report" in (calls[0][1] or b"")


def test_clipboard_refused_for_pdf(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    out = tmp_path / "r.pdf"
    report_cmd.main(["--all", "--format", "pdf", "--out", str(out),
                     "--clipboard", "--data", str(tmp_path)])
    err = capsys.readouterr().err
    assert "not supported for binary formats" in err


def test_clipboard_warns_when_no_tool(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    import shutil as _sh
    monkeypatch.setattr(_sh, "which", lambda name: None)

    out = tmp_path / "r.md"
    report_cmd.main(["--all", "--format", "md", "--out", str(out),
                     "--clipboard", "--data", str(tmp_path)])
    err = capsys.readouterr().err
    assert "clipboard:" in err
    assert "no clipboard tool" in err