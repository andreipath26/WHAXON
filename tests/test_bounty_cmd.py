"""whaxon bounty CLI: policy init/list/validate, run gate (§26.1)."""
from __future__ import annotations

import json
from pathlib import Path

from whaxon.interfaces.cli import bounty_cmd

_PAGE = """Public programs
Moneybox Bug Bounty
Last update on 2026-05-26
Max reward
\u20ac2,000
Critical
\u20ac50
\u20ac50
\u20ac500
\u20ac1,000
\u20ac2,000
High
\u20ac100
\u20ac300
\u20ac800
\u20ac1,200
https://api.moneyboxapp.com
API
Critical
https://admin.moneyboxapp.org
Web application
Critical
Please append to your user-agent header the following value: ' bugbounty-0421 '.
Do not use automated scanners or tools that generate large amount of network traffic
"""


def _init(tmp: Path, monkeypatch) -> int:
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(_PAGE))
    return bounty_cmd.main(["--data", str(tmp), "policy", "init",
                            "moneybox", "--from-clipboard"])


def test_policy_init_writes_valid_file(tmp_path: Path, monkeypatch, capsys) -> None:
    rc = _init(tmp_path, monkeypatch)
    assert rc == 0
    out = capsys.readouterr().out
    assert "wrote" in out
    assert (tmp_path / "programs" / "moneybox.json").exists()


def test_policy_list_and_validate(tmp_path: Path, monkeypatch, capsys) -> None:
    _init(tmp_path, monkeypatch)
    assert bounty_cmd.main(["--data", str(tmp_path), "policy", "list"]) == 0
    out = capsys.readouterr().out
    assert "moneybox" in out
    assert bounty_cmd.main(["--data", str(tmp_path), "policy", "validate", "moneybox"]) == 0


def test_validate_missing_policy_refuses(tmp_path: Path, capsys) -> None:
    rc = bounty_cmd.main(["--data", str(tmp_path), "policy", "validate", "nope"])
    assert rc == bounty_cmd.EXIT_POLICY


def test_run_refuses_without_policy(tmp_path: Path, capsys) -> None:
    rc = bounty_cmd.main(["--data", str(tmp_path), "run", "api.moneyboxapp.com",
                          "--", "nmap"])
    assert rc == bounty_cmd.EXIT_POLICY
    assert "no program policy matches" in capsys.readouterr().err


def test_run_allows_permitted_tool(tmp_path: Path, monkeypatch, capsys) -> None:
    _init(tmp_path, monkeypatch)
    rc = bounty_cmd.main(["--data", str(tmp_path), "run", "api.moneyboxapp.com",
                          "--", "curl"])
    assert rc == 0
    assert "permits curl" in capsys.readouterr().out


def test_run_refuses_denylisted_tool(tmp_path: Path, monkeypatch, capsys) -> None:
    _init(tmp_path, monkeypatch)
    rc = bounty_cmd.main(["--data", str(tmp_path), "run", "api.moneyboxapp.com",
                          "--", "nmap"])
    assert rc == bounty_cmd.EXIT_POLICY
    assert "denylist" in capsys.readouterr().err


def test_run_refuses_tool_missing_from_allowlist(tmp_path: Path, monkeypatch, capsys) -> None:
    _init(tmp_path, monkeypatch)
    path = tmp_path / "programs" / "moneybox.json"
    policy = json.loads(path.read_text(encoding="utf-8"))
    policy["tools"] = {"mode": "allowlist", "allowlist": [], "denylist": []}
    path.write_text(json.dumps(policy), encoding="utf-8")
    rc = bounty_cmd.main(["--data", str(tmp_path), "run", "api.moneyboxapp.com",
                          "--", "curl"])
    assert rc == bounty_cmd.EXIT_POLICY
    assert "not on" in capsys.readouterr().err


def test_run_allows_only_tools_in_allowlist(tmp_path: Path, monkeypatch, capsys) -> None:
    _init(tmp_path, monkeypatch)
    path = tmp_path / "programs" / "moneybox.json"
    policy = json.loads(path.read_text(encoding="utf-8"))
    policy["tools"] = {"mode": "allowlist", "allowlist": ["curl"], "denylist": []}
    path.write_text(json.dumps(policy), encoding="utf-8")
    rc = bounty_cmd.main(["--data", str(tmp_path), "run", "api.moneyboxapp.com",
                          "--", "curl"])
    assert rc == 0
    assert "permits curl" in capsys.readouterr().out
