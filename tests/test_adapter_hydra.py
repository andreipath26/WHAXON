"""Hydra adapter: parses credential-attack success lines."""
from whaxon.adapters.hydra import HydraAdapter


def test_parses_success_line():
    lines = [
        ("stdout", "[80][http-post-form] host: 172.17.0.3   login: admin   password: password"),
    ]
    out = HydraAdapter().parse(lines, ctx={"target": "172.17.0.3"})
    assert len(out) == 1
    f = out[0]
    assert f.kind == "weak_credential"
    assert f.severity == "high"
    assert f.data["login"] == "admin"
    assert f.data["password"] == "password"
    assert f.data["port"] == 80


def test_dedupes_repeated_line():
    line = ("stdout", "[80][http-post-form] host: 1.2.3.4   login: a   password: b")
    out = HydraAdapter().parse([line, line], ctx={})
    assert len(out) == 1


def test_ignores_non_success_lines():
    lines = [
        ("stdout", "[DATA] max 16 tasks per 1s"),
        ("stdout", "[STATUS] 12 tries, 11 failed"),
        ("stdout", "[80][http-post-form] host: 1.2.3.4   login: a   password: b"),
    ]
    out = HydraAdapter().parse(lines, ctx={})
    assert len(out) == 1




def test_parses_real_output_with_misc_segment():
    line = (
        "stdout",
        "[80][http-post-form] host: 172.17.0.3   misc: /login.php:username=^USER^&password=^PASS^&Login=Login:F=Login failed   login: admin   password: admin",
    )
    out = HydraAdapter().parse([line], ctx={})
    assert len(out) == 1
    assert out[0].data["login"] == "admin"
    assert out[0].data["password"] == "admin"
