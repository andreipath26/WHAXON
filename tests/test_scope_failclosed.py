"""Tests for the fail-closed scope policy.

These guard against the specific bug we fixed on 2026-09-27: a missing
or malformed scope.json used to set enabled=false, which made check()
return allowed=True for every target. In a platform that runs exploits,
that is a security hole.

If someone reintroduces fail-open behavior, these tests will fail.
"""
from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from whaxon.core.scope import ScopeManager


def test_missing_config_writes_strict_default(tmp_path: Path) -> None:
    """No scope.json → a strict default is written, and it's enabled."""
    cfg = tmp_path / "scope.json"
    assert not cfg.exists()

    sm = ScopeManager(cfg)

    assert cfg.exists(), "load() must create the default config"
    assert sm.enabled is True, "scope must default to ENABLED, not disabled"

    data = json.loads(cfg.read_text())
    assert data["enabled"] is True
    assert "127.0.0.0/8" in data["in_scope"]
    assert "10.0.0.0/8" in data["in_scope"]
    # RFC1918 ranges must be present
    assert any(r.startswith("192.168") for r in data["in_scope"])
    assert any(r.startswith("172.16") for r in data["in_scope"])


def test_localhost_and_rfc1918_allowed(tmp_path: Path) -> None:
    sm = ScopeManager(tmp_path / "scope.json")

    for host in ("127.0.0.1", "10.0.0.5", "192.168.1.10", "172.16.5.5"):
        m = sm.check(host)
        assert m.allowed is True, f"{host} should be allowed, got {m.reason}"


def test_public_internet_denied(tmp_path: Path) -> None:
    sm = ScopeManager(tmp_path / "scope.json")

    for host in ("8.8.8.8", "1.1.1.1", "google.com", "example.com"):
        m = sm.check(host)
        assert m.allowed is False, f"{host} should be denied, got allowed=True"
        assert m.reason


def test_malformed_config_raises(tmp_path: Path) -> None:
    """Broken JSON must NOT silently disable scope."""
    cfg = tmp_path / "scope.json"
    cfg.write_text("{ this is not valid json")

    with pytest.raises(RuntimeError, match="unreadable"):
        ScopeManager(cfg)


def test_out_of_scope_wins_over_in_scope(tmp_path: Path) -> None:
    cfg = tmp_path / "scope.json"
    cfg.write_text(json.dumps({
        "engagement": "test",
        "enabled": True,
        "in_scope": ["10.0.0.0/8"],
        "out_of_scope": ["10.0.0.5"],
    }))
    sm = ScopeManager(cfg)

    assert sm.check("10.0.0.4").allowed is True
    assert sm.check("10.0.0.5").allowed is False, "out-of-scope must override"


def test_operator_can_disable_explicitly(tmp_path: Path) -> None:
    """If the operator writes enabled:false, scope is genuinely off."""
    cfg = tmp_path / "scope.json"
    cfg.write_text(json.dumps({
        "engagement": "lab",
        "enabled": False,
        "in_scope": ["127.0.0.1"],
        "out_of_scope": [],
    }))
    sm = ScopeManager(cfg)

    assert sm.enabled is False
    assert sm.check("8.8.8.8").allowed is True
    assert "disabled" in sm.check("8.8.8.8").reason


def test_default_scope_includes_ipv6_ranges(tmp_path: Path) -> None:
    """Default scope must cover IPv6 loopback, link-local, and ULA."""
    cfg = tmp_path / "scope.json"
    sm = ScopeManager(cfg)
    data = json.loads(cfg.read_text())
    in_scope = data["in_scope"]
    assert "::1" in in_scope
    assert "fe80::/10" in in_scope
    assert "fc00::/7" in in_scope
    assert sm.enabled is True


def test_default_scope_includes_ipv4_loopback_cidr(tmp_path: Path) -> None:
    cfg = tmp_path / "scope.json"
    ScopeManager(cfg)
    data = json.loads(cfg.read_text())
    assert "127.0.0.0/8" in data["in_scope"]

@pytest.mark.parametrize("invalid_enabled", [None, 0, 1, "", "false", [], {}])
def test_non_boolean_enabled_value_cannot_disable_scope(
    tmp_path: Path, invalid_enabled
) -> None:
    cfg = tmp_path / "scope.json"
    cfg.write_text(json.dumps({
        "engagement": "test",
        "enabled": invalid_enabled,
        "in_scope": ["127.0.0.1"],
        "out_of_scope": [],
    }))

    with pytest.raises(RuntimeError, match="invalid 'enabled'"):
        ScopeManager(cfg)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("in_scope", "127.0.0.1"),
        ("in_scope", [None]),
        ("out_of_scope", 0),
        ("out_of_scope", [""]),
    ],
)
def test_malformed_scope_rules_are_rejected(tmp_path: Path, key: str, value) -> None:
    cfg = tmp_path / "scope.json"
    data = {
        "engagement": "test",
        "enabled": True,
        "in_scope": ["127.0.0.1"],
        "out_of_scope": [],
    }
    data[key] = value
    cfg.write_text(json.dumps(data))

    with pytest.raises(RuntimeError, match=f"invalid '{key}'"):
        ScopeManager(cfg)


def test_non_object_scope_config_is_rejected(tmp_path: Path) -> None:
    cfg = tmp_path / "scope.json"
    cfg.write_text(json.dumps(["enabled", False]))

    with pytest.raises(RuntimeError, match="JSON object"):
        ScopeManager(cfg)


def _dns_answer(ip: str):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def test_hostname_resolution_must_match_ip_scope(tmp_path: Path, monkeypatch) -> None:
    cfg = tmp_path / "scope.json"
    cfg.write_text(json.dumps({
        "engagement": "test",
        "enabled": True,
        "in_scope": ["10.0.0.0/8"],
        "out_of_scope": [],
    }))
    monkeypatch.setattr(
        "whaxon.core.scope.socket.getaddrinfo",
        lambda host, port, type: _dns_answer("203.0.113.8"),
    )
    match = ScopeManager(cfg).check("target.test")
    assert match.allowed is False
    assert "resolved addresses" in match.reason


def test_out_of_scope_resolved_ip_overrides_hostname_allow(
    tmp_path: Path, monkeypatch
) -> None:
    cfg = tmp_path / "scope.json"
    cfg.write_text(json.dumps({
        "engagement": "test",
        "enabled": True,
        "in_scope": ["target.test"],
        "out_of_scope": ["203.0.113.0/24"],
    }))
    monkeypatch.setattr(
        "whaxon.core.scope.socket.getaddrinfo",
        lambda host, port, type: _dns_answer("203.0.113.8"),
    )
    match = ScopeManager(cfg).check("target.test")
    assert match.allowed is False
    assert "out-of-scope rule" in match.reason


def test_hostname_dns_failure_fails_closed(tmp_path: Path, monkeypatch) -> None:
    cfg = tmp_path / "scope.json"
    cfg.write_text(json.dumps({
        "engagement": "test",
        "enabled": True,
        "in_scope": ["target.test"],
        "out_of_scope": ["203.0.113.0/24"],
    }))

    def fail_dns(host, port, type):
        raise socket.gaierror("temporary DNS failure")

    monkeypatch.setattr("whaxon.core.scope.socket.getaddrinfo", fail_dns)
    match = ScopeManager(cfg).check("target.test")
    assert match.allowed is False
    assert "resolution failed" in match.reason

def test_atomic_scope_write_does_not_follow_predictable_temp_symlink(tmp_path: Path) -> None:
    """A pre-created .tmp symlink must not redirect a scope write to another file."""
    from whaxon.core.scope import _atomic_write

    config = tmp_path / "scope.json"
    victim = tmp_path / "victim.txt"
    victim.write_text("do not overwrite", encoding="utf-8")
    predictable_temp = config.with_suffix(config.suffix + ".tmp")
    try:
        predictable_temp.symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available in this environment")

    _atomic_write(config, '{"enabled": true}')

    assert victim.read_text(encoding="utf-8") == "do not overwrite"
    assert config.read_text(encoding="utf-8") == '{"enabled": true}'

@pytest.mark.parametrize("rule", [
    "10.0.0.0/33",
    "2001:db8::/129",
    "*. ",
    "*.example.com/path",
    "bad..example",
    "https://example.com",
])
def test_malformed_scope_rule_fails_closed(tmp_path: Path, rule: str) -> None:
    cfg = tmp_path / "scope.json"
    cfg.write_text(json.dumps({
        "engagement": "test",
        "enabled": True,
        "in_scope": [rule],
        "out_of_scope": [],
    }))
    with pytest.raises(RuntimeError, match="malformed 'in_scope' rule"):
        ScopeManager(cfg)

def test_global_cidr_scope_rule_emits_high_blast_radius_warning(
    tmp_path: Path, caplog,
) -> None:
    cfg = tmp_path / "scope.json"
    cfg.write_text(json.dumps({
        "engagement": "explicit-global-test",
        "enabled": True,
        "in_scope": ["0.0.0.0/0", "::/0"],
        "out_of_scope": ["169.254.0.0/16"],
    }))

    with caplog.at_level("WARNING", logger="whaxon.core.scope"):
        ScopeManager(cfg)

    assert any(
        "effectively permits every address" in record.message
        for record in caplog.records
    )


@pytest.mark.parametrize("target", [
    "http://[not-an-ipv6]/",
    "http://[::1",
    "http://bad host.example/",
    "127.0.0.1\nmalicious",
])
def test_malformed_url_authority_fails_closed(tmp_path: Path, target: str) -> None:
    """Malformed target URLs must not crash or bypass scope authorization."""
    sm = ScopeManager(tmp_path / "scope.json")
    match = sm.check(target)
    assert match.allowed is False
    assert match.reason
    execution = sm.check_for_execution(target)
    assert execution.allowed is False
