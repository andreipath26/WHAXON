"""Tests for the fail-closed scope policy.

These guard against the specific bug we fixed on 2026-09-27: a missing
or malformed scope.json used to set enabled=false, which made check()
return allowed=True for every target. In a platform that runs exploits,
that is a security hole.

If someone reintroduces fail-open behavior, these tests will fail.
"""
from __future__ import annotations

import json
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
        assert "no matching in-scope rule" in m.reason


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
