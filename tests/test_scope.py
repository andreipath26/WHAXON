import json
import pytest

from whaxon.core.scope import ScopeManager, OutOfScopeError


@pytest.fixture
def scope_file(tmp_path):
    def _write(data):
        p = tmp_path / "scope.json"
        p.write_text(json.dumps(data))
        return p
    return _write


def test_missing_file_is_fail_closed(tmp_path):
    """Missing scope.json must NOT disable enforcement.

    The old behavior (enabled=False for a missing file) was a
    fail-open security hole; it was fixed on 2026-09-27. See
    tests/test_scope_failclosed.py for the exhaustive contract.
    """
    s = ScopeManager(tmp_path / "nonexistent.json")
    assert s.enabled is True
    assert s.check("10.0.0.5").allowed is True   # RFC1918 default
    assert s.check("evil.example.com").allowed is False

def test_disabled_scope_allows_everything(scope_file):
    s = ScopeManager(scope_file({"enabled": False, "in_scope": ["a.com"]}))
    assert s.check("b.com").allowed is True


def test_exact_host_in_scope(scope_file):
    s = ScopeManager(scope_file({"enabled": True, "in_scope": ["acme.com"]}))
    assert s.check("acme.com").allowed is True
    assert s.check("other.com").allowed is False


def test_wildcard_matches_subdomain(scope_file):
    s = ScopeManager(scope_file({"enabled": True, "in_scope": ["*.acme.com"]}))
    assert s.check("api.acme.com").allowed is True
    assert s.check("deep.api.acme.com").allowed is True
    assert s.check("acme.com").allowed is False


def test_out_of_scope_wins(scope_file):
    s = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["*.acme.com"],
        "out_of_scope": ["prod.acme.com"],
    }))
    assert s.check("api.acme.com").allowed is True
    assert s.check("prod.acme.com").allowed is False
    assert s.check("prod.acme.com").matched_rule == "prod.acme.com"


def test_cidr_range(scope_file):
    s = ScopeManager(scope_file({"enabled": True, "in_scope": ["10.0.0.0/24"]}))
    assert s.check("10.0.0.5").allowed is True
    assert s.check("10.0.0.255").allowed is True
    assert s.check("10.0.1.1").allowed is False


def test_ip_out_of_range(scope_file):
    s = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["10.0.0.0/24"],
        "out_of_scope": ["10.0.0.1"],
    }))
    assert s.check("10.0.0.5").allowed is True
    assert s.check("10.0.0.1").allowed is False


def test_url_normalized(scope_file):
    s = ScopeManager(scope_file({"enabled": True, "in_scope": ["acme.com"]}))
    assert s.check("https://acme.com/path").allowed is True
    assert s.check("http://api.acme.com").allowed is False


def test_host_with_port(scope_file):
    s = ScopeManager(scope_file({"enabled": True, "in_scope": ["acme.com"]}))
    assert s.check("acme.com:8080").allowed is True


def test_runner_refuses_out_of_scope(scope_file):
    """Integration: runner raises OutOfScopeError when scope forbids the target."""
    import asyncio
    from whaxon.core.runner import ToolRunner
    from whaxon.core.events import EventBus

    bus = EventBus()
    scope = ScopeManager(scope_file({"enabled": True, "in_scope": ["allowed.com"]}))
    runner = ToolRunner(bus, catalog=None, scope=scope)

    with pytest.raises(OutOfScopeError):
        asyncio.run(runner.run_tool("echo", "forbidden.com"))
