import json

import pytest

from whaxon.core.scope import OutOfScopeError, ScopeManager


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


def test_cidr_rule_matches_url_target(scope_file):
    """Regression: a URL whose host is an IP literal must match CIDR rules.

    scope --check allowed a bare `127.0.0.1` but denied
    `http://127.0.0.1:8099/ping`, because CIDR matching only ran for
    targets whose kind was "ip" and a URL was classified as "url".
    """
    s = ScopeManager(scope_file({"enabled": True, "in_scope": ["127.0.0.0/8"]}))
    assert s.check("http://127.0.0.1:8099/ping?ip=1").allowed is True
    assert s.check("http://127.0.0.1:8099/ping?ip=1").matched_rule == "127.0.0.0/8"
    assert s.check("https://10.1.2.3/admin").allowed is False


def test_cidr_out_of_scope_denies_url_target(scope_file):
    """The deny path matters as much as the allow path."""
    s = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["10.0.0.0/8"],
        "out_of_scope": ["10.9.0.0/16"],
    }))
    assert s.check("http://10.1.1.1/x").allowed is True
    assert s.check("http://10.9.1.1/x").allowed is False
    assert s.check("http://10.9.1.1/x").matched_rule == "10.9.0.0/16"


def test_ipv6_url_matches_cidr_rule(scope_file):
    s = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["::1", "fc00::/7"],
        "out_of_scope": ["2001:db8::/32"],
    }))
    assert s.check("http://[::1]:8080/x").allowed is True
    assert s.check("http://[fd00::1]/x").allowed is True
    assert s.check("http://[2001:db8::1]/x").allowed is False


def test_hostname_url_is_not_matched_by_cidr(scope_file):
    s = ScopeManager(scope_file({"enabled": True, "in_scope": ["10.0.0.0/8"]}))
    assert s.check("http://acme.com/").allowed is False


def test_default_scope_allows_loopback_and_rfc1918_urls(tmp_path):
    """The auto-written default scope is CIDR-only, so URLs must match it."""
    s = ScopeManager(tmp_path / "scope.json")
    assert s.check("http://127.0.0.1:8099/").allowed is True
    assert s.check("http://192.168.1.10:80/").allowed is True
    assert s.check("https://pentest-ground.com:4280/").allowed is False


def test_runner_refuses_out_of_scope(scope_file):
    """Integration: runner raises OutOfScopeError when scope forbids the target."""
    import asyncio

    from whaxon.core.events import EventBus
    from whaxon.core.runner import ToolRunner

    bus = EventBus()
    scope = ScopeManager(scope_file({"enabled": True, "in_scope": ["allowed.com"]}))
    runner = ToolRunner(bus, catalog=None, scope=scope)

    with pytest.raises(OutOfScopeError):
        asyncio.run(runner.run_tool("echo", "forbidden.com"))


def test_execution_scope_fails_closed_for_dns_under_cidr_policy(scope_file, monkeypatch):
    import socket

    s = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["10.0.0.0/8"],
        "out_of_scope": ["10.9.0.0/16"],
    }))
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))
        ],
    )
    # The ordinary check is a DNS preflight only; it cannot bind the address
    # that an arbitrary third-party scanner will use when it connects.
    assert s.check("scan.acme.test").allowed is True
    result = s.check_for_execution("https://scan.acme.test/")
    assert result.allowed is False
    assert "cannot be safely DNS-pinned" in result.reason


def test_execution_scope_accepts_authorized_ip_literal(scope_file):
    s = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["10.0.0.0/8"],
    }))
    assert s.check_for_execution("https://10.1.2.3/").allowed is True


def test_execution_scope_accepts_explicit_hostname_only_policy(scope_file):
    s = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["*.acme.test"],
    }))
    assert s.check_for_execution("https://scan.acme.test/").allowed is True


def test_dns_pinning_execution_block_cannot_be_overridden(scope_file, monkeypatch):
    import asyncio
    import socket

    from whaxon.core.events import EventBus
    from whaxon.core.runner import ToolRunner

    scope = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["10.0.0.0/8"],
    }))
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))
        ],
    )
    runner = ToolRunner(EventBus(), scope=scope)
    with pytest.raises(OutOfScopeError) as error:
        asyncio.run(
            runner.run_tool(
                "nikto", "scan.acme.test", allow_out_of_scope=True,
            )
        )
    assert error.value.overridable is False


def _pinned_answer(ip, port=443):
    import socket

    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


def test_pinned_resolution_resolves_once_and_returns_numeric_socket_address(
    scope_file, monkeypatch,
):
    import socket

    from whaxon.core.scope import ScopeManager

    # Without IP/CIDR bounds, the explicit hostname continues to authorize
    # its resolved numeric address.
    scope = ScopeManager(scope_file({
        "enabled": True, "in_scope": ["scan.acme.test"], "out_of_scope": [],
    }))
    calls = []

    def resolve(host, port, **kwargs):
        calls.append((host, port, kwargs))
        return [_pinned_answer("192.0.2.12", port)]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    result = scope.resolve_for_execution("SCAN.Acme.Test.", port=443)

    assert result.allowed is True
    assert len(calls) == 1
    assert calls[0][0:2] == ("scan.acme.test", 443)
    assert len(result.addresses) == 1
    assert result.addresses[0].sockaddr == ("192.0.2.12", 443)
    assert result.addresses[0].family == socket.AF_INET


@pytest.mark.parametrize("ip", ["127.0.0.1", "8.8.8.8"])
def test_pinned_resolution_enforces_ip_bounds_even_for_allowed_hostname(
    scope_file, monkeypatch, ip,
):
    import socket

    from whaxon.core.scope import ScopeManager

    scope = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["scan.acme.test", "10.0.0.0/8"],
        "out_of_scope": [],
    }))
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda _host, port, **_kwargs: [_pinned_answer(ip, port)],
    )

    result = scope.resolve_for_execution("scan.acme.test", port=443)

    assert result.allowed is False
    assert "not every resolved address" in result.reason
    assert result.addresses == ()


def test_pinned_resolution_rejects_mixed_allowed_and_denied_answers(
    scope_file, monkeypatch,
):
    import socket

    from whaxon.core.scope import ScopeManager

    scope = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["*.acme.test", "10.0.0.0/8"],
        "out_of_scope": ["10.9.0.0/16"],
    }))
    calls = []

    def resolve(host, port, **kwargs):
        calls.append(host)
        return [_pinned_answer("10.1.2.3", port), _pinned_answer("10.9.1.2", port)]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    result = scope.resolve_for_execution("scan.acme.test", port=443)

    assert calls == ["scan.acme.test"]
    assert result.allowed is False
    assert "out-of-scope" in result.reason
    assert result.addresses == ()


def test_pinned_resolution_denies_out_of_scope_hostname_before_dns(
    scope_file, monkeypatch,
):
    import socket

    from whaxon.core.scope import ScopeManager

    scope = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["*.acme.test"],
        "out_of_scope": ["prod.acme.test"],
    }))

    def unexpected_resolution(*_args, **_kwargs):
        pytest.fail("out-of-scope hostname must be rejected before DNS")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_resolution)
    result = scope.resolve_for_execution("prod.acme.test", port=443)

    assert result.allowed is False
    assert result.addresses == ()


@pytest.mark.parametrize(
    ("resolver_result", "resolver_error", "reason"),
    [
        (None, OSError("resolver unavailable"), "resolution failed"),
        ([], None, "no usable socket addresses"),
    ],
)
def test_pinned_resolution_denies_resolution_failure_or_empty_answer(
    scope_file, monkeypatch, resolver_result, resolver_error, reason,
):
    import socket

    from whaxon.core.scope import ScopeManager

    scope = ScopeManager(scope_file({
        "enabled": True, "in_scope": ["scan.acme.test"], "out_of_scope": [],
    }))
    calls = []

    def resolve(host, port, **kwargs):
        calls.append((host, port))
        if resolver_error is not None:
            raise resolver_error
        return resolver_result

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    result = scope.resolve_for_execution("scan.acme.test", port=443)

    assert calls == [("scan.acme.test", 443)]
    assert result.allowed is False
    assert reason in result.reason
    assert result.addresses == ()


def test_pinned_scheduler_preflight_is_non_resolving(scope_file, monkeypatch):
    import socket

    from whaxon.core.scope import ScopeManager

    scope = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["scan.acme.test", "10.0.0.0/8"],
        "out_of_scope": ["10.9.0.0/16"],
    }))

    def unexpected_resolution(*_args, **_kwargs):
        pytest.fail("scheduler preflight must not resolve hostnames")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_resolution)
    result = scope.check_for_pinned_execution("scan.acme.test")

    assert result.allowed is True
    assert result.matched_rule == "scan.acme.test"


@pytest.mark.parametrize("target", [" scan.acme.test", "scan.acme.test "])
def test_pinned_preflight_rejects_whitespace_targets(scope_file, target):
    from whaxon.core.scope import ScopeManager

    scope = ScopeManager(scope_file({
        "enabled": True, "in_scope": ["scan.acme.test"], "out_of_scope": [],
    }))

    result = scope.check_for_pinned_execution(target)

    assert result.allowed is False
    assert "invalid pinned execution target" in result.reason


def test_pinned_resolution_checks_every_answer_under_ip_only_scope(
    scope_file, monkeypatch,
):
    import socket

    from whaxon.core.scope import ScopeManager

    scope = ScopeManager(scope_file({
        "enabled": True, "in_scope": ["10.0.0.0/8"], "out_of_scope": [],
    }))
    calls = []

    def resolve(host, port, **kwargs):
        calls.append(host)
        return [_pinned_answer("10.1.2.3", port), _pinned_answer("10.9.8.7", port)]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    preflight = scope.check_for_pinned_execution("scan.acme.test")
    result = scope.resolve_for_execution("scan.acme.test", port=443)

    assert preflight.allowed is True
    assert "child-side" in preflight.reason
    assert calls == ["scan.acme.test"]
    assert result.allowed is True
    assert len(result.addresses) == 2
    assert {item.sockaddr[0] for item in result.addresses} == {"10.1.2.3", "10.9.8.7"}


def test_pinned_resolution_rejects_cidr_only_mixed_answers(
    scope_file, monkeypatch,
):
    import socket

    from whaxon.core.scope import ScopeManager

    scope = ScopeManager(scope_file({
        "enabled": True, "in_scope": ["10.0.0.0/8"], "out_of_scope": [],
    }))
    calls = []

    def resolve(host, port, **kwargs):
        calls.append(host)
        return [_pinned_answer("10.1.2.3", port), _pinned_answer("192.0.2.9", port)]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    preflight = scope.check_for_pinned_execution("scan.acme.test")
    result = scope.resolve_for_execution("scan.acme.test", port=443)

    assert preflight.allowed is True
    assert "child-side" in preflight.reason
    assert calls == ["scan.acme.test"]
    assert result.allowed is False
    assert "not every resolved address" in result.reason
    assert result.addresses == ()


def test_pinned_resolution_checks_ipv4_mapped_ipv6_against_ipv4_denies(
    scope_file, monkeypatch,
):
    import socket

    from whaxon.core.scope import ScopeManager

    scope = ScopeManager(scope_file({
        "enabled": True,
        "in_scope": ["scan.acme.test"],
        "out_of_scope": ["10.9.0.0/16"],
    }))
    calls = []

    def resolve(host, port, **kwargs):
        calls.append(host)
        return [_pinned_answer("::ffff:10.9.1.2", port)]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    result = scope.resolve_for_execution("scan.acme.test", port=443)

    assert calls == ["scan.acme.test"]
    assert result.allowed is False
    assert "out-of-scope" in result.reason
    assert result.addresses == ()
