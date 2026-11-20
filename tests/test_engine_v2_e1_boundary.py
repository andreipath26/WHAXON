"""Engine V2 E1 adversarial authorization tests for DNS/target boundaries.

Scope preview is not execution permission for a name that may resolve again
inside an external scanner. These tests exercise both decisions explicitly.
"""

import json
import socket

import pytest

from whaxon.core.scope import ScopeManager


def _scope(tmp_path, *, allow, deny=()):
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps({
            "engagement": "e1-boundary-test",
            "enabled": True,
            "in_scope": list(allow),
            "out_of_scope": list(deny),
        }),
        encoding="utf-8",
    )
    return ScopeManager(path)


def _answers(*addresses):
    return [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))
        for ip in addresses
    ]


@pytest.mark.parametrize(
    ("addresses", "preview_allowed"),
    [
        (("192.0.2.7", "192.0.2.8"), True),
        (("192.0.2.7", "203.0.113.8"), False),
        (("203.0.113.8",), False),
    ],
)
def test_ip_cidr_scope_never_dispatches_unpinned_hostname(
    tmp_path, monkeypatch, addresses, preview_allowed,
):
    scope = _scope(tmp_path, allow=("192.0.2.0/24",))
    monkeypatch.setattr(
        "whaxon.core.scope.socket.getaddrinfo",
        lambda host, port, type: _answers(*addresses),
    )
    preview = scope.check("target.example")
    assert preview.allowed is preview_allowed
    execution = scope.check_for_execution("target.example")
    assert execution.allowed is False
    if preview_allowed:
        assert execution.overridable is False
        assert "DNS-pinned" in execution.reason


def test_hostname_allowlist_cannot_override_excluded_resolved_ip(tmp_path, monkeypatch):
    scope = _scope(
        tmp_path,
        allow=("target.example",),
        deny=("203.0.113.0/24",),
    )
    monkeypatch.setattr(
        "whaxon.core.scope.socket.getaddrinfo",
        lambda host, port, type: _answers("192.0.2.7", "203.0.113.8"),
    )
    assert not scope.check("target.example").allowed
    assert not scope.check_for_execution("target.example").allowed


def test_literal_ip_under_cidr_is_dispatchable_without_dns(tmp_path, monkeypatch):
    scope = _scope(tmp_path, allow=("192.0.2.0/24",))

    def forbidden_dns(*args, **kwargs):
        raise AssertionError("IP literal must not trigger a hostname lookup")

    monkeypatch.setattr("whaxon.core.scope.socket.getaddrinfo", forbidden_dns)
    assert scope.check_for_execution("192.0.2.7").allowed is True
    assert scope.check_for_execution("203.0.113.8").allowed is False


def test_explicit_hostname_only_scope_is_distinct_from_cidr_scope(tmp_path, monkeypatch):
    scope = _scope(tmp_path, allow=("target.example",))

    def forbidden_dns(*args, **kwargs):
        raise AssertionError("hostname-only policy should not require an IP lookup")

    monkeypatch.setattr("whaxon.core.scope.socket.getaddrinfo", forbidden_dns)
    assert scope.check_for_execution("target.example").allowed is True
    assert scope.check_for_execution("other.example").allowed is False
