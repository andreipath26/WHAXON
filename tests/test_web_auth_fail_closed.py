"""Regression tests for web authentication fail-closed behavior."""
from __future__ import annotations

import pytest

from whaxon.interfaces.web.server import _check_auth, create_app_factory


def test_missing_credentials_do_not_disable_authentication(monkeypatch):
    monkeypatch.delenv("WHAXON_AUTH_USER", raising=False)
    monkeypatch.delenv("WHAXON_AUTH_PASS_HASH", raising=False)
    assert _check_auth(None) is False
    assert _check_auth("Basic d2hheG9uOndoYXhvbgo=") is False


def test_network_listener_requires_explicit_non_default_credentials(monkeypatch):
    for name in ("WHAXON_AUTH_USER", "WHAXON_AUTH_PASS", "WHAXON_AUTH_PASS_HASH"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(RuntimeError, match="non-loopback host"):
        create_app_factory(host="0.0.0.0", port=5001)


def test_network_listener_rejects_demo_credentials(monkeypatch):
    monkeypatch.setenv("WHAXON_AUTH_USER", "whaxon")
    monkeypatch.setenv("WHAXON_AUTH_PASS", "whaxon")
    monkeypatch.delenv("WHAXON_AUTH_PASS_HASH", raising=False)

    with pytest.raises(RuntimeError, match="non-loopback host"):
        create_app_factory(host="0.0.0.0", port=5001)

def test_custom_username_without_password_is_rejected_for_network_listener(monkeypatch):
    monkeypatch.setenv("WHAXON_AUTH_USER", "operator")
    monkeypatch.delenv("WHAXON_AUTH_PASS", raising=False)
    monkeypatch.delenv("WHAXON_AUTH_PASS_HASH", raising=False)

    with pytest.raises(RuntimeError, match="non-loopback host"):
        create_app_factory(host="0.0.0.0", port=5001)


def test_serve_does_not_invent_demo_credentials_for_network_listener(monkeypatch, tmp_path):
    from whaxon.interfaces.web.serve import main as serve_main

    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    for name in ("WHAXON_AUTH_USER", "WHAXON_AUTH_PASS", "WHAXON_AUTH_PASS_HASH"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(RuntimeError, match="non-loopback host"):
        serve_main(["--host", "0.0.0.0"])


def test_dev_server_rejects_custom_username_with_implicit_demo_password(monkeypatch):
    from whaxon.interfaces.web.server import main as server_main

    monkeypatch.setenv("WHAXON_HOST", "0.0.0.0")
    monkeypatch.setenv("WHAXON_AUTH_USER", "operator")
    monkeypatch.delenv("WHAXON_AUTH_PASS", raising=False)
    monkeypatch.delenv("WHAXON_AUTH_PASS_HASH", raising=False)

    with pytest.raises(SystemExit, match="non-default"):
        server_main([])
