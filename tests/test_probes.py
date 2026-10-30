"""Tests for constrained observation probes."""
import os
import socket
from pathlib import Path

import pytest

from whaxon.core.findings import Finding
from whaxon.core.probes import ProbeRunner
from whaxon.core.validator import Validator


def _listening_socket():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    return listener


def test_probe_runner_verifies_open_local_tcp_port():
    listener = _listening_socket()
    try:
        result = ProbeRunner(timeout=1).run("127.0.0.1", listener.getsockname()[1])
        assert result.status == "verified", result.reason
        assert result.exit_code == 0
        assert "accepted a connection" in result.reason
    finally:
        listener.close()


def test_probe_runner_refutes_closed_local_tcp_port():
    # Bind and close first to obtain a port that is normally not listening.
    reservation = _listening_socket()
    port = reservation.getsockname()[1]
    reservation.close()
    result = ProbeRunner(timeout=1).run("127.0.0.1", port)
    assert result.status in {"refuted", "candidate"}, result.reason
    if result.status == "refuted":
        assert result.exit_code != 0


def test_probe_runner_rejects_invalid_ports_without_network_access():
    result = ProbeRunner().run("127.0.0.1", 70000)
    assert result.status == "candidate"
    assert result.exit_code != 0


def test_validator_routes_open_port_to_probe_runner(monkeypatch):
    class FakeResult:
        status = "verified"
        reason = "TCP port 81 accepted a connection"

    class FakeRunner:
        def __init__(self, timeout=3.0):
            assert timeout == 3.0

        def run(self, host, port, service=""):
            assert host == "pentest-ground.com"
            assert port == 81
            return FakeResult()

    monkeypatch.setattr("whaxon.core.validator.ProbeRunner", FakeRunner)
    finding = Finding(
        kind="open_port",
        severity="info",
        source="nmap",
        data={"port": 81, "protocol": "tcp", "service": "http"},
        raw_line="81/tcp open http",
    )
    status, reason = Validator(payload_dir=Path(".")).validate(
        finding, target_url="http://pentest-ground.com:81/"
    )
    assert status == "verified"
    assert "port 81" in reason


@pytest.mark.skipif(
    os.environ.get("WHAXON_RUN_LIVE_PROBES") != "1",
    reason="set WHAXON_RUN_LIVE_PROBES=1 to probe the explicitly designated public lab",
)
def test_live_pentest_ground_port_81():
    """Opt-in integration check; does not run against external hosts by default."""
    result = ProbeRunner(timeout=5).run("pentest-ground.com", 81, service="http")
    assert result.status == "verified", result.reason


@pytest.mark.parametrize("port", [True, 0, -1, 65536, 81.5, "81"])
def test_probe_runner_rejects_invalid_port_types_and_ranges(port):
    result = ProbeRunner().run("127.0.0.1", port)
    assert result.status == "candidate"


def test_probe_runner_rejects_invalid_timeout():
    with pytest.raises(ValueError):
        ProbeRunner(timeout=True)


def test_validator_rejects_mismatched_finding_host(monkeypatch):
    finding = Finding(
        kind="open_port", severity="info", source="nmap",
        data={"host": "other.example", "port": 81}, raw_line="",
    )
    status, reason = Validator(Path(".")).validate(
        finding, target_url="https://pentest-ground.com/"
    )
    assert status == "candidate"
    assert "does not match" in reason


def test_validator_rejects_non_tcp_protocol(monkeypatch):
    finding = Finding(
        kind="open_port", severity="info", source="nmap",
        data={"port": 53, "protocol": "udp"}, raw_line="",
    )
    status, reason = Validator(Path(".")).validate(
        finding, target_url="https://pentest-ground.com/"
    )
    assert status == "candidate"
    assert "do not yet support" in reason
