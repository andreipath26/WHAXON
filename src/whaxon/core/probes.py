"""Constrained observation probes for environmental findings.

Probes are implemented with Python's socket/TLS APIs rather than shell strings.
This avoids shell injection and makes the observation deterministic and auditable.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass

_TLS_SERVICES = {
    "https", "https-alt", "ssl", "tls", "ssl/http", "smtps", "imaps",
    "pop3s", "ldaps", "ftps", "mqtts",
}
_TLS_PORTS = {443, 465, 636, 853, 990, 993, 995, 8443, 9443}


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of one observation probe."""

    status: str  # "verified" | "refuted" | "candidate"
    reason: str
    host: str
    port: int
    service: str = ""

    @property
    def exit_code(self) -> int:
        """Shell-compatible convention: 0 only for verified observations."""
        return 0 if self.status == "verified" else 1


class ProbeRunner:
    """Run allowlisted TCP reachability and TLS-handshake observation probes.

    This deliberately does not execute arbitrary commands from finding data.
    A TCP connect verifies reachability, not that the service is vulnerable.
    """

    def __init__(self, timeout: float = 3.0):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise ValueError("timeout must be greater than 0 and at most 30 seconds")
        self.timeout = float(timeout)

    def run(self, host: str, port: int, service: str = "") -> ProbeResult:
        """Probe a TCP port; return verified, refuted, or candidate.

        Connection refusal is evidence that the port is not accepting TCP
        connections. Timeouts and DNS/network errors are inconclusive, not proof
        that a port is closed.
        """
        if not isinstance(host, str) or not host or host.strip() != host:
            return ProbeResult("candidate", "host is missing or invalid", str(host), -1, "")
        if any(ch in host for ch in "/?#@") or any(ch.isspace() for ch in host):
            return ProbeResult("candidate", "host must be a hostname or IP address", host, -1, "")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return ProbeResult("candidate", "port must be an integer from 1 to 65535", host, -1, "")
        if not isinstance(service, str):
            return ProbeResult("candidate", "service must be a string", host, port, "")

        service_l = service.strip().lower()
        use_tls = service_l in _TLS_SERVICES or port in _TLS_PORTS
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as conn:
                if use_tls:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(conn, server_hostname=host):
                        pass
                    return ProbeResult(
                        "verified",
                        f"TCP port {port} is reachable and TLS handshake succeeded",
                        host, port, service_l,
                    )
                return ProbeResult(
                    "verified", f"TCP port {port} accepted a connection",
                    host, port, service_l,
                )
        except ConnectionRefusedError:
            return ProbeResult(
                "refuted", f"TCP connection to port {port} was refused",
                host, port, service_l,
            )
        except TimeoutError:
            return ProbeResult(
                "candidate", f"TCP connection to port {port} timed out; state is inconclusive",
                host, port, service_l,
            )
        except ssl.SSLError as exc:
            # TCP accepted the connection: this verifies reachability, not TLS identity.
            return ProbeResult(
                "verified",
                f"TCP port {port} accepted a connection, but TLS handshake failed: {exc}",
                host, port, service_l,
            )
        except socket.gaierror as exc:
            return ProbeResult("candidate", f"DNS resolution failed: {exc}", host, port, service_l)
        except OSError as exc:
            return ProbeResult("candidate", f"network probe failed: {exc}", host, port, service_l)
