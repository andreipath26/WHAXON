"""Safe observation probes for environmental findings."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from whaxon.core.findings import Finding
from whaxon.core.validator import Validator

PAYLOADS = Path(__file__).resolve().parents[1] / "src" / "whaxon" / "data" / "payloads"


class _HeaderServer(BaseHTTPRequestHandler):
    send_csp = False

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        if self.send_csp:
            self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Set-Cookie", "session=abc; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve(handler=_HeaderServer):
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


def test_open_port_observation_is_verified_by_successful_tcp_connect():
    server, url = _serve()
    try:
        finding = Finding(
            kind="open_port", severity="info", source="nmap",
            data={"port": server.server_address[1], "protocol": "tcp"},
            raw_line="tcp port open",
        )
        status, reason = Validator(PAYLOADS).validate(finding, target_url=url)
        assert status == "verified", reason
        assert "TCP connection" in reason
    finally:
        server.shutdown()
        server.server_close()


def test_missing_http_header_is_verified_from_live_response():
    server, url = _serve()
    try:
        finding = Finding(
            kind="http_header_missing", severity="low", source="recon:headers",
            data={"header": "Content-Security-Policy", "url": url},
            raw_line="missing CSP",
        )
        status, reason = Validator(PAYLOADS).validate(finding, target_url=url)
        assert status == "verified", reason
        assert "lacks Content-Security-Policy" in reason
    finally:
        server.shutdown()
        server.server_close()


def test_present_http_header_does_not_claim_the_finding_is_fixed():
    class _ProtectedHeaderServer(_HeaderServer):
        send_csp = True

    server, url = _serve(_ProtectedHeaderServer)
    try:
        finding = Finding(
            kind="http_header_missing", severity="low", source="recon:headers",
            data={"header": "Content-Security-Policy", "url": url},
            raw_line="missing CSP",
        )
        status, reason = Validator(PAYLOADS).validate(finding, target_url=url)
        assert status == "candidate", reason
        assert "includes Content-Security-Policy" in reason
    finally:
        server.shutdown()
        server.server_close()


def test_cookie_missing_flag_is_verified_from_live_set_cookie_header():
    server, url = _serve()
    try:
        finding = Finding(
            kind="cookie_insecure", severity="medium", source="recon:cookies",
            data={"cookie": "session", "missing": "httponly", "url": url},
            raw_line="session cookie lacks HttpOnly",
        )
        status, reason = Validator(PAYLOADS).validate(finding, target_url=url)
        assert status == "verified", reason
        assert "lacks httponly" in reason
    finally:
        server.shutdown()
        server.server_close()


def test_observation_without_required_fields_stays_candidate():
    finding = Finding(
        kind="open_port", severity="info", source="nmap",
        data={"port": True, "protocol": "tcp"}, raw_line="invalid port",
    )
    status, reason = Validator(PAYLOADS).validate(
        finding, target_url="http://127.0.0.1/"
    )
    assert status == "candidate", reason
    assert "valid TCP port" in reason
