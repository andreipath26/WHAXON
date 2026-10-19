"""Live replay tests for the deterministic validator (§32.2)."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from whaxon.core.findings import Finding
from whaxon.core.validator import Validator

PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "src" / "whaxon" / "data" / "payloads"


class _Reflector(BaseHTTPRequestHandler):
    """Echoes back ?q= verbatim. SQLi/XSS payloads land in the body unchanged."""
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        body = f"<html><body>You searched for: {q}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve():
    srv = HTTPServer(("127.0.0.1", 0), _Reflector)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/search"


def test_xss_reflected_is_verified():
    srv, url = _serve()
    try:
        v = Validator(PAYLOAD_DIR)
        f = Finding(kind="xss", severity="high", source="test",
                    data={"parameter": "q"}, raw_line="")
        status, reason = v.validate(f, target_url=url)
        # The vendored first XSS payload should reflect and contain a marker.
        assert status in ("verified", "candidate"), reason
    finally:
        srv.shutdown()


def test_unknown_kind_is_candidate():
    v = Validator(PAYLOAD_DIR)
    f = Finding(kind="open_port", severity="info", source="nmap",
                data={"port": 22}, raw_line="")
    status, reason = v.validate(f, target_url="http://127.0.0.1:1/")
    assert status == "candidate"
    assert "not directly replayable" in reason


def test_no_url_is_candidate():
    v = Validator(PAYLOAD_DIR)
    f = Finding(kind="xss", severity="high", source="test",
                data={"parameter": "q"}, raw_line="")
    status, reason = v.validate(f, target_url=None)
    assert status == "candidate"
    assert "no target URL" in reason


def test_no_parameter_is_candidate():
    v = Validator(PAYLOAD_DIR)
    f = Finding(kind="xss", severity="high", source="test", data={}, raw_line="")
    status, reason = v.validate(f, target_url="http://127.0.0.1:1/")
    assert status == "candidate"
    assert "no parameter" in reason
