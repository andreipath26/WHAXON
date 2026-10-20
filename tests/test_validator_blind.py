"""Blind validation via timing delta (§34.2 step 2)."""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from whaxon.core.findings import Finding
from whaxon.core.validator import Validator

PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "src" / "whaxon" / "data" / "payloads"


class _BlindServer(BaseHTTPRequestHandler):
    """Delays the response by 4s if the 'q' parameter contains SLEEP."""

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        if "SLEEP" in q.upper():
            time.sleep(4)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve():
    srv = HTTPServer(("127.0.0.1", 0), _BlindServer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/search"


def test_blind_timing_is_verified():
    srv, url = _serve()
    try:
        # Force the loader to return a SLEEP payload by bypassing the cache.
        v = Validator(PAYLOAD_DIR)
        v.loader.get_payloads = lambda kind: ["1' AND SLEEP(4)-- -"]

        f = Finding(
            kind="sqli", severity="high", source="test",
            data={"parameter": "q"}, raw_line="",
        )
        status, reason = v.validate(f, target_url=url)
        assert status == "verified", reason
        assert "timing delta" in reason
    finally:
        srv.shutdown()


def test_identical_fast_response_is_refuted():
    srv, url = _serve()
    try:
        v = Validator(PAYLOAD_DIR)
        v.loader.get_payloads = lambda kind: ["harmless"]

        f = Finding(
            kind="sqli", severity="high", source="test",
            data={"parameter": "q"}, raw_line="",
        )
        status, reason = v.validate(f, target_url=url)
        # Identical body, fast: refuted.
        assert status == "refuted", reason
    finally:
        srv.shutdown()
