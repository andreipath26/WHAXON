"""G02 regression tests for authorization at request boundaries."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from whaxon.core.findings import Finding
from whaxon.core.validator import Validator


class _RedirectFixture(BaseHTTPRequestHandler):
    paths: list[str] = []

    def do_GET(self):
        type(self).paths.append(self.path)
        if self.path.startswith("/source"):
            self.send_response(302)
            self.send_header("Location", "/sink?id=1")
            self.end_headers()
            return
        body = b"You have an error in your SQL syntax"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def test_sqli_verifier_does_not_follow_redirect_to_unapproved_path():
    _RedirectFixture.paths = []
    server = HTTPServer(("127.0.0.1", 0), _RedirectFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        finding = Finding(
            kind="sqli", severity="high", source="sqlmap",
            data={"parameter": "id"}, raw_line="controlled redirect fixture",
        )
        payload_dir = Path(__file__).resolve().parents[1] / "src" / "whaxon" / "data" / "payloads"
        status, reason = Validator(payload_dir).validate(
            finding, target_url=f"http://127.0.0.1:{server.server_port}/source?id=1",
        )

        assert status == "candidate"
        assert "redirect blocked" in reason
        assert len(_RedirectFixture.paths) == 1
        assert _RedirectFixture.paths[0].startswith("/source?")
        assert all(not path.startswith("/sink") for path in _RedirectFixture.paths)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
