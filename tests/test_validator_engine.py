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


class _EscapingReflector(_Reflector):
    """Echoes the query only after HTML escaping it."""
    def do_GET(self):
        import html
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        body = f"<html><body>You searched for: {html.escape(q)}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(handler=_Reflector):
    srv = HTTPServer(("127.0.0.1", 0), handler)
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
        # This fixture reflects the probe unescaped into an HTML response;
        # the validator should identify the explicit XSS marker, not pass on
        # timing alone or accept either verdict.
        assert status == "verified", reason
        assert "XSS probe" in reason, reason
    finally:
        srv.shutdown()


def test_escaped_reflection_is_not_verified():
    srv, url = _serve(_EscapingReflector)
    try:
        v = Validator(PAYLOAD_DIR)
        f = Finding(kind="xss", severity="high", source="test",
                    data={"parameter": "q"}, raw_line="")
        status, reason = v.validate(f, target_url=url)
        assert status != "verified", reason
    finally:
        srv.shutdown()


def test_unknown_kind_is_candidate():
    v = Validator(PAYLOAD_DIR)
    f = Finding(kind="unknown_observation", severity="info", source="nmap",
                data={"port": 22}, raw_line="")
    status, reason = v.validate(f, target_url="http://127.0.0.1:1/")
    assert status == "candidate"
    assert "no safe validation probe" in reason


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


def test_replay_ctx_injects_payload_from_request_context():
    """Dogfooding bug: _replay_ctx sent the raw URL without the payload.
    The reflecting server echoes <script>, so the marker must appear.
    """
    srv, url = _serve()
    try:
        v = Validator(PAYLOAD_DIR)
        f = Finding(
            kind="xss", severity="medium", source="test",
            data={
                "parameter": "q",
                "_request_context": {
                    "method": "GET",
                    "url": url,
                    "parameter": "q",
                },
            },
            raw_line="",
        )
        # The caller must supply the scope-checked engagement target; the
        # context URL alone is evidence, not authorization to make a request.
        status, reason = v.validate(f, target_url=url)
        assert status == "verified", reason
        assert "XSS probe" in reason
    finally:
        srv.shutdown()

class _DatabaseNameDecoy(BaseHTTPRequestHandler):
    """Mentions a DBMS name but does not execute SQL or produce a parser error."""
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        if q == "'":
            body = "Database driver error: postgresql backend unavailable"
        else:
            body = "Search page"
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def test_database_name_alone_does_not_verify_sqli():
    srv, url = _serve(_DatabaseNameDecoy)
    try:
        v = Validator(PAYLOAD_DIR)
        f = Finding(kind="sqli", severity="high", source="test",
                    data={"parameter": "q"}, raw_line="")
        status, reason = v.validate(f, target_url=url)
        assert status == "candidate", reason
        assert "postgresql" not in reason.lower()
    finally:
        srv.shutdown()

class _TextareaReflector(_Reflector):
    """Raw markup inside a textarea is text, not executable HTML."""
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        body = f"<html><body><textarea>{q}</textarea></body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_xss_raw_reflection_inside_textarea_is_not_verified():
    srv, url = _serve(_TextareaReflector)
    try:
        v = Validator(PAYLOAD_DIR)
        f = Finding(kind="xss", severity="high", source="test",
                    data={"parameter": "q"}, raw_line="")
        status, reason = v.validate(f, target_url=url)
        assert status == "candidate", reason
    finally:
        srv.shutdown()
