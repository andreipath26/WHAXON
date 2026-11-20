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


def test_blind_timing_remains_candidate_without_marker():
    srv, url = _serve()
    try:
        # Force the loader to return a SLEEP payload by bypassing the cache.
        v = Validator(PAYLOAD_DIR)
        v._safe_probe = lambda kind: "1' AND SLEEP(4)-- -"

        f = Finding(
            kind="sqli", severity="high", source="test",
            data={"parameter": "q"}, raw_line="",
        )
        status, reason = v.validate(f, target_url=url)
        assert status == "candidate", reason
        assert "timing-only result is inconclusive" in reason
    finally:
        srv.shutdown()


def test_identical_fast_response_remains_candidate():
    srv, url = _serve()
    try:
        v = Validator(PAYLOAD_DIR)
        v.loader.get_payloads = lambda kind: ["harmless"]

        f = Finding(
            kind="sqli", severity="high", source="test",
            data={"parameter": "q"}, raw_line="",
        )
        status, reason = v.validate(f, target_url=url)
        # An identical response is not proof of absence; keep the finding inconclusive.
        assert status == "candidate", reason
        assert "no conclusive" in reason
    finally:
        srv.shutdown()


def test_slow_baseline_does_not_false_positive():
    """A server slow on every request should not verify: median delta is ~0."""
    class _AlwaysSlow(BaseHTTPRequestHandler):
        def do_GET(self):
            import time as _t
            _t.sleep(1.5)
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _AlwaysSlow)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/search"
    try:
        v = Validator(PAYLOAD_DIR)
        v.loader.get_payloads = lambda kind: ["' AND SLEEP(4)-- -"]
        v.timing_threshold = 3.0
        f = Finding(kind="sqli", severity="high", source="test",
                    data={"parameter": "q"}, raw_line="")
        status, reason = v.validate(f, target_url=url)
        assert status != "verified", reason
    finally:
        srv.shutdown()


def test_jitter_does_not_promote_to_verified():
    """Random small variance on both sides should not cross the threshold."""
    import random as _random
    class _Jittery(BaseHTTPRequestHandler):
        def do_GET(self):
            import time as _t
            _t.sleep(_random.uniform(0.0, 0.4))
            body = b"clean"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _Jittery)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/search"
    try:
        v = Validator(PAYLOAD_DIR)
        v.loader.get_payloads = lambda kind: ["' AND SLEEP(4)-- -"]
        v.timing_threshold = 3.0
        f = Finding(kind="sqli", severity="high", source="test",
                    data={"parameter": "q"}, raw_line="")
        status, reason = v.validate(f, target_url=url)
        assert status != "verified", reason
    finally:
        srv.shutdown()


def test_intermittent_timeout_returns_candidate():
    """A request that raises (timeout / reset) must return candidate, never verified."""
    class _Hangs(BaseHTTPRequestHandler):
        def do_GET(self):
            import time as _t
            _t.sleep(20)
        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _Hangs)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/search"
    try:
        v = Validator(PAYLOAD_DIR)
        v.loader.get_payloads = lambda kind: ["payload"]
        v.timing_threshold = 3.0
        f = Finding(kind="sqli", severity="high", source="test",
                    data={"parameter": "q"}, raw_line="")
        status, reason = v.validate(f, target_url=url)
        assert status == "candidate", reason
        assert "replay failed" in reason, reason
    finally:
        srv.shutdown()


def test_single_slow_measurement_is_rejected_by_median():
    """Only the first injected sample is slow. Median of 3 is fast, so not verified."""
    state = {"n": 0}
    class _OneSlow(BaseHTTPRequestHandler):
        def do_GET(self):
            state["n"] += 1
            import time as _t
            if state["n"] == 4:
                _t.sleep(4.0)
            body = b"clean"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _OneSlow)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/search"
    try:
        v = Validator(PAYLOAD_DIR)
        v.loader.get_payloads = lambda kind: ["payload"]
        v.timing_threshold = 3.0
        f = Finding(kind="sqli", severity="high", source="test",
                    data={"parameter": "q"}, raw_line="")
        status, reason = v.validate(f, target_url=url)
        assert status != "verified", reason
    finally:
        srv.shutdown()
