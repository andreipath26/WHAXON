"""Command-injection (CWE-78) detection and deterministic replay tests."""
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from whaxon.adapters.commix import CommixAdapter
from whaxon.core.findings import Finding
from whaxon.core.validator import Validator

PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "src" / "whaxon" / "data" / "payloads"


def _fake_shell(value: str) -> str:
    """Emulate `ping -c 4 <value>` behind a shell, for echo probes only."""
    out = ["PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.", "4 packets transmitted, 0% loss"]
    m = re.search(r"(?:;|\||&&)\s*echo\s+(?P<arg>.+)$", value)
    if m:
        arg = m.group("arg").strip()
        arg = re.sub(r"\$\(printf ([0-9a-f]+)\)", r"\1", arg)
        arg = arg.replace('""', "")
        out.append(arg)
    return "\n".join(out)


class _Vulnerable(BaseHTTPRequestHandler):
    """Runs the injected command (the echo probes) and returns its output."""

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse

        ip = parse_qs(urlparse(self.path).query).get("ip", [""])[0]
        body = f"<pre>{_fake_shell(ip)}</pre>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _Reflector(BaseHTTPRequestHandler):
    """Safely reflects the parameter — no command execution at all."""

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse

        ip = parse_qs(urlparse(self.path).query).get("ip", [""])[0]
        body = f"<pre>pinging {ip}</pre>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/vulnerabilities/exec/?ip=1"


def test_command_injection_is_verified_when_the_shell_runs_it():
    srv, url = _serve(_Vulnerable)
    try:
        v = Validator(PAYLOAD_DIR)
        f = Finding(kind="command_injection", severity="critical", source="commix",
                    data={"parameter": "ip", "where": "GET"}, raw_line="")
        status, reason = v.validate(f, target_url=url)
        assert status == "verified", reason
        assert "whaxon_cmdi_" in reason
        assert v.last_payload and "echo" in v.last_payload
    finally:
        srv.shutdown()


def test_payload_reflection_alone_is_not_proof():
    """A page that echoes the payload back must never verify."""
    srv, url = _serve(_Reflector)
    try:
        v = Validator(PAYLOAD_DIR)
        f = Finding(kind="command_injection", severity="critical", source="commix",
                    data={"parameter": "ip", "where": "GET"}, raw_line="")
        status, reason = v.validate(f, target_url=url)
        assert status == "candidate", reason
        assert v.last_payload is None
    finally:
        srv.shutdown()


def test_command_injection_ctx_replay_verifies():
    srv, url = _serve(_Vulnerable)
    try:
        v = Validator(PAYLOAD_DIR)
        f = Finding(
            kind="command_injection", severity="critical", source="commix",
            data={
                "parameter": "ip",
                "_request_context": {"method": "GET", "url": url, "parameter": "ip"},
            },
            raw_line="",
        )
        status, reason = v.validate(f, target_url=url)
        assert status == "verified", reason
        assert "whaxon_cmdi_" in reason
    finally:
        srv.shutdown()


def test_probe_marker_never_appears_in_the_submitted_payload():
    for payload, marker in Validator._cmdi_probes():
        assert marker not in payload
        assert "echo" in payload


COMMIX_OUTPUT = [
    ("stdout", "                      __"),
    ("stdout", "  ___  ___  __  __  ___  __  __"),
    ("stdout", "[*] Testing the (POST) 'ip' parameter..."),
    ("stdout", "[+] The (POST) 'ip' parameter is vulnerable to OS command injection."),
    ("stdout", "[+] Type: results-based"),
    ("stdout", "[+] Payload: 127.0.0.1;echo kWUxQw"),
    ("stdout", ""),
    ("stderr", "[!] something unrelated"),
]


def test_commix_adapter_reports_cwe_78_finding():
    findings = CommixAdapter().parse(COMMIX_OUTPUT)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "command_injection"
    assert f.severity == "critical"
    assert f.cwe == "CWE-78"
    assert f.source == "commix"
    assert f.data["parameter"] == "ip"
    assert f.data["where"] == "POST"
    assert f.data["type"] == "results-based"
    assert f.data["payload"] == "127.0.0.1;echo kWUxQw"
    assert f.remediation and f.impact


COMMIX_V4_OUTPUT = [
    ("stdout", "[09:55:54] [info] Testing connection to the target URL."),
    ("stdout", "\x1b[1m[09:56:05] [info] Setting POST parameter 'ip' for tests.\x1b[0m"),
    ("stdout", "[09:56:05] [info] Heuristic (basic) test shows that POST parameter 'ip' might be injectable"),
    ("stdout", "[09:56:06] [info] POST parameter 'ip' appears to be injectable via results-based classic command injection technique."),
    ("stdout", "POST parameter 'ip' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N"),
    ("stdout", "Identified the following injection point(s) with a total of 7 HTTP(S) requests:"),
    ("stdout", "Parameter: ip (POST)"),
    ("stdout", " * Technique: Results-based"),
    ("stdout", " * Type: Classic command injection"),
    ("stdout", " * Payload: VUZ;echo XDEZJP$((27+8))$(echo XDEZJP)XDEZJP;"),
    ("stdout", "[09:56:06] [info] Fetching the target environment."),
]


def test_commix_v4_output_yields_one_finding_per_injection_point():
    findings = CommixAdapter().parse(COMMIX_V4_OUTPUT)
    assert len(findings) == 1, [f.raw_line for f in findings]
    f = findings[0]
    assert f.kind == "command_injection"
    assert f.cwe == "CWE-78"
    assert f.data["parameter"] == "ip"
    assert f.data["where"] == "POST"
    assert f.data["technique"] == "Results-based"
    assert f.data["type"] == "Classic command injection"
    assert f.data["payload"].startswith("VUZ;echo")


def test_commix_heuristic_hint_alone_is_not_a_finding():
    """'might be injectable' is a hint, not a confirmed verdict."""
    lines = [("stdout", "[09:56:05] [info] Heuristic (basic) test shows that POST parameter 'ip' might be injectable")]
    assert CommixAdapter().parse(lines) == []


def test_request_context_is_built_for_get_targets():
    lines = [("stdout", "[+] The (GET) 'q' parameter is vulnerable to OS command injection.")]
    findings = CommixAdapter().parse(lines, ctx={"target": "http://127.0.0.1:8099/search?q=1"})
    ctx = findings[0].data["_request_context"]
    assert ctx["method"] == "GET"
    assert ctx["url"] == "http://127.0.0.1:8099/search?q=1"
    assert ctx["parameter"] == "q"


def test_request_context_carries_the_post_body_from_extra_args():
    findings = CommixAdapter().parse(
        COMMIX_V4_OUTPUT,
        ctx={
            "target": "https://example.test/vulnerabilities/exec/",
            "extra_args": '--data="ip=127.0.0.1&Submit=Submit" --cookie="security=low"',
        },
    )
    ctx = findings[0].data["_request_context"]
    assert ctx["method"] == "POST"
    assert ctx["body"] == "ip=127.0.0.1&Submit=Submit"
    assert ctx["parameter"] == "ip"


def test_no_request_context_without_an_absolute_target():
    findings = CommixAdapter().parse(COMMIX_V4_OUTPUT, ctx={"target": "127.0.0.1"})
    assert "_request_context" not in findings[0].data


def test_commix_adapter_ignores_noise_and_duplicates():
    lines = [
        ("stdout", "[*] Starting commix..."),
        ("stdout", "[+] The (GET) 'q' parameter appears to be injectable to OS command injection."),
        ("stdout", "[+] The (GET) 'q' parameter appears to be injectable to OS command injection."),
        ("stderr", "[!] connection dropped"),
    ]
    findings = CommixAdapter().parse(lines)
    assert len(findings) == 1
    assert findings[0].data["parameter"] == "q"
    assert findings[0].data["where"] == "GET"
