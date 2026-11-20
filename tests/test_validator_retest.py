"""Retest loop tests (§34.2 step 3)."""
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from whaxon.core.findings import Finding
from whaxon.core.validator import Validator

PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "src" / "whaxon" / "data" / "payloads"


class _Flaky(BaseHTTPRequestHandler):
    _calls = {"n": 0}

    def do_GET(self):
        _Flaky._calls["n"] += 1
        # validate() with median-of-3 makes 6 calls:
        #   calls 1-3: baseline,  calls 4-6: injected.
        # revalidate() likewise makes 6 calls: 7-9 baseline, 10-12 injected.
        # Marker only on the injected calls of validate() (4-6),
        # so validate() verifies, but revalidate() cannot prove the issue is fixed.
        if 4 <= _Flaky._calls["n"] <= 6:
            body = b"You have an error in your SQL syntax"
        else:
            body = b"clean response"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_revalidate_reports_inconclusive_when_proof_disappears():
    _Flaky._calls["n"] = 0
    srv = HTTPServer(("127.0.0.1", 0), _Flaky)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/search"
    try:
        v = Validator(PAYLOAD_DIR)
        v.loader.get_payloads = lambda kind: ["' OR 1=1 --"]
        f = Finding(
            kind="sqli", severity="high", source="test",
            data={"parameter": "q"}, raw_line="",
        )
        status, _ = v.validate(f, target_url=url)
        assert status == "verified"
        retest_status, reason = v.revalidate(f, target_url=url)
        assert retest_status == "inconclusive", reason
    finally:
        srv.shutdown()


def test_retest_cli_refuses_unverified(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from whaxon.core import Core
    from whaxon.interfaces.cli import retest_cmd

    core = Core(tmp_path / "data")
    asyncio.run(core.initialize())
    core.store.create("job1")

    f = Finding(kind="sqli", severity="high", source="test",
                data={"parameter": "id"}, raw_line="test")
    core.store.append_finding("job1", f, 1)

    rc = retest_cmd.main(["job1", "1"])
    assert rc == retest_cmd.EXIT_NOT_VERIFIED

def test_retest_cli_refuses_out_of_scope_target(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    from whaxon.core import Core
    from whaxon.interfaces.cli import retest_cmd

    core = Core(tmp_path / "data")
    asyncio.run(core.initialize())
    core.store.create("outside")
    core.store.set_started("outside", "sqlmap", "google.com")
    finding = Finding(kind="sqli", severity="high", source="test",
                      data={"parameter": "id"}, raw_line="test")
    core.store.append_finding("outside", finding, 1)
    core.store.update_verification("outside", 1, "verified", by="test", reason="seed")

    rc = retest_cmd.main(["outside", "1"])
    assert rc == retest_cmd.EXIT_SCOPE_BLOCKED
    assert "out of scope" in capsys.readouterr().err.lower()


def test_retest_cli_refuses_to_mutate_engine_v2_evidence(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    from whaxon.core import Core
    from whaxon.interfaces.cli import retest_cmd

    core = Core(tmp_path / "data")
    asyncio.run(core.initialize(drain=False))
    core.store.create("0123456789ab")
    core.store.set_started("0123456789ab", "verify_sqli", "127.0.0.1:80")
    finding = Finding(kind="sqli", severity="high", source="engine-v2-verifier",
                      data={"parameter": "id"}, raw_line="verified")
    core.store.append_finding("0123456789ab", finding, 0)
    core.store.update_verification("0123456789ab", 0, "verified", by="engine-v2")
    core.store.mark_engine_v2_execution_job("0123456789ab")

    rc = retest_cmd.main(["0123456789ab", "0"])

    assert rc == retest_cmd.EXIT_V2_WORKFLOW_REQUIRED
    assert "plan propose-verification" in capsys.readouterr().err
    assert core.store.get_findings("0123456789ab")[0]["verification_status"] == "verified"

def test_retest_cli_blocks_legacy_execution_by_default(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    from whaxon.core import Core
    from whaxon.interfaces.cli import retest_cmd

    core = Core(tmp_path / "data")
    asyncio.run(core.initialize(drain=False))
    core.store.create("job1")
    core.store.set_started("job1", "sqlmap", "127.0.0.1:80")
    finding = Finding(kind="sqli", severity="high", source="test",
                      data={"parameter": "id"}, raw_line="test")
    core.store.append_finding("job1", finding, 1)
    core.store.update_verification("job1", 1, "verified", by="test", reason="seed")

    rc = retest_cmd.main(["job1", "1"])

    assert rc == retest_cmd.EXIT_V2_WORKFLOW_REQUIRED
    assert "no request was sent" in capsys.readouterr().err
    assert core.store.get_findings("job1")[0]["verification_status"] == "verified"

