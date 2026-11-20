"""Adapter request context roundtrip (§34.2 step 1)."""
from pathlib import Path

from whaxon.adapters.sqlmap import SqlmapAdapter
from whaxon.core.findings import Finding
from whaxon.core.validator import Validator

PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "src" / "whaxon" / "data" / "payloads"


def test_sqlmap_writes_request_context():
    lines = [
        ("stdout", "Parameter: id (GET)"),
        ("stdout", "    Type: boolean-based blind"),
        ("stdout", "    Title: AND boolean-based blind"),
        ("stdout", "    Payload: id=1 AND 1=1"),
    ]
    out = SqlmapAdapter().parse(
        lines,
        ctx={"target": "http://127.0.0.1:8080/login.php"},
    )
    assert len(out) >= 1
    finding = out[0]
    ctx = finding.data.get("_request_context")
    assert ctx is not None
    assert ctx["method"] == "GET"
    assert ctx["url"] == "http://127.0.0.1:8080/login.php"
    assert ctx["parameter"] == "id"


def test_finding_to_dict_includes_request_context():
    f = Finding(
        kind="sqli", severity="high", source="test",
        data={"parameter": "id"},
        request_context={"method": "POST", "url": "http://x/y", "body": "a=1"},
    )
    d = f.to_dict()
    assert d["request_context"]["method"] == "POST"
    assert d["request_context"]["body"] == "a=1"


def test_validator_uses_request_context():
    v = Validator(PAYLOAD_DIR)
    f = Finding(
        kind="sqli", severity="high", source="test",
        data={
            "_request_context": {
                "method": "GET",
                "url": "http://127.0.0.1:1/never",
                "parameter": "id",
            },
        },
    )
    status, reason = v.validate(f, target_url=None)
    assert status == "candidate"
    assert "authorized target URL required" in reason
    assert "no request sent" in reason
