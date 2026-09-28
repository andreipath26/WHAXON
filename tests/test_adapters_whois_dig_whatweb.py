"""Tests for the whois, dig, and whatweb adapters added in session 4b-1."""
from __future__ import annotations

import json
from pathlib import Path

from whaxon.adapters.dig import DigAdapter
from whaxon.adapters.whatweb import WhatwebAdapter
from whaxon.adapters.whois import WhoisAdapter


def _stdout(lines):
    return [("stdout", l) for l in lines]


# ---------------------------------------------------------------- whois

def test_whois_parses_expiry_registrar_and_ns():
    lines = _stdout([
        "Domain Name: EXAMPLE.COM",
        "Registrar: RESERVED-INTERNET ASSIGNED NUMBERS AUTHORITY",
        "Name Server: A.IANA-SERVERS.NET",
        "Name Server: B.IANA-SERVERS.NET",
        "Registry Expiry Date: 2025-08-14T04:00:00Z",
    ])
    findings = WhoisAdapter().parse(lines)
    kinds = {f.kind for f in findings}
    assert "domain_expiry" in kinds
    assert "registrar" in kinds
    assert "nameserver" in kinds

    expiry = next(f for f in findings if f.kind == "domain_expiry")
    assert expiry.severity == "info"
    assert "2025" in expiry.data["expiry"]
    assert expiry.remediation  # non-empty
    assert expiry.impact

    registrar = next(f for f in findings if f.kind == "registrar")
    assert "ASSIGNED" in registrar.data["registrar"]

    nameservers = [f for f in findings if f.kind == "nameserver"]
    assert len(nameservers) == 2


def test_whois_dedupes_repeated_fields():
    lines = _stdout([
        "Registrar: Foo Inc.",
        "Registrar: Foo Inc.",
        "Registry Expiry Date: 2025-01-01",
        "Registry Expiry Date: 2025-01-01",
    ])
    findings = WhoisAdapter().parse(lines)
    # Only one of each despite duplicates in input
    assert sum(1 for f in findings if f.kind == "registrar") == 1
    assert sum(1 for f in findings if f.kind == "domain_expiry") == 1


def test_whois_handles_empty_input():
    assert WhoisAdapter().parse([]) == []


# ---------------------------------------------------------------- dig

def test_dig_parses_a_record():
    lines = _stdout(["45.33.32.156"])
    findings = DigAdapter().parse(lines)
    assert len(findings) == 1
    assert findings[0].kind == "a_record"
    assert findings[0].data["ip"] == "45.33.32.156"


def test_dig_parses_aaaa_record():
    lines = _stdout(["2600:3c01::f03c:91ff:fe18:bb2f"])
    findings = DigAdapter().parse(lines)
    assert len(findings) == 1
    assert findings[0].kind == "aaaa_record"


def test_dig_parses_ns_and_mx():
    lines = _stdout([
        "ns1.example.com.",
        "ns2.example.com.",
        "10 mail.example.com.",
        "20 mail2.example.com.",
    ])
    findings = DigAdapter().parse(lines)
    ns = [f for f in findings if f.kind == "ns_record"]
    mx = [f for f in findings if f.kind == "mx_record"]
    assert len(ns) == 2
    assert len(mx) == 2
    # MX records carry the priority
    mail = next(f for f in mx if "mail.example.com" in f.data["mx"])
    assert mail.data["priority"] == 10


def test_dig_parses_mx_with_at():
    lines = _stdout(["user@example.com"])
    findings = DigAdapter().parse(lines)
    assert len(findings) == 1
    assert findings[0].kind == "mx_record"


def test_dig_skips_stderr():
    lines = [
        ("stderr", "45.33.32.156"),
        ("stdout", ";; connection timed out"),
    ]
    findings = DigAdapter().parse(lines)
    assert findings == []


# ---------------------------------------------------------------- whatweb

def test_whatweb_parses_json_file(tmp_path):
    json_path = tmp_path / "whatweb.json"
    json_path.write_text(json.dumps([
        {
            "target": "http://scanme.nmap.org",
            "http_status": 200,
            "plugins": {
                "Apache": {"version": ["2.4.7"]},
                "HTTPServer": {"os": ["Ubuntu Linux"], "string": ["Apache/2.4.7"]},
                "HTML5": {},
            },
        }
    ]))
    ctx = {"extra_args": f"-a 1 scanme.nmap.org --log-json={json_path}"}
    findings = WhatwebAdapter().parse([], ctx=ctx)
    assert len(findings) == 3
    names = {f.data["plugin"] for f in findings}
    assert names == {"Apache", "HTTPServer", "HTML5"}

    apache = next(f for f in findings if f.data["plugin"] == "Apache")
    assert apache.data["version"] == "2.4.7"
    assert apache.data["target"] == "http://scanme.nmap.org"
    assert apache.remediation  # Apache has enrichment


def test_whatweb_falls_back_to_text_when_no_json():
    lines = _stdout([
        "http://scanme.nmap.org [200 OK] Apache[2.4.7], Country[RESERVED][ZZ], HTML5, IP[45.33.32.156]",
    ])
    findings = WhatwebAdapter().parse(lines)
    assert len(findings) >= 3  # Apache, Country, HTML5, IP
    names = {f.data["plugin"] for f in findings}
    assert "Apache" in names
    assert "HTML5" in names


def test_whatweb_json_missing_file_falls_back_to_text():
    lines = _stdout([
        "http://example.com [200 OK] nginx[1.20.1]",
    ])
    ctx = {"extra_args": "--log-json=/tmp/nonexistent-whatweb.json"}
    findings = WhatwebAdapter().parse(lines, ctx=ctx)
    # Falls through to text since the file is missing
    assert any(f.data["plugin"] == "nginx" for f in findings)