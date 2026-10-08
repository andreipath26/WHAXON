"""Tests for the theHarvester and dnsrecon adapters.

Covers:
- theHarvester JSON parsing (hosts, emails)
- theHarvester hostname normalization (DuckDuckGo 2F artifact strip)
- theHarvester missing-file behavior (returns [], logs warning)
- theHarvester prefers ctx["outfile"] over extra_args regex
- dnsrecon JSON parsing (A, AAAA, MX, NS, SOA, TXT)
- dnsrecon skips ScanInfo
- dnsrecon missing-file behavior
- dnsrecon prefers ctx["outfile"] over extra_args regex
"""
from __future__ import annotations

import json
import logging

from whaxon.adapters.dnsrecon import DnsreconAdapter
from whaxon.adapters.theharvester import TheHarvesterAdapter

# --------------------------------------------------------------- helpers

def _write_json(tmp_path, name, payload):
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


# --------------------------------------------------------------- theHarvester

def test_th_parses_hosts(tmp_path):
    p = _write_json(tmp_path, "th.json", {
        "cmd": "-d example.com -b duckduckgo -f th.json",
        "hosts": ["a.example.com", "b.example.com"],
        "emails": [],
    })
    a = TheHarvesterAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 2
    assert {f.data["host"] for f in out} == {"a.example.com", "b.example.com"}
    assert all(f.kind == "hostname" for f in out)
    assert all(f.source == "theharvester" for f in out)


def test_th_parses_emails(tmp_path):
    p = _write_json(tmp_path, "th.json", {
        "hosts": [],
        "emails": ["admin@example.com", "info@example.com"],
    })
    a = TheHarvesterAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 2
    assert {f.data["email"] for f in out} == {"admin@example.com", "info@example.com"}
    assert all(f.kind == "email" for f in out)


def test_th_strips_duckduckgo_2f_artifact(tmp_path):
    p = _write_json(tmp_path, "th.json", {"hosts": ["2Fdocs.kali.org"], "emails": []})
    a = TheHarvesterAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 1
    assert out[0].data["host"] == "docs.kali.org"


def test_th_preserves_legit_2f_host(tmp_path):
    p = _write_json(tmp_path, "th.json", {"hosts": ["2F.example.com"], "emails": []})
    a = TheHarvesterAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 1
    assert out[0].data["host"] == "2F.example.com"


def test_th_drops_malformed_hosts(tmp_path, caplog):
    p = _write_json(tmp_path, "th.json", {
        "hosts": ["ok.example.com", "-bad.example.com", "", ".", "a" * 64 + ".com"],
        "emails": [],
    })
    a = TheHarvesterAdapter()
    with caplog.at_level(logging.DEBUG, logger="whaxon.adapters.theharvester"):
        out = a.parse([], ctx={"outfile": str(p)})
    assert [f.data["host"] for f in out] == ["ok.example.com"]
    assert any("dropped malformed host" in r.message for r in caplog.records)


def test_th_missing_file_returns_empty_and_warns(caplog):
    a = TheHarvesterAdapter()
    with caplog.at_level(logging.WARNING, logger="whaxon.adapters.theharvester"):
        out = a.parse([], ctx={"outfile": "/tmp/does-not-exist-th.json"})
    assert out == []
    assert any("output file expected but not found" in r.message for r in caplog.records)


def test_th_no_ctx_no_warning(caplog):
    a = TheHarvesterAdapter()
    with caplog.at_level(logging.WARNING, logger="whaxon.adapters.theharvester"):
        out = a.parse([], ctx={})
    assert out == []
    assert not any("output file expected" in r.message for r in caplog.records)


def test_th_prefers_ctx_outfile_over_extra_args(tmp_path):
    p = _write_json(tmp_path, "th.json", {"hosts": ["ctx.example.com"], "emails": []})
    a = TheHarvesterAdapter()
    out = a.parse([], ctx={
        "outfile": str(p),
        "extra_args": "-f /nonexistent/other.json",
    })
    assert [f.data["host"] for f in out] == ["ctx.example.com"]


def test_th_falls_back_to_extra_args_regex(tmp_path):
    p = _write_json(tmp_path, "th.json", {"hosts": ["legacy.example.com"], "emails": []})
    a = TheHarvesterAdapter()
    out = a.parse([], ctx={"extra_args": f"-d example.com -f {p}"})
    assert [f.data["host"] for f in out] == ["legacy.example.com"]


def test_th_empty_json_returns_empty(tmp_path):
    p = _write_json(tmp_path, "th.json", {"hosts": [], "emails": []})
    a = TheHarvesterAdapter()
    assert a.parse([], ctx={"outfile": str(p)}) == []


# --------------------------------------------------------------- dnsrecon

def _dnsrec(**kw):
    base = {"domain": "example.com", "type": "A", "address": "1.2.3.4", "name": "example.com"}
    base.update(kw)
    return base


def test_dr_parses_a(tmp_path):
    p = _write_json(tmp_path, "dr.json", [_dnsrec(type="A", address="1.2.3.4", name="example.com")])
    a = DnsreconAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 1
    assert out[0].kind == "dns_a"
    assert out[0].data == {"name": "example.com", "address": "1.2.3.4"}


def test_dr_parses_aaaa(tmp_path):
    p = _write_json(tmp_path, "dr.json", [_dnsrec(type="AAAA", address="2606:4700::1", name="example.com")])
    a = DnsreconAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 1
    assert out[0].kind == "dns_aaaa"
    assert out[0].data["address"] == "2606:4700::1"


def test_dr_parses_mx(tmp_path):
    p = _write_json(tmp_path, "dr.json", [_dnsrec(type="MX", exchange="mail.example.com", address="5.6.7.8")])
    a = DnsreconAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 1
    assert out[0].kind == "dns_mx"
    assert out[0].data == {"exchange": "mail.example.com", "address": "5.6.7.8"}


def test_dr_parses_ns(tmp_path):
    p = _write_json(tmp_path, "dr.json", [_dnsrec(type="NS", target="ns1.example.com", address="9.9.9.9")])
    a = DnsreconAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 1
    assert out[0].kind == "dns_ns"
    assert out[0].data == {"target": "ns1.example.com", "address": "9.9.9.9"}


def test_dr_parses_soa(tmp_path):
    p = _write_json(tmp_path, "dr.json", [_dnsrec(type="SOA", mname="ns1.example.com", address="9.9.9.9")])
    a = DnsreconAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 1
    assert out[0].kind == "dns_soa"
    assert out[0].data == {"mname": "ns1.example.com", "address": "9.9.9.9"}


def test_dr_parses_txt(tmp_path):
    p = _write_json(tmp_path, "dr.json", [_dnsrec(type="TXT", name="example.com", strings="v=spf1 -all")])
    a = DnsreconAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 1
    assert out[0].kind == "dns_txt"
    assert out[0].data == {"name": "example.com", "strings": "v=spf1 -all"}


def test_dr_skips_scaninfo(tmp_path):
    p = _write_json(tmp_path, "dr.json", [
        {"type": "ScanInfo", "arguments": "/usr/bin/dnsrecon -d example.com", "date": "now"},
        _dnsrec(type="A"),
    ])
    a = DnsreconAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 1
    assert out[0].kind == "dns_a"


def test_dr_skips_unknown_type(tmp_path):
    p = _write_json(tmp_path, "dr.json", [{"type": "CAA"}, _dnsrec(type="A")])
    a = DnsreconAdapter()
    out = a.parse([], ctx={"outfile": str(p)})
    assert len(out) == 1
    assert out[0].kind == "dns_a"


def test_dr_missing_file_returns_empty_and_warns(caplog):
    a = DnsreconAdapter()
    with caplog.at_level(logging.WARNING, logger="whaxon.adapters.dnsrecon"):
        out = a.parse([], ctx={"outfile": "/tmp/does-not-exist-dr.json"})
    assert out == []
    assert any("output file expected but not found" in r.message for r in caplog.records)


def test_dr_no_ctx_no_warning(caplog):
    a = DnsreconAdapter()
    with caplog.at_level(logging.WARNING, logger="whaxon.adapters.dnsrecon"):
        out = a.parse([], ctx={})
    assert out == []
    assert not any("output file expected" in r.message for r in caplog.records)


def test_dr_prefers_ctx_outfile_over_extra_args(tmp_path):
    p = _write_json(tmp_path, "dr.json", [_dnsrec(type="A", address="1.1.1.1")])
    a = DnsreconAdapter()
    out = a.parse([], ctx={
        "outfile": str(p),
        "extra_args": "-j /nonexistent/other.json",
    })
    assert len(out) == 1
    assert out[0].data["address"] == "1.1.1.1"


def test_dr_falls_back_to_extra_args_regex(tmp_path):
    p = _write_json(tmp_path, "dr.json", [_dnsrec(type="A", address="2.2.2.2")])
    a = DnsreconAdapter()
    out = a.parse([], ctx={"extra_args": f"-d example.com -j {p} -t std"})
    assert len(out) == 1
    assert out[0].data["address"] == "2.2.2.2"


def test_dr_non_list_json_returns_empty(tmp_path):
    p = _write_json(tmp_path, "dr.json", {"not": "a list"})
    a = DnsreconAdapter()
    assert a.parse([], ctx={"outfile": str(p)}) == []


def test_dr_malformed_json_returns_empty(tmp_path):
    p = tmp_path / "dr.json"
    p.write_text("{not valid json", encoding="utf-8")
    a = DnsreconAdapter()
    assert a.parse([], ctx={"outfile": str(p)}) == []


# --------------------------------------------------------------- registry

def test_both_adapters_registered():
    from whaxon.adapters import get_adapter, list_adapters
    names = list_adapters()
    assert "theharvester" in names
    assert "dnsrecon" in names
    assert get_adapter("theharvester") is not None
    assert get_adapter("dnsrecon") is not None