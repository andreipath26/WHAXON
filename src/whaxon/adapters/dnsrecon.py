"""dnsrecon adapter — DNS records from a JSON dump.

dnsrecon with -j writes a JSON array. Each element has a "type" field;
the adapter maps record types to Finding kinds.

Shape (per element):
    A / AAAA      -> name, address, domain
    MX            -> exchange, address, domain
    NS            -> target, address, domain, recursive
    SOA           -> mname, address, domain
    TXT           -> strings, name, domain
    ScanInfo      -> arguments, date   (skipped; metadata)
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..core.findings import Finding
from .base import Adapter
from .registry import register


_J_PATH_RE = re.compile(r"(?:-j|--json)\s+(\S+)")

_log = logging.getLogger(__name__)


_IMPACT = {
    "A": "IPv4 address. Correlates with port scans to identify which services are exposed.",
    "AAAA": "IPv6 address. Often overlooked in firewalls and monitoring.",
    "MX": "Mail exchanger. Correlates with SPF / DMARC posture.",
    "NS": "Nameserver. Maps DNS authority chain.",
    "SOA": "Start of Authority. Names the primary nameserver for the zone.",
    "TXT": "TXT record. May disclose SPF, DMARC, DKIM, or verification tokens.",
}


def _mk_finding(rec_type, rec, raw_line):
    impact = _IMPACT.get(rec_type, "")
    if rec_type == "A":
        return Finding(
            kind="dns_a", severity="info", source="dnsrecon",
            data={"name": rec.get("name", ""), "address": rec.get("address", "")},
            raw_line=raw_line, impact=impact,
        )
    if rec_type == "AAAA":
        return Finding(
            kind="dns_aaaa", severity="info", source="dnsrecon",
            data={"name": rec.get("name", ""), "address": rec.get("address", "")},
            raw_line=raw_line, impact=impact,
        )
    if rec_type == "MX":
        return Finding(
            kind="dns_mx", severity="info", source="dnsrecon",
            data={"exchange": rec.get("exchange", ""), "address": rec.get("address", "")},
            raw_line=raw_line, impact=impact,
        )
    if rec_type == "NS":
        return Finding(
            kind="dns_ns", severity="info", source="dnsrecon",
            data={"target": rec.get("target", ""), "address": rec.get("address", "")},
            raw_line=raw_line, impact=impact,
        )
    if rec_type == "SOA":
        return Finding(
            kind="dns_soa", severity="info", source="dnsrecon",
            data={"mname": rec.get("mname", ""), "address": rec.get("address", "")},
            raw_line=raw_line, impact=impact,
        )
    if rec_type == "TXT":
        return Finding(
            kind="dns_txt", severity="info", source="dnsrecon",
            data={"name": rec.get("name", ""), "strings": rec.get("strings", "")},
            raw_line=raw_line, impact=impact,
        )
    return None


class DnsreconAdapter(Adapter):
    tool_id = "dnsrecon"

    def _json_path(self, ctx):
        ctx = ctx or {}
        explicit = ctx.get("outfile") or ""
        if explicit:
            p = Path(explicit)
            return p if p.exists() else None
        extra = ctx.get("extra_args") or ""
        m = _J_PATH_RE.search(extra)
        if not m:
            return None
        p = Path(m.group(1))
        return p if p.exists() else None

    def parse(self, lines, ctx=None):
        ctx = ctx or {}
        path = self._json_path(ctx)
        if path is None:
            if ctx.get("outfile") or _J_PATH_RE.search(ctx.get("extra_args") or ""):
                _log.warning(
                    "dnsrecon: output file expected but not found "
                    "(outfile=%r extra_args=%r)",
                    ctx.get("outfile"), ctx.get("extra_args"),
                )
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        if not isinstance(data, list):
            return []
        findings = []
        for rec in data:
            rec_type = rec.get("type")
            if rec_type in (None, "ScanInfo"):
                continue
            f = _mk_finding(rec_type, rec, raw_line=json.dumps(rec))
            if f is not None:
                findings.append(f)
        return findings


register(DnsreconAdapter())
