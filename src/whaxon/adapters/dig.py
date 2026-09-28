"""Dig adapter — DNS records with light enrichment.

Dig findings are pure reconnaissance context. A and AAAA records
identify IP addresses; NS records identify DNS infrastructure; MX
records identify mail infrastructure. None of these are vulnerabilities
on their own, but they feed the correlator.
"""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register


_IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")
_MX_PRIORITY_RE = re.compile(r"^(?P<priority>\d+)\s+(?P<host>\S+\.)$")


class DigAdapter(Adapter):
    tool_id = "dig"

    def parse(self, lines, ctx=None):
        findings = []
        for stream, text in lines:
            if stream != "stdout":
                continue
            t = text.strip()
            if not t:
                continue

            if _IPV4_RE.match(t):
                findings.append(Finding(
                    kind="a_record", severity="info", source="dig",
                    data={"ip": t}, raw_line=text,
                    impact=(
                        "The IP address is the network location of the service. "
                        "Correlates with port scans to identify which open ports "
                        "belong to which hostname."
                    ),
                ))
                continue

            if ":" in t and _IPV6_RE.match(t):
                findings.append(Finding(
                    kind="aaaa_record", severity="info", source="dig",
                    data={"ip": t}, raw_line=text,
                    impact=(
                        "IPv6 address. Often overlooked in firewalls and monitoring, "
                        "so IPv6 paths may bypass controls that only cover IPv4."
                    ),
                ))
                continue

            m = _MX_PRIORITY_RE.match(t)
            if m:
                findings.append(Finding(
                    kind="mx_record", severity="info", source="dig",
                    data={"mx": m.group("host"), "priority": int(m.group("priority"))},
                    raw_line=text,
                    impact=(
                        "Mail exchanger. Correlates with SPF/DMARC posture and "
                        "identifies the mail infrastructure an attacker could target "
                        "for phishing or spoofing."
                    ),
                ))
                continue

            if "@" in t:
                findings.append(Finding(
                    kind="mx_record", severity="info", source="dig",
                    data={"mx": t}, raw_line=text,
                    impact=(
                        "Mail exchanger. Correlates with SPF/DMARC posture and "
                        "identifies the mail infrastructure an attacker could target "
                        "for phishing or spoofing."
                    ),
                ))
                continue

            if t.endswith("."):
                findings.append(Finding(
                    kind="ns_record", severity="info", source="dig",
                    data={"ns": t}, raw_line=text,
                    impact=(
                        "Nameserver infrastructure. Correlates with whois output and "
                        "helps map the DNS authority chain."
                    ),
                ))
        return findings


register(DigAdapter())