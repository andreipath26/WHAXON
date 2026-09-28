"""Whois adapter — domain registration data with light enrichment.

Whois findings are informational — they don't represent vulnerabilities.
But they provide context the correlator can use: registrar (privacy
posture), nameservers (DNS infrastructure), domain expiry (operational
risk if a domain lapses). Enrichment is minimal by design.
"""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register


_EXPIRY_RE = re.compile(
    r"^(?:Registry Expiry Date|Expiry Date|paid-till|expiration date):\s*(?P<date>.+)$",
    re.IGNORECASE,
)
_REGISTRAR_RE = re.compile(r"^Registrar:\s*(?P<name>.+)$", re.IGNORECASE)
_NS_RE = re.compile(r"^Name Server:\s*(?P<ns>\S+)", re.IGNORECASE)


class WhoisAdapter(Adapter):
    tool_id = "whois"

    def parse(self, lines, ctx=None):
        findings = []
        seen = set()
        for stream, text in lines:
            t = text.strip()

            m = _EXPIRY_RE.match(t)
            if m and "expiry" not in seen:
                seen.add("expiry")
                expiry = m.group("date").strip()
                findings.append(Finding(
                    kind="domain_expiry",
                    severity="info",
                    source="whois",
                    data={"expiry": expiry},
                    raw_line=text,
                    remediation=(
                        "Confirm the domain is set to auto-renew, and monitor the "
                        "expiry date. A lapsed domain can be registered by a third "
                        "party, who then controls DNS for the whole organization."
                    ),
                    impact=(
                        "Domain expiry is an operational and security risk. In a "
                        "domain takeover scenario, an attacker who re-registers the "
                        "domain controls mail, DNS, and any service that trusts it."
                    ),
                ))
                continue

            m = _REGISTRAR_RE.match(t)
            if m and "registrar" not in seen:
                seen.add("registrar")
                findings.append(Finding(
                    kind="registrar",
                    severity="info",
                    source="whois",
                    data={"registrar": m.group("name").strip()},
                    raw_line=text,
                    impact=(
                        "The registrar is the organization that controls the domain "
                        "registration. Registrar compromise or account takeover is a "
                        "common path to full DNS control."
                    ),
                ))
                continue

            m = _NS_RE.match(t)
            if m:
                ns = m.group("ns")
                key = ("ns", ns)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        kind="nameserver",
                        severity="info",
                        source="whois",
                        data={"ns": ns},
                        raw_line=text,
                        impact=(
                            "Nameservers hold DNS authority for the domain. Compromise "
                            "or misconfiguration permits DNS hijacking, subdomain "
                            "takeover, and mail redirection."
                        ),
                    ))
        return findings


register(WhoisAdapter())
