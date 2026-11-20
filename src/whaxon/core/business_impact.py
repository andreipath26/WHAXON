"""Business-impact severity and cost ranges.

Separate from technical severity. Answers "what does this cost us" and
"how urgent is this for the client," not "how bad is the CVE."

Computed at resolve time (core/severity.py), stored on the finding,
reused by the report and the web UI.

Sources for the cost ranges:

- Cyentia IRIS 2025 (Information Risk Insights Study). Used by the UK
  Department for Science, Innovation and Technology as the basis for its
  national cyber attack cost model. Median, 90th percentile, geometric
  mean losses by incident pattern.
- Verizon DBIR 2026. Median ransom payment.
- Zenodo ICS Ransomware Dataset (127 incidents). Critical-infrastructure
  incident cost columns.
- ITIC 2025. Downtime cost per hour by organisation size.
- GDPR Article 83. Regulatory fine ceiling.
- HIPAA Journal 2025. Typical settlement range.

The cost ranges are published incident distributions. The mapping from
WHAXON finding kind to incident pattern is WHAXON's derivation, not the
sources'. The report says so.
"""
from __future__ import annotations

# ── Business-impact severity bands ──────────────────────────────────
#
# Four bands, same vocabulary as technical severity:
#   critical / high / medium / low
#
# Base band per finding kind. Adapters that want a non-default band can
# declare one in their adapter metadata; this table is the fallback.

_BASE_BY_KIND = {
    "ntlm_hash": "critical",
    "sqli": "critical",
    "sqli_dump": "critical",
    "command_injection": "critical",
    "msf_session": "critical",
    "nxc_credential_admin": "critical",
    "nxc_credential": "high",
    "open_port_vulnerable": "high",
    "web_issue_exploitable": "high",
    "sysinfo": "low",
    "open_port": "low",
    "web_issue": "low",
    "suggestion": "low",
    "http_request": "low",
}

# Special handling: correlated findings inherit from the CVE CVSS band.

_BANDS = ("critical", "high", "medium", "low")


def _rank(band: str) -> int:
    try:
        return _BANDS.index(band.lower())
    except ValueError:
        return len(_BANDS) - 1


def _shift_up(band: str) -> str:
    r = _rank(band)
    if r <= 0:
        return "critical"
    return _BANDS[r - 1]


def _is_production_target(target: str) -> bool:
    """True for a hostname with a real TLD, or an IP outside RFC1918/loopback."""
    if not target:
        return False
    t = target.strip().lower()
    # Strip a port if present
    if ":" in t and not t.startswith("["):
        head = t.rsplit(":", 1)[0]
        if head.count(".") == 3 and head.replace(".", "").isdigit():
            t = head
    # Lab markers
    if t.startswith("127.") or t.startswith("10.") or t.startswith("192.168."):
        return False
    if t.startswith("172."):
        parts = t.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return False
            except ValueError:
                pass
    if t in ("localhost", "::1") or t.endswith(".test") or t.endswith(".local"):
        return False
    return not t.endswith("scanme.nmap.org")


def base_band(finding: dict) -> str:
    """Compute the business-impact band for a finding.

    Uses the kind-specific base table plus a target modifier:
    production targets shift up one band.
    """
    kind = (finding.get("kind") or "").lower()
    sev = (finding.get("severity") or "info").lower()

    # Correlated findings carry the CVSS-derived severity from the
    # severity resolver. Inherit from that when present.
    if kind in ("correlated", "vulnerable_service"):
        if sev == "critical":
            band = "critical"
        elif sev == "high":
            band = "high"
        elif sev == "medium":
            band = "medium"
        else:
            band = "low"
        target = (finding.get("data") or {}).get("target") or ""
        if _is_production_target(target):
            band = _shift_up(band)
        return band

    # open_port: escalate to high when the version matches a known-bad
    # list. The nmap adapter sets lookup_hint for versioned services.
    if kind == "open_port":
        band = "high" if finding.get("lookup_hint") else "low"
        return band

    # web_issue: escalate to high for exploitability classes.
    if kind == "web_issue":
        msg = ((finding.get("data") or {}).get("message") or "").lower()
        raw = (finding.get("raw_line") or "").lower()
        text = msg + " " + raw
        if any(k in text for k in ("sql injection", "command injection",
                                    "remote code execution", "rce",
                                    "cross-site scripting", "xss",
                                    "xxe", "ssrf", "lfi", "rfi")):
            return "high"
        return "low"

    band = _BASE_BY_KIND.get(kind, "low")

    target = (finding.get("data") or {}).get("target") or finding.get("target") or ""
    if _is_production_target(target):
        band = _shift_up(band)
    return band


# ── Cost ranges ─────────────────────────────────────────────────────
#
# One row per finding class. Values are published incident distributions,
# not WHAXON estimates. Median and 90th percentile in USD.

_COST_RANGES = {
    "credential_access": {
        "incident_pattern": "System intrusion",
        "median": 150_200,
        "p90": 7_400_000,
        "source": "Cyentia IRIS 2025",
    },
    "web_app_breach": {
        "incident_pattern": "Data breach (web app)",
        "median": 266_000,
        "p90": None,
        "source": "Cyentia IRIS 2022 (geometric mean)",
    },
    "ransomware": {
        "incident_pattern": "Ransomware",
        "median": 155_500,
        "p90": 5_000_000,
        "source": "Cyentia IRIS 2025",
    },
    "ransom_payment": {
        "incident_pattern": "Ransom payment",
        "median": 139_875,
        "p90": None,
        "source": "Verizon DBIR 2026 (median)",
    },
    "disclosure": {
        "incident_pattern": "Accidental disclosure",
        "median": 56_900,
        "p90": None,
        "source": "Cyentia IRIS 2025",
    },
}


# Kind-to-class mapping. This is WHAXON's derivation, not the sources'.

_CLASS_BY_KIND = {
    "ntlm_hash": "credential_access",
    "nxc_credential": "credential_access",
    "nxc_credential_admin": "credential_access",
    "sqli": "web_app_breach",
    "sqli_dump": "web_app_breach",
    "command_injection": "web_app_breach",
    "web_issue": "disclosure",
    "open_port": "credential_access",
    "correlated": "ransomware",
}


def cost_range(finding: dict) -> dict | None:
    """Return the cost-range row for a finding, or None when unmapped."""
    kind = (finding.get("kind") or "").lower()
    cls = _CLASS_BY_KIND.get(kind)
    if cls is None:
        return None
    row = dict(_COST_RANGES.get(cls) or {})
    if not row:
        return None
    row["finding_class"] = cls
    return row


# ── Downtime per hour (ITIC 2025) ───────────────────────────────────

DOWNTIME_PER_HOUR = {
    "small": {"usd_per_hour": 100_000, "source": "ITIC 2025"},
    "mid": {"usd_per_hour": 300_000, "source": "ITIC 2025"},
    "enterprise": {"usd_per_hour": 1_100_000, "source": "ITIC 2025"},
}


# ── Regulatory fine ceilings ────────────────────────────────────────

REGULATORY_FINES = {
    "gdpr": {
        "max": "EUR 20M or 4% of global annual turnover",
        "source": "GDPR Article 83",
    },
    "hipaa": {
        "typical_settlement_usd": (500_000, 3_000_000),
        "source": "HIPAA Journal 2025",
    },
}


# ── Report framing ──────────────────────────────────────────────────

SOURCES_NOTE = (
    "Cost ranges are published incident-cost distributions "
    "(Cyentia IRIS, Verizon DBIR, Zenodo ICS dataset, ITIC). "
    "The mapping from finding kind to incident pattern is WHAXON's "
    "derivation, not the sources'."
)
