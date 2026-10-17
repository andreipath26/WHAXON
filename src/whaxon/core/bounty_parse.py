"""Parse a pasted YesWeHack program page into a policy dict (§26.1).

No network. The human copies the program page text and passes it here.
Heuristics only; the output is reviewed and corrected by the operator.
"""
from __future__ import annotations

import re

_SLUG_RE = re.compile(r"Public programs\s*\n\s*(.+?)\s*\n", re.MULTILINE)
_REWARD_ROW_RE = re.compile(
    r"^(Critical|High|Medium|Low|Very low)\s*\n\s*€(\d+)\s*\n\s*€(\d+)\s*\n\s*€(\d+)\s*\n\s*€(\d+)",
    re.MULTILINE,
)
_SCOPE_RE = re.compile(
    r"^(https?://\S+|\*\.\S+|\S+\.(?:com|fr|co|io|de|net|org)\S*)\s*\n\s*"
    r"(Web application|API|Wildcard|Mobile application \w+|Other)\s*\n\s*"
    r"(Critical|High|Medium|Low|Very low)",
    re.MULTILINE,
)
_UA_RE = re.compile(r"user-agent[^\n]*?following value:\s*'([^']+)'", re.IGNORECASE)
_REPORTS_RE = re.compile(r"^Reports\s*\n\s*(\d+|-)", re.MULTILINE)
_FIRST_RESP_RE = re.compile(r"^1st response\s*\n\s*(< 1 day|< \d+ days|-)", re.MULTILINE)
_MAX_REWARD_RE = re.compile(r"^Max reward\s*\n\s*(€[\d,]+|-)", re.MULTILINE)

_ASSET_MAP = {"critical": "critical", "high": "high", "medium": "medium",
              "low": "low", "very low": "very_low"}


def _reward_grid(text: str) -> list[dict]:
    rows = []
    for m in _REWARD_ROW_RE.finditer(text):
        av = m.group(1).lower()
        rows.append({"asset_value": _ASSET_MAP[av],
                     "low": int(m.group(2)), "medium": int(m.group(3)),
                     "high": int(m.group(4)), "critical": int(m.group(5))})
    return rows


def _scopes(text: str) -> list[dict]:
    out = []
    for m in _SCOPE_RE.finditer(text):
        typ = m.group(2).lower().replace(" ", "_").replace("application", "app")
        out.append({"scope": m.group(1), "type": typ,
                    "asset_value": _ASSET_MAP[m.group(3).lower()]})
    return out


def parse_yeswehack(text: str, slug: str = "") -> dict:
    """Return a policy dict populated from the pasted program text."""
    title_m = _SLUG_RE.search(text)
    title = title_m.group(1).strip() if title_m else slug
    grid = _reward_grid(text)
    scopes = _scopes(text)
    ua = _UA_RE.search(text)
    mx = _MAX_REWARD_RE.search(text)
    _FIRST_RESP_RE.search(text)
    max_reward = None
    if mx and mx.group(1) != "-":
        max_reward = int(mx.group(1).replace("€", "").replace(",", ""))
    return {
        "slug": slug or title.lower().replace(" ", "-"),
        "platform": "yeswehack",
        "program_url": f"https://yeswehack.com/programs/{slug}" if slug else "",
        "title": title,
        "organization": "",
        "program_type": "bug_bounty",
        "visibility": "public",
        "last_reviewed": None,
        "last_update": None,
        "supported_languages": ["en"],
        "identity": {"user_agent_suffix": ua.group(1) if ua else "",
                     "email_alias": "", "hunter_username": ""},
        "account_access": {"mode": "self_register", "notes": "", "vpn_required": False},
        "rate": {"max_requests_per_second": 2, "max_concurrent_connections": 1,
                 "respect_robots_txt": False},
        "reward_model": {"type": "grid", "currency": "EUR", "grid": grid,
                         "max_reward": max_reward, "avg_reward": None,
                         "systemic_decay": []},
        "scope": {"in_scope": scopes, "out_of_scope": []},
        "hunting_requirements": {
            "proof_of_exploitation": "", "first_reporter_wins": True,
            "reporting_window_hours": None,
            "disclosure_allowed": "no vulnerability disclosure" not in text.lower(),
            "automated_scanners": "forbidden" if "automated scanner" in text.lower() else "limited",
            "data_handling": "",
        },
        "tools": {"mode": "denylist", "allowlist": [],
                  "denylist": ["nmap", "nikto", "ffuf", "nuclei", "sqlmap"]},
        "ai_policy": {"allow_action_selection": False, "allow_live_requests": False,
                      "allow_auto_mode": False, "require_human_confirm": True},
        "reporting": {"platform_form": "yeswehack",
                      "required_fields": ["description", "exploit", "impact",
                                          "remediation", "proof", "repro_steps"],
                      "title_format": None},
        "bug_classes": {"qualifying": [], "non_qualifying": []},
        "platform_extras": {"yeswehack": {"credits_cost": None,
                                          "hunters_collaboration": True,
                                          "max_collaborators": 5}},
        "population": "clipboard_parse",
        "override_log": {"path": "", "append_only": True, "cross_check_at_report": True},
    }
