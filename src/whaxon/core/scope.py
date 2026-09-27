"""Scope enforcement — check whether a target is authorized for testing.

The scope file lives at `<data_dir>/scope.json` and looks like:

    {
      "engagement": "Acme Q3 pentest",
      "enabled": true,
      "in_scope": ["acme.com", "*.acme.com", "10.0.0.0/24"],
      "out_of_scope": ["prod.acme.com"],
      "notes": "Testing window: Mon-Fri 09:00-18:00 UTC."
    }

Rules:
- out_of_scope always wins over in_scope.
- If no scope file exists, or enabled is false, every target is allowed.
- Supports exact hosts, wildcards (*.example.com), CIDR ranges, and bare IPs.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeMatch:
    allowed: bool
    reason: str = ""
    matched_rule: str = ""

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "reason": self.reason,
                "matched_rule": self.matched_rule}


class OutOfScopeError(RuntimeError):
    """Raised when a target is outside the declared scope and no override was given."""
    def __init__(self, target: str, reason: str, matched_rule: str = "") -> None:
        self.target = target
        self.reason = reason
        self.matched_rule = matched_rule
        super().__init__(f"Out of scope: {target} — {reason}")


def _normalize_target(raw: str) -> tuple[str, str]:
    """Return (host, kind) where kind is 'host', 'ip', or 'url'.

    - URLs are parsed and their host extracted.
    - Hostnames are lowercased.
    - Trailing dots are stripped.
    - A scheme-less host with a port (host:port) keeps just the host.
    """
    if not raw:
        return "", "host"
    raw = raw.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        return host.lower().rstrip("."), "url"
    # Bare host or IP, possibly with :port
    host = raw.split("/", 1)[0]  # strip any path
    if ":" in host and not _looks_like_ipv6(host):
        host = host.rsplit(":", 1)[0]  # strip port
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host, "ip"
    except ValueError:
        return host, "host"


def _looks_like_ipv6(s: str) -> bool:
    return s.count(":") >= 2


def _rule_matches_host(rule: str, host: str) -> bool:
    """Match a rule against a host. Supports exact and wildcard (*.example.com)."""
    rule = rule.lower().rstrip(".")
    if rule == host:
        return True
    if rule.startswith("*."):
        suffix = rule[2:]
        # *.example.com matches sub.example.com but not example.com itself
        if host == suffix:
            return False
        return host.endswith("." + suffix)
    return False


def _rule_matches_ip(rule: str, ip: str) -> bool:
    """Match a rule against an IP. Supports exact and CIDR."""
    try:
        if "/" in rule:
            net = ipaddress.ip_network(rule, strict=False)
            addr = ipaddress.ip_address(ip)
            return addr in net
        else:
            return str(ipaddress.ip_address(rule)) == ip
    except ValueError:
        return False


class ScopeManager:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._enabled = False
        self._engagement = ""
        self._in: list[str] = []
        self._out: list[str] = []
        self._notes = ""
        self.load()

    # ---- loading ----

    def load(self) -> None:
        if not self.path.exists():
            self._enabled = False
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            self._enabled = False
            return
        self._enabled = bool(raw.get("enabled", True))
        self._engagement = str(raw.get("engagement", "") or "")
        self._in = [str(x) for x in (raw.get("in_scope") or [])]
        self._out = [str(x) for x in (raw.get("out_of_scope") or [])]
        self._notes = str(raw.get("notes", "") or "")

    def save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.load()

    # ---- properties ----

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def engagement(self) -> str:
        return self._engagement

    @property
    def in_scope(self) -> list[str]:
        return list(self._in)

    @property
    def out_of_scope(self) -> list[str]:
        return list(self._out)

    @property
    def notes(self) -> str:
        return self._notes

    def summary(self) -> dict:
        return {
            "enabled": self._enabled,
            "engagement": self._engagement,
            "in_scope": list(self._in),
            "out_of_scope": list(self._out),
            "notes": self._notes,
            "path": str(self.path),
        }

    # ---- the check ----

    def check(self, raw_target: str) -> ScopeMatch:
        if not self._enabled:
            return ScopeMatch(allowed=True, reason="scope disabled")

        host, kind = _normalize_target(raw_target)
        if not host:
            return ScopeMatch(allowed=False, reason="empty target", matched_rule="")

        # Out-of-scope wins
        for rule in self._out:
            if kind == "ip" and _rule_matches_ip(rule, host):
                return ScopeMatch(False, "matches out-of-scope rule", rule)
            if _rule_matches_host(rule, host):
                return ScopeMatch(False, "matches out-of-scope rule", rule)

        # In-scope required
        for rule in self._in:
            if kind == "ip" and _rule_matches_ip(rule, host):
                return ScopeMatch(True, "matches in-scope rule", rule)
            if _rule_matches_host(rule, host):
                return ScopeMatch(True, "matches in-scope rule", rule)

        return ScopeMatch(False, "no matching in-scope rule", "")
