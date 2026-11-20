"""Scope enforcement — check whether a target is authorized for testing.

The scope file lives at `<data_dir>/scope.json` and looks like:

    {
      "engagement": "Acme Q3 pentest",
      "enabled": true,
      "in_scope": ["127.0.0.1", "acme.com", "*.acme.com", "10.0.0.0/24"],
      "out_of_scope": ["prod.acme.com"],
      "notes": "Testing window: Mon-Fri 09:00-18:00 UTC."
    }

Rules:
- out_of_scope always wins over in_scope.
- If enabled is false, every target is allowed. This is a deliberate,
  operator-set value; it must never be the result of a missing or
  malformed config file.
- If no scope file exists, a strict default is written on first load:
  loopback + RFC1918 only. Anything else is denied.
- A malformed scope file is a fatal error: refuse to run rather than
  silently allow everything.
- Supports exact hosts, wildcards (*.example.com), CIDR ranges, and bare IPs.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeMatch:
    allowed: bool
    reason: str = ""
    matched_rule: str = ""
    overridable: bool = True

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "reason": self.reason,
                "matched_rule": self.matched_rule}


@dataclass(frozen=True)
class PinnedSocketAddress:
    """One numeric socket destination, with no hostname left to re-resolve."""

    family: int
    socktype: int
    proto: int
    sockaddr: tuple


@dataclass(frozen=True)
class ScopeResolution:
    """Scope decision and canonical numeric destinations for a pinned connect."""

    match: ScopeMatch
    addresses: tuple[PinnedSocketAddress, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.match.allowed

    @property
    def reason(self) -> str:
        return self.match.reason

    @property
    def matched_rule(self) -> str:
        return self.match.matched_rule


class OutOfScopeError(RuntimeError):
    """Raised when a target is outside the declared scope and no override was given."""
    def __init__(
        self, target: str, reason: str, matched_rule: str = "",
        *, overridable: bool = True,
    ) -> None:
        self.target = target
        self.reason = reason
        self.matched_rule = matched_rule
        self.overridable = overridable
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
    # Reject control characters and embedded whitespace in targets. URL parsers
    # otherwise accept ambiguous authorities that external tools may reinterpret.
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in raw):
        return "", "host"
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            host = parsed.hostname or ""
            # Reject malformed authorities instead of letting urlparse errors
            # escape the authorization boundary or treating them as hosts.
            if not host or any(c.isspace() for c in host):
                return "", "url"
            return host.lower().rstrip("."), "url"
        except ValueError:
            return "", "url"
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


def _is_ip_rule(rule: str) -> bool:
    """Return whether a scope rule is an IP literal or CIDR network."""
    try:
        if "/" in rule:
            ipaddress.ip_network(rule, strict=False)
        else:
            ipaddress.ip_address(rule)
        return True
    except ValueError:
        return False


def _validate_scope_rule(rule: str) -> bool:
    """Accept only valid IP/CIDR or hostname/wildcard rules."""
    if _is_ip_rule(rule):
        return True
    # A malformed network or address must not silently become a hostname rule.
    if "/" in rule or ":" in rule or "[" in rule or "]" in rule:
        return False
    host = rule[2:] if rule.startswith("*.") else rule
    if not host or "*" in host or len(host) > 253:
        return False
    labels = host.rstrip(".").split(".")
    return not any(
        not label
        or len(label) > 63
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (char.isalnum() or char == "-") for char in label)
        for label in labels
    )




def _atomic_write(path: Path, content: str) -> None:
    """Write a private config file atomically without following a predictable temp path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


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

    # Written to disk the first time the manager loads with no config present.
    _DEFAULT_SCOPE = {
        "engagement": "default",
        "enabled": True,
        "in_scope": [
            # IPv4 loopback + RFC1918
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            # IPv6 loopback + link-local + unique-local
            "::1",
            "fe80::/10",
            "fc00::/7",
        ],
        "out_of_scope": [],
        "notes": (
            "Auto-generated default scope. Loopback and RFC1918 only. "
            "Edit this file to declare your engagement. To explicitly "
            "disable scope enforcement, set \"enabled\": false — that "
            "must be an operator decision, never a fallback."
        ),
    }

    def load(self) -> None:
        if not self.path.exists():
            # Fail closed: write a strict default, then use it.
            self.path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(self.path, json.dumps(self._DEFAULT_SCOPE, indent=2))
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            # Fail closed: a broken config must not become "allow everything".
            raise RuntimeError(
                f"scope config at {self.path} is unreadable ({e}). "
                f"Fix or delete it to continue."
            ) from e
        if not isinstance(raw, dict):
            raise RuntimeError(
                f"scope config at {self.path} must contain a JSON object"
            )

        enabled = raw.get("enabled", True)
        # bool(value) is unsafe here: null, 0, and "" would silently disable
        # scope enforcement. Only the literal JSON booleans are valid.
        if type(enabled) is not bool:
            raise RuntimeError(
                f"scope config at {self.path} has invalid 'enabled'; "
                "expected true or false"
            )

        def _rules(key: str) -> list[str]:
            value = raw.get(key, [])
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                raise RuntimeError(
                    f"scope config at {self.path} has invalid '{key}'; "
                    "expected a list of non-empty strings"
                )
            normalized = [item.strip() for item in value]
            if any(not _validate_scope_rule(item) for item in normalized):
                raise RuntimeError(
                    f"scope config at {self.path} has malformed '{key}' rule; "
                    "expected a valid hostname, wildcard, IP address, or CIDR"
                )
            return normalized

        engagement = raw.get("engagement", "")
        notes = raw.get("notes", "")
        if not isinstance(engagement, str) or not isinstance(notes, str):
            raise RuntimeError(
                f"scope config at {self.path} has invalid engagement or notes; "
                "expected strings"
            )

        self._enabled = enabled
        self._engagement = engagement
        self._in = _rules("in_scope")
        self._out = _rules("out_of_scope")
        self._notes = notes

        # A /0 rule is valid CIDR syntax but effectively authorizes the whole
        # address family. Keep explicit operator intent possible, while making
        # this high-blast-radius configuration visible at load time.
        broad_rules = []
        for rule in self._in:
            try:
                if ipaddress.ip_network(rule, strict=False).prefixlen == 0:
                    broad_rules.append(rule)
            except ValueError:
                continue
        if self._enabled and broad_rules:
            logging.getLogger(__name__).warning(
                "scope config %s includes global network rule(s) %s; "
                "this effectively permits every address in that family",
                self.path,
                ", ".join(broad_rules),
            )

    def save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(self.path, json.dumps(data, indent=2))
        try:
            from whaxon.core import override_log as _ovr
            _ovr.log_override(self.path.parent, "scope_edit", "scope.json")
        except Exception:
            pass
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

        # Direct host/IP rules are evaluated before DNS. Out-of-scope always wins.
        for rule in self._out:
            if _rule_matches_ip(rule, host) or _rule_matches_host(rule, host):
                return ScopeMatch(False, "matches out-of-scope rule", rule)

        resolved_ips: set[str] = set()
        ip_rules = [
            rule for rule in (*self._in, *self._out) if _is_ip_rule(rule)
        ]
        if kind == "ip":
            resolved_ips.add(str(ipaddress.ip_address(host)))
        elif ip_rules:
            # A hostname can resolve outside an IP/CIDR-only engagement. Check
            # its current A/AAAA answers before authorizing a network operation.
            # This is a preflight guard, not a substitute for network-level
            # egress enforcement: tools may resolve the name again at connect
            # time, so DNS rebinding must also be controlled at the network layer.
            try:
                answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                for answer in answers:
                    address = str(answer[4][0]).split("%", 1)[0]
                    resolved_ips.add(str(ipaddress.ip_address(address)))
            except (OSError, ValueError):
                return ScopeMatch(
                    False,
                    "hostname resolution failed; scope cannot be confirmed",
                    host,
                )
            if not resolved_ips:
                return ScopeMatch(
                    False,
                    "hostname resolved to no addresses; scope cannot be confirmed",
                    host,
                )

        # Out-of-scope IP/CIDR rules also apply to hostname resolutions.
        for rule in self._out:
            for address in resolved_ips:
                if _rule_matches_ip(rule, address):
                    return ScopeMatch(
                        False, "resolved address matches out-of-scope rule", rule
                    )

        # An explicit hostname rule authorizes that hostname, subject to the
        # out-of-scope checks above. Otherwise every resolved address must
        # match an in-scope IP/CIDR rule; one in-scope answer is not enough if
        # the same name also resolves to an unauthorized address.
        for rule in self._in:
            if _rule_matches_host(rule, host):
                return ScopeMatch(True, "matches in-scope hostname rule", rule)

        if resolved_ips and all(
            any(_rule_matches_ip(rule, address) for rule in self._in)
            for address in resolved_ips
        ):
            matched = next(
                (
                    rule for rule in self._in
                    if any(_rule_matches_ip(rule, address) for address in resolved_ips)
                ),
                "",
            )
            return ScopeMatch(True, "all resolved addresses match in-scope rules", matched)

        return ScopeMatch(False, "no matching in-scope rule for host or resolved addresses", "")

    def check_for_execution(self, raw_target: str) -> ScopeMatch:
        """Authorize a network target without relying on a second DNS lookup.

        Generic external tools resolve hostnames themselves, so a preflight
        getaddrinfo() check cannot pin the address used at connect time. Until
        a provider has an explicit pinned-address transport, fail closed for
        hostname targets whenever the engagement policy contains IP/CIDR
        rules. Operators can pass the authorized IP literal, or use an
        explicit hostname-only policy where no IP/CIDR boundary is defined.
        """
        checked = self.check(raw_target)
        if not checked.allowed or not self._enabled:
            return checked
        host, _kind = _normalize_target(raw_target)
        try:
            ipaddress.ip_address(host)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False
        if not is_ip_literal and any(
            _is_ip_rule(rule) for rule in (*self._in, *self._out)
        ):
            return ScopeMatch(
                False,
                "hostname execution cannot be safely DNS-pinned under IP/CIDR scope; use an authorized IP literal",
                host,
                overridable=False,
            )
        return checked

    def check_for_pinned_execution(self, raw_target: str) -> ScopeMatch:
        """Perform a non-resolving preflight for a provider that pins its connect.

        A bounded child must still call :meth:`resolve_for_execution` before
        connecting. This preflight admits explicit hostname rules, in-scope IP
        literals, or hostname targets with positive IP scope rules for child-side
        validation; it never performs DNS on the scheduler thread.
        """
        if (
            not isinstance(raw_target, str)
            or not raw_target
            or raw_target != raw_target.strip()
        ):
            return ScopeMatch(False, "invalid pinned execution target")
        host, kind = _normalize_target(raw_target)
        if not host or kind not in {"host", "ip"}:
            return ScopeMatch(False, "pinned execution requires a bare hostname or IP")
        if kind == "host" and raw_target.strip().lower().rstrip(".") != host:
            return ScopeMatch(False, "pinned execution requires a bare hostname")
        if kind == "ip" and raw_target.strip() != host:
            return ScopeMatch(False, "pinned execution requires a bare IP literal")
        if not self._enabled:
            return ScopeMatch(True, "scope disabled")
        for rule in self._out:
            if _rule_matches_host(rule, host) or (
                kind == "ip" and _rule_matches_ip(rule, host)
            ):
                return ScopeMatch(False, "matches out-of-scope rule", rule)
        if kind == "ip":
            return self.check(raw_target)
        for rule in self._in:
            if _rule_matches_host(rule, host):
                return ScopeMatch(True, "matches explicit in-scope hostname rule", rule)
        ip_in_rules = [rule for rule in self._in if _is_ip_rule(rule)]
        if ip_in_rules:
            # This is only a scheduler preflight. The supervised provider
            # must call resolve_for_execution and prove that every returned
            # numeric address matches these rules before connecting.
            return ScopeMatch(
                True,
                "hostname requires child-side pinned address scope validation",
                host,
                overridable=False,
            )
        if any(_is_ip_rule(rule) for rule in self._out):
            return ScopeMatch(
                False,
                "pinned hostname execution requires an in-scope hostname or IP rule",
                host,
                overridable=False,
            )
        return ScopeMatch(False, "no matching in-scope hostname rule", host)

    def resolve_for_execution(
        self, raw_target: str, *, port: int,
    ) -> ScopeResolution:
        """Resolve once, scope-check every answer, and return numeric socket targets.

        Call this inside the provider's supervised child immediately before a
        network connection. The returned sockaddr values contain numeric IPs,
        so the caller can connect without asking the resolver a second time.
        """
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return ScopeResolution(ScopeMatch(False, "pinned execution port is invalid"))
        preflight = self.check_for_pinned_execution(raw_target)
        if not preflight.allowed:
            return ScopeResolution(preflight)
        host, kind = _normalize_target(raw_target)
        if kind == "ip":
            address = ipaddress.ip_address(host)
            if address.version == 4:
                pinned = PinnedSocketAddress(
                    socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                    (address.compressed, port),
                )
            else:
                pinned = PinnedSocketAddress(
                    socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                    (address.compressed, port, 0, 0),
                )
            return ScopeResolution(preflight, (pinned,))

        try:
            answers = socket.getaddrinfo(
                host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except (OSError, UnicodeError, ValueError) as exc:
            return ScopeResolution(ScopeMatch(
                False,
                "hostname resolution failed; scope cannot be confirmed "
                f"({type(exc).__name__})",
                host,
            ))
        pinned_addresses: list[PinnedSocketAddress] = []
        canonical_ips: list[str] = []
        seen: set[tuple] = set()
        for answer in answers:
            try:
                family, socktype, proto, _canonname, sockaddr = answer
                if family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                if (
                    socktype not in (0, socket.SOCK_STREAM)
                    or proto not in (0, socket.IPPROTO_TCP)
                    or not isinstance(sockaddr, tuple)
                ):
                    continue
                if len(sockaddr) < 2 or int(sockaddr[1]) != port:
                    continue
                raw_ip = str(sockaddr[0])
                ip_text, separator, zone = raw_ip.partition("%")
                resolved_address = ipaddress.ip_address(ip_text)
                if (family == socket.AF_INET) != (resolved_address.version == 4):
                    continue
                mapped_ipv4 = (
                    resolved_address.ipv4_mapped
                    if isinstance(resolved_address, ipaddress.IPv6Address)
                    else None
                )
                if mapped_ipv4 is not None:
                    # An IPv4-mapped IPv6 sockaddr reaches the corresponding
                    # IPv4 host; evaluate it against IPv4 rules and return an
                    # IPv4 sockaddr so the scope check matches the socket peer.
                    resolved_address = mapped_ipv4
                    family = socket.AF_INET
                address_text = resolved_address.compressed
                if family == socket.AF_INET:
                    socket_address_v4: tuple[str, int] = (address_text, port)
                    pinned = PinnedSocketAddress(
                        family, socket.SOCK_STREAM,
                        int(proto or socket.IPPROTO_TCP), socket_address_v4,
                    )
                    socket_ip = address_text
                    flowinfo = 0
                    scope_id = 0
                else:
                    flowinfo = int(sockaddr[2]) if len(sockaddr) > 2 else 0
                    scope_id = int(sockaddr[3]) if len(sockaddr) > 3 else 0
                    if separator and not scope_id:
                        # getaddrinfo may preserve an interface name rather
                        # than its numeric index; never return an unresolved
                        # zone token as a supposedly pinned socket address.
                        continue
                    socket_ip = address_text + (f"%{zone}" if separator else "")
                    socket_address_v6: tuple[str, int, int, int] = (
                        socket_ip, port, flowinfo, scope_id,
                    )
                    pinned = PinnedSocketAddress(
                        family, socket.SOCK_STREAM,
                        int(proto or socket.IPPROTO_TCP), socket_address_v6,
                    )
                canonical = (
                    family, socket.SOCK_STREAM,
                    int(proto or socket.IPPROTO_TCP), socket_ip,
                    port, flowinfo, scope_id,
                )
                if canonical in seen:
                    continue
                seen.add(canonical)
                pinned_addresses.append(pinned)
                canonical_ips.append(address_text)
            except (IndexError, TypeError, ValueError, OverflowError):
                continue

        if not pinned_addresses:
            return ScopeResolution(ScopeMatch(
                False, "hostname resolved to no usable socket addresses; scope cannot be confirmed",
                host,
            ))
        if self._enabled:
            for rule in self._out:
                for address_text in canonical_ips:
                    if _rule_matches_ip(rule, address_text):
                        return ScopeResolution(ScopeMatch(
                            False, "resolved address matches out-of-scope rule", rule,
                        ))
            host_rule = next(
                (rule for rule in self._in if _rule_matches_host(rule, host)), "",
            )
            ip_rules = [rule for rule in self._in if _is_ip_rule(rule)]
            # An explicit hostname rule must not widen configured address bounds.
            if ip_rules and not all(
                any(_rule_matches_ip(rule, address_text) for rule in ip_rules)
                for address_text in canonical_ips
            ):
                return ScopeResolution(ScopeMatch(
                    False,
                    "not every resolved address matches an in-scope rule",
                    host,
                ))
            if not host_rule:
                host_rule = next(
                    (rule for rule in ip_rules
                     if any(_rule_matches_ip(rule, address_text) for address_text in canonical_ips)),
                    "",
                )
            match = ScopeMatch(True, "all pinned addresses match scope", host_rule)
        else:
            match = ScopeMatch(True, "scope disabled")
        return ScopeResolution(match, tuple(pinned_addresses))

    def check_for_dns_query(self, raw_target: str) -> ScopeMatch:
        """Preflight a passive DNS query without resolving the name here.

        The DNS provider performs the full current scope check in its
        supervised child immediately before querying. Core authorization must
        not call synchronous ``getaddrinfo`` in an uncancellable scheduler
        thread, so this preflight requires an explicit hostname rule when IP
        or CIDR rules are also configured. Out-of-scope hostname rules still
        take precedence.
        """
        if not self._enabled:
            return ScopeMatch(allowed=True, reason="scope disabled")
        try:
            host, kind = _normalize_target(raw_target)
        except (TypeError, ValueError):
            return ScopeMatch(allowed=False, reason="invalid DNS target")
        if kind != "host" or not host:
            return ScopeMatch(allowed=False, reason="DNS query requires a hostname")
        for rule in self._out:
            if _rule_matches_host(rule, host):
                return ScopeMatch(False, "matches out-of-scope hostname rule", rule)
        for rule in self._in:
            if _rule_matches_host(rule, host):
                return ScopeMatch(True, "matches explicit in-scope hostname rule", rule)
        if any(_is_ip_rule(rule) for rule in (*self._in, *self._out)):
            return ScopeMatch(
                False,
                "DNS query requires an explicit hostname scope rule when IP/CIDR rules are configured",
                host,
                overridable=False,
            )
        return ScopeMatch(False, "no matching in-scope hostname rule", host)

