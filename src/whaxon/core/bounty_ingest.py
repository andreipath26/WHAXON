"""Safe public YesWeHack program-page ingestion (§26.12).

This module only retrieves public program pages and returns an unapproved
policy draft. It never writes a policy, launches tests, or submits reports.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from whaxon.core.bounty_parse import parse_yeswehack

PARSER_VERSION = "1.0"
_ALLOWED_HOSTS = {"yeswehack.com", "www.yeswehack.com"}
_MAX_BYTES = 2 * 1024 * 1024
_TIMEOUT_SECONDS = 8
_MAX_REDIRECTS = 3


class IngestionError(ValueError):
    """The URL or response cannot be safely ingested."""


class _VisibleText(HTMLParser):
    _HIDDEN = {"script", "style", "noscript", "svg"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() in self._HIDDEN:
            self.hidden += 1
        elif tag.lower() in {"br", "p", "div", "li", "tr", "td", "th", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in self._HIDDEN and self.hidden:
            self.hidden -= 1
        elif tag.lower() in {"p", "div", "li", "tr", "td", "th", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.hidden and data.strip():
            self.parts.append(data.strip())

    def text(self) -> str:
        return re.sub(r"\n{3,}", "\n\n", "\n".join(self.parts)).strip()


def _validated_url(url: str):
    if not isinstance(url, str) or len(url) > 2048:
        raise IngestionError("URL is missing or too long")
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except ValueError as exc:
        raise IngestionError("Malformed program URL") from exc
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme.lower() != "https":
        raise IngestionError("Only HTTPS program URLs are accepted")
    if parsed.username is not None or parsed.password is not None:
        raise IngestionError("Credentials in URLs are not accepted")
    if host not in _ALLOWED_HOSTS:
        raise IngestionError("Only public YesWeHack program URLs are supported")
    if port not in (None, 443):
        raise IngestionError("Non-standard ports are not accepted")
    if not re.fullmatch(r"/programs/[A-Za-z0-9][A-Za-z0-9_-]{0,127}/?", parsed.path):
        raise IngestionError("URL must identify a YesWeHack public program")
    if parsed.fragment:
        raise IngestionError("URL fragments are not accepted")
    return parsed, host


def _public_ip(host: str) -> str:
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise IngestionError(f"DNS lookup failed: {exc}") from exc
    addresses = sorted({item[4][0] for item in answers})
    if not addresses:
        raise IngestionError("Hostname did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise IngestionError("Hostname resolves to a non-public address")
    # Pin the TCP connection to one of the validated addresses. TLS still
    # verifies the certificate against the original hostname.
    return str(addresses[0])


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str):
        self._tls_context = ssl.create_default_context()
        super().__init__(host, 443, timeout=_TIMEOUT_SECONDS,
                         context=self._tls_context)
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._tls_context.wrap_socket(raw, server_hostname=self.host)


def _request(url: str) -> tuple[bytes, str, str]:
    current = url
    for redirect_count in range(_MAX_REDIRECTS + 1):
        parsed, host = _validated_url(current)
        address = _public_ip(host)
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        conn = _PinnedHTTPSConnection(host, address)
        try:
            conn.request("GET", path, headers={
                "Host": host,
                "User-Agent": "WHAXON-Program-Importer/1.0 (+public-program-metadata)",
                "Accept": "text/html,text/plain;q=0.9",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            response = conn.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                response.read(1024)
                if not location or redirect_count >= _MAX_REDIRECTS:
                    raise IngestionError("Redirect limit reached or Location missing")
                current = urljoin(current, location)
                continue
            if response.status != 200:
                raise IngestionError(f"Program page returned HTTP {response.status}")
            content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].lower()
            if content_type not in {"text/html", "text/plain"}:
                raise IngestionError(f"Unsupported content type: {content_type or 'missing'}")
            if response.getheader("Content-Encoding", "identity").lower() not in {"", "identity"}:
                raise IngestionError("Compressed responses are not accepted")
            body = response.read(_MAX_BYTES + 1)
            if len(body) > _MAX_BYTES:
                raise IngestionError("Program page exceeds the 2 MiB limit")
            return body, content_type, current
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise IngestionError(f"Could not retrieve program page: {exc}") from exc
        finally:
            conn.close()
    raise IngestionError("Redirect limit reached")


def _source_evidence(source_text: str, draft: dict) -> list[dict]:
    lines = source_text.splitlines()
    evidence: list[dict] = []
    for entry in (draft.get("scope") or {}).get("in_scope", []):
        value = str(entry.get("scope") or "") if isinstance(entry, dict) else str(entry)
        for number, line in enumerate(lines, 1):
            if value and value in line:
                evidence.append({"field": "scope.in_scope", "value": value,
                                 "line": number, "excerpt": line.strip()[:500]})
                break
    terms = ("out of scope", "excluded", "not allowed", "forbidden", "must ",
             "do not", "rate limit", "requests per", "automated scanner",
             "disclosure", "report", "authentication", "vpn", "user-agent",
             "proof of", "bounty eligible", "first reporter")
    for number, line in enumerate(lines, 1):
        if any(term in line.lower() for term in terms):
            excerpt = line.strip()[:500]
            if excerpt and not any(item["line"] == number for item in evidence):
                evidence.append({"field": "program_rule", "value": None,
                                 "line": number, "excerpt": excerpt})
    return evidence


def _harden_draft(draft: dict, source_url: str) -> None:
    """Replace parser guesses with conservative values until a human confirms them."""
    draft["program_url"] = source_url
    rate = draft.setdefault("rate", {})
    rate["max_requests_per_second"] = 0
    rate["max_concurrent_connections"] = 0
    rate["respect_robots_txt"] = True
    hunting = draft.setdefault("hunting_requirements", {})
    if hunting.get("automated_scanners") == "limited":
        hunting["automated_scanners"] = "unknown"
    # Do not infer permission, disclosure rights, or eligibility from silence.
    hunting["disclosure_allowed"] = False
    hunting["first_reporter_wins"] = False
    account = draft.setdefault("account_access", {})
    account["mode"] = "unknown"
    account["vpn_required"] = True
    tools = draft.setdefault("tools", {})
    tools["mode"] = "allowlist"
    tools["allowlist"] = []
    tools["denylist"] = []
    ai = draft.setdefault("ai_policy", {})
    # Imported programme terms are not permission to begin testing.
    # Once the operator approves the programme, routine in-scope work is
    # delegated to the agent; only consequential decisions return to the user.
    ai.update({
        "mode": "bounded_autonomous_after_approval",
        "execution_enabled": False,
        "activation": "disabled_until_program_approval",
        "allow_action_selection": False,
        "allow_live_requests": False,
        "allow_auto_mode": False,
        "require_human_confirm": False,
        "post_approval_autonomous_actions": [
            "programme_rule_analysis",
            "scope_matching_within_approved_scope",
            "passive_reconnaissance",
            "low_impact_permitted_checks",
            "tool_selection_from_approved_allowlist",
            "finding_correlation_and_deduplication",
            "evidence_reproduction_within_approved_limits",
            "severity_and_impact_assessment",
            "draft_report_preparation",
        ],
        "human_approval_required_for": [
            "programme_activation_or_campaign_start",
            "scope_expansion_or_ambiguous_scope",
            "rate_or_concurrency_increase",
            "intrusive_or_destructive_testing",
            "sensitive_data_access",
            "account_creation_or_external_identity_actions",
            "third_party_testing",
            "public_disclosure_or_report_submission",
            "paid_actions_or_external_costs",
        ],
    })


def _review_status(draft: dict) -> dict[str, str]:
    scope = draft.get("scope") or {}
    reward = draft.get("reward_model") or {}
    identity = draft.get("identity") or {}
    hunting = draft.get("hunting_requirements") or {}
    return {
        "scope.in_scope": "extracted_requires_confirmation" if scope.get("in_scope") else "missing",
        "scope.out_of_scope": "manual_review_required_not_extracted",
        "rate_limits": "manual_review_required_not_extracted",
        "account_access_and_vpn": "manual_review_required_not_extracted",
        "automated_scanner_permissions": "extracted_requires_confirmation" if hunting.get("automated_scanners") == "forbidden" else "manual_review_required",
        "disclosure_permission": "manual_review_required_not_assumed",
        "qualifying_vulnerability_classes": "manual_review_required_not_extracted",
        "non_qualifying_vulnerability_classes": "manual_review_required_not_extracted",
        "reward_grid": "extracted_requires_confirmation" if reward.get("grid") else "missing",
        "required_user_agent": "extracted_requires_confirmation" if identity.get("user_agent_suffix") else "manual_review_required",
    }

def ingest_yeswehack_url(url: str) -> dict:
    """Fetch a public program page and return an unapproved, provenance-rich draft."""
    body, content_type, final_url = _request(url)
    try:
        decoded = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestionError("Program page is not valid UTF-8") from exc
    if content_type == "text/html":
        parser = _VisibleText()
        parser.feed(decoded)
        source_text = parser.text()
    else:
        source_text = decoded
    if not source_text.strip():
        raise IngestionError("Program page contained no readable text")

    slug_match = re.fullmatch(r"/programs/([A-Za-z0-9][A-Za-z0-9_-]{0,127})/?",
                              urlsplit(final_url).path)
    slug = slug_match.group(1).lower() if slug_match else ""
    draft = parse_yeswehack(source_text, slug=slug)
    _harden_draft(draft, final_url)
    evidence = _source_evidence(source_text, draft)
    return {
        "status": "draft_requires_review",
        "policy_draft": draft,
        "evidence": evidence,
        "review": _review_status(draft),
        "source": {
            "url": final_url,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "content_type": content_type,
            "parser": "yeswehack",
            "parser_version": PARSER_VERSION,
            "bytes": len(body),
        },
        "warnings": [
            "This is an unapproved extraction draft, not proof of authorization.",
            "Review every scope entry, exclusion and testing restriction against the source.",
            "Missing or ambiguous rules must be resolved manually before policy activation.",
            "No policy was saved and no test or report was submitted.",
        ],
    }


def ingest_yeswehack_text(text: str, source_url: str = "") -> dict:
    """Parse operator-supplied text without network access or policy activation."""
    if not isinstance(text, str) or not text.strip():
        raise IngestionError("Pasted program text is empty")
    if len(text.encode("utf-8")) > _MAX_BYTES:
        raise IngestionError("Pasted program text exceeds the 2 MiB limit")
    if source_url:
        _validated_url(source_url)
    draft = parse_yeswehack(text)
    _harden_draft(draft, source_url)
    evidence = _source_evidence(text, draft)
    raw = text.encode("utf-8")
    return {
        "status": "draft_requires_review",
        "policy_draft": draft,
        "evidence": evidence,
        "review": _review_status(draft),
        "source": {
            "url": source_url,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "content_sha256": hashlib.sha256(raw).hexdigest(),
            "content_type": "text/plain",
            "parser": "yeswehack",
            "parser_version": PARSER_VERSION,
            "bytes": len(raw),
        },
        "warnings": [
            "This is an unapproved extraction draft, not proof of authorization.",
            "Review every scope entry, exclusion and testing restriction against the source.",
            "No policy was saved and no test or report was submitted.",
        ],
    }
