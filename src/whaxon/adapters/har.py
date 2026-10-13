"""HTTP Archive (HAR) adapter — ingests browser traffic exports.

HAR files are exported by Chrome DevTools, Firefox, and most browser
developer tools. Each entry is one HTTP request/response pair.

This adapter is an ingestion layer, not a finding source. Every entry
becomes a Finding with kind="http_request" and severity="info". The
state machine (26.2.3), differential session analysis (26.2.1), and
invariant engine (26.2.2) consume these findings as input.

Auth headers and cookies are redacted before storage. Bodies are
truncated to 2000 chars. Response body hashes are recorded for
differential comparison across sessions.

Design ref: docs/bounty-addon.md §26.2.1.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..core.findings import Finding
from .base import Adapter
from .registry import register

BODY_TRUNCATE = 2000

_BINARY_CONTENT_TYPES = (
    "image/",
    "video/",
    "audio/",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "font/",
)



class HarAdapter(Adapter):
    tool_id = "har"

    def parse(self, lines, ctx=None):
        ctx = ctx or {}
        path = ctx.get("file_path")
        if not path:
            return []
        return self.parse_file(Path(path), ctx)

    def parse_file(self, path: Path, ctx: dict | None = None) -> list[Finding]:
        ctx = ctx or {}
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, FileNotFoundError, OSError):
            return []

        entries = data.get("log", {}).get("entries", [])
        if not isinstance(entries, list):
            return []

        out: list[Finding] = []
        for entry in entries:
            f = self._parse_entry(entry, ctx)
            if f is not None:
                out.append(f)
        return out

    def _parse_entry(self, entry: dict, ctx: dict | None = None) -> Finding | None:
        ctx = ctx or {}
        if not isinstance(entry, dict):
            return None

        request = entry.get("request") or {}
        response = entry.get("response") or {}
        if not isinstance(request, dict) or not isinstance(response, dict):
            return None

        url = (request.get("url") or "").strip()
        method = (request.get("method") or "").strip().upper()
        if not url or not method:
            return None

        host, path_only = _split_url(url)
        status = response.get("status")

        req_headers = _collect_headers(request.get("headers") or [])
        resp_headers = _collect_headers(response.get("headers") or [])

        req_body = _extract_body(request.get("postData"))
        resp_content = response.get("content") or {}
        resp_body_text, resp_body_hash = _extract_response_body(resp_content)

        content_type = _header_lookup(resp_headers, "content-type")
        started = (entry.get("startedDateTime") or "").strip()

        data: dict = {
            "method": method,
            "url": url,
            "host": host,
            "path": path_only,
            "status": status,
            "content_type": content_type,
            "request_headers": req_headers,
            "response_headers": resp_headers,
            "started_datetime": started,
        }
        if ctx.get("session_id"):
            data["session_id"] = ctx["session_id"]
        if ctx.get("principal"):
            data["principal"] = ctx["principal"]
        if req_body:
            data["request_body"] = req_body
        if resp_body_text:
            data["response_body"] = resp_body_text
        if resp_body_hash:
            data["response_body_hash"] = resp_body_hash

        raw_line = f"{method} {url} -> {status}" if status is not None else f"{method} {url}"

        return Finding(
            kind="http_request",
            severity="info",
            source="har",
            data=data,
            raw_line=raw_line,
        )


def _split_url(url: str) -> tuple[str, str]:
    scheme_sep = url.find("://")
    rest = url[scheme_sep + 3:] if scheme_sep != -1 else url
    slash = rest.find("/")
    if slash == -1:
        return rest, "/"
    return rest[:slash], rest[slash:]


def _header_lookup(headers: dict, key: str) -> str:
    if not isinstance(headers, dict):
        return ""
    for k, v in headers.items():
        if k.lower() == key:
            return v if isinstance(v, str) else str(v)
    return ""


def _collect_headers(raw_headers) -> dict:
    out: dict[str, str] = {}
    if not isinstance(raw_headers, list):
        return out
    for h in raw_headers:
        if not isinstance(h, dict):
            continue
        name = h.get("name")
        value = h.get("value", "")
        if not isinstance(name, str) or not name:
            continue
        if not isinstance(value, str):
            value = str(value)
        if name in out:
            out[name] = out[name] + ", " + value
        else:
            out[name] = value
    return out


def _extract_body(post_data) -> str:
    if not isinstance(post_data, dict):
        return ""
    text = post_data.get("text")
    if isinstance(text, str) and text:
        return _truncate(text)
    params = post_data.get("params")
    if isinstance(params, list) and params:
        parts = []
        for p in params:
            if not isinstance(p, dict):
                continue
            n = p.get("name", "")
            v = p.get("value", "")
            if n:
                parts.append(f"{n}={v}")
        return _truncate("&".join(parts))
    return ""


def _extract_response_body(content) -> tuple[str, str]:
    if not isinstance(content, dict):
        return "", ""
    text = content.get("text")
    if not isinstance(text, str) or not text:
        return "", ""
    body_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    mime = content.get("mimeType") or ""
    is_binary = any(mime.startswith(prefix) for prefix in _BINARY_CONTENT_TYPES)
    if content.get("encoding") == "base64" or is_binary:
        return "", body_hash
    return _truncate(text), body_hash


def _truncate(text: str) -> str:
    if len(text) <= BODY_TRUNCATE:
        return text
    return text[:BODY_TRUNCATE] + "...[truncated]"


register(HarAdapter())