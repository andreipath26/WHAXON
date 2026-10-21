"""Build a reproducible proof-of-exploit command for a finding."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def render_proof(finding_data: dict, payload: str | None = None) -> str:
    """Return a curl command that reproduces the finding.

    If `payload` is provided, it is injected into the parameter named in
    `_request_context`. Otherwise the raw URL from the context is used.
    """
    ctx = (finding_data or {}).get("_request_context") or {}
    method = (ctx.get("method") or "GET").upper()
    url = ctx.get("url") or ""
    headers = ctx.get("headers") or {}
    param = ctx.get("parameter")
    body = ctx.get("body")

    if not url:
        return "# No request context recorded; cannot generate a reproducible proof."

    # Inject payload into the URL or body.
    if payload and param:
        if method in ("POST", "PUT", "PATCH"):
            pairs = dict(parse_qsl(body or ""))
            pairs[param] = payload
            body = urlencode(pairs)
        else:
            parsed = urlparse(url)
            q = dict(parse_qsl(parsed.query))
            q[param] = payload
            url = urlunparse(parsed._replace(query=urlencode(q)))

    # Build the curl command.
    parts = ["curl", "-sS", "-i"]
    if method != "GET":
        parts.extend(["-X", method])
    for k, v in headers.items():
        parts.extend(["-H", f"{k}: {v}"])
    if body:
        parts.extend(["--data", body])
    parts.append(f"'{url}'")
    return " ".join(parts)
