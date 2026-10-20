"""Deterministic validation engine (§32.2 / §33.1)."""
from __future__ import annotations

import re
from pathlib import Path

from whaxon.core.findings import Finding


class PayloadLoader:
    def __init__(self, payload_dir: Path):
        self.payload_dir = payload_dir
        self._cache: dict[str, list[str]] = {}

    def get_payloads(self, kind: str) -> list[str]:
        """Extract fenced payloads from the markdown for a given finding kind."""
        if kind in self._cache:
            return self._cache[kind]
        
        # Map finding kinds to vendored files
        mapping = {
            "sqli": "sql_injection.md",
            "sql_injection": "sql_injection.md",
            "xss": "xss.md",
            "command_injection": "command_injection.md",
            "lfi": "lfi_rfi.md",
            "rfi": "lfi_rfi.md",
            "crlf_injection": "crlf.md",
            "ssrf": "ssrf.md",
        }
        filename = mapping.get(kind)
        if not filename:
            return []
            
        path = self.payload_dir / filename
        if not path.exists():
            return []

        content = path.read_text(encoding="utf-8")
        # Match ```lang\n content \n```
        blocks = re.findall(r'```(?:[a-zA-Z0-9_-]+)?\n(.*?)```', content, re.DOTALL)
        
        payloads = []
        for b in blocks:
            # Split by newline, strip whitespace, ignore empty lines and comments
            for line in b.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.append(line)
        
        self._cache[kind] = payloads
        return payloads

class Validator:
    """Deterministic payload replay (§32.2 / §33.1).

    Only kinds with a known HTTP shape are replayed. Unknown or
    incomplete findings return 'candidate' with the reason, never a
    silent pass. No LLM. No subprocess. urllib only (R105, R103).
    """

    # Error signatures that prove an injection landed.
    SQL_ERROR_MARKERS = (
        "sql syntax", "mysql_fetch", "ora-0", "postgresql", "sqlite",
        "unclosed quotation", "you have an error in your sql",
    )
    # XSS markers: payload reflected unescaped.
    XSS_MARKERS = ("<script>", "onerror=", "javascript:")

    REPLAYABLE = {"sqli": "sql", "xss": "xss"}

    def __init__(self, payload_dir: Path, timing_threshold: float = 3.0):
        self.loader = PayloadLoader(payload_dir)
        self.timing_threshold = timing_threshold

    def validate(self, finding: Finding, target_url: str | None = None) -> tuple[str, str]:
        """Return (status, reason). status in {verified, refuted, candidate}."""
        ctx = (finding.data or {}).get("_request_context")
        if ctx and ctx.get("url"):
            return self._replay_ctx(ctx)
        kind = finding.kind
        if kind not in self.REPLAYABLE:
            return "candidate", f"kind {kind!r} is not directly replayable"
        if not target_url:
            return "candidate", "no target URL supplied"
        param = (finding.data or {}).get("parameter")
        if not param:
            return "candidate", "finding has no parameter to inject"

        payloads = self.loader.get_payloads(kind)
        if not payloads:
            return "candidate", f"no payloads vendored for kind {kind!r}"
        payload = payloads[0]

        family = self.REPLAYABLE[kind]
        markers = self.SQL_ERROR_MARKERS if family == "sql" else self.XSS_MARKERS

        try:
            baseline, base_t = self._fetch(target_url, param, "whaxon_baseline")
            injected, inj_t = self._fetch(target_url, param, payload)
        except Exception as e:
            return "candidate", f"replay failed: {e}"

        delta = inj_t - base_t
        if delta >= self.timing_threshold:
            return "verified", f"timing delta {delta:.2f}s >= {self.timing_threshold:.1f}s"

        baseline_l = (baseline or "").lower()
        injected_l = (injected or "").lower()
        for m in markers:
            if m in injected_l and m not in baseline_l:
                return "verified", f"marker {m!r} appeared only after injection"
        if injected_l == baseline_l:
            return "refuted", "response identical to baseline"
        return "candidate", "response differed but no known marker"

    @staticmethod
    def _fetch(url: str, param: str, value: str) -> tuple[str, float]:
        import time
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
        from urllib.request import Request, urlopen
        parsed = urlparse(url)
        q = dict(parse_qsl(parsed.query))
        q[param] = value
        new_url = urlunparse(parsed._replace(query=urlencode(q)))
        req = Request(new_url, headers={"User-Agent": "whaxon-validate/0.11"})
        t0 = time.monotonic()
        with urlopen(req, timeout=10) as r:
            body = r.read(20000).decode("utf-8", errors="replace")
        return body, time.monotonic() - t0

    def _replay_ctx(self, ctx: dict) -> tuple[str, str]:
        """Replay a finding's full HTTP context (method, url, headers, body)."""
        from urllib.request import Request, urlopen
        method = (ctx.get("method") or "GET").upper()
        url = ctx.get("url")
        if not isinstance(url, str):
            return "candidate", "request context has no valid url"
        headers = ctx.get("headers") or {"User-Agent": "whaxon-validate/0.11"}
        body = ctx.get("body")
        data = body.encode() if body and method in ("POST", "PUT", "PATCH") else None

        import time
        try:
            t0 = time.monotonic()
            req = Request(url, data=data, headers=headers, method=method)
            with urlopen(req, timeout=10) as r:
                injected = r.read(20000).decode("utf-8", errors="replace")
            elapsed = time.monotonic() - t0
        except Exception as e:
            return "candidate", f"replay failed: {e}"

        if elapsed >= self.timing_threshold:
            return "verified", f"timing delta {elapsed:.2f}s >= {self.timing_threshold:.1f}s"

        # For context-replay we cannot establish a safe baseline without
        # knowing which parameter to perturb. Detect by marker presence.
        injected_l = injected.lower()
        for m in self.SQL_ERROR_MARKERS:
            if m in injected_l:
                return "verified", f"sql marker {m!r} present"
        for m in self.XSS_MARKERS:
            if m in injected_l:
                return "verified", f"xss marker {m!r} present"
        return "candidate", "context replay returned no known marker"
