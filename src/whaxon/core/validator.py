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
            return self._replay_ctx(ctx, target_url=target_url, kind=finding.kind)
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
            baseline_samples = [self._fetch(target_url, param, "whaxon_baseline") for _ in range(3)]
            injected_samples = [self._fetch(target_url, param, payload) for _ in range(3)]
        except Exception as e:
            return "candidate", f"replay failed: {e}"

        # Median of 3 samples per side: robust to single-sample jitter,
        # which is what makes a single slow response untrustworthy as
        # proof of a timing-based injection.
        import statistics as _stats
        base_t = _stats.median(s[1] for s in baseline_samples)
        inj_t = _stats.median(s[1] for s in injected_samples)
        # Use the first measurement's body for marker checks.
        baseline = baseline_samples[0][0]
        injected = injected_samples[0][0]

        delta = inj_t - base_t
        if delta >= self.timing_threshold:
            return "verified", f"timing delta (median of 3) {delta:.2f}s >= {self.timing_threshold:.1f}s"

        baseline_l = (baseline or "").lower()
        injected_l = (injected or "").lower()
        for m in markers:
            if m in injected_l and m not in baseline_l:
                return "verified", f"marker {m!r} appeared only after injection"
        if injected_l == baseline_l:
            return "refuted", "response identical to baseline"
        return "candidate", "response differed but no known marker"

    def revalidate(self, finding: Finding, target_url: str | None = None) -> tuple[str, str]:
        """Re-run a previously verified finding and report the outcome.

        Returns ("fixed", reason) if the finding no longer reproduces,
        ("still_vulnerable", reason) if it does. The distinction is:
        a finding was "verified" before; if the replay still produces
        the marker, it is not fixed; if it does not, it is.
        """
        status, reason = self.validate(finding, target_url=target_url)
        if status == "verified":
            return "still_vulnerable", f"replay still verifies: {reason}"
        if status == "refuted":
            return "fixed", f"replay no longer verifies: {reason}"
        if status == "candidate":
            return "inconclusive", f"replay was inconclusive: {reason}"
        return "candidate", f"unexpected revalidation status: {status}"

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

    def _replay_ctx(self, ctx: dict, target_url: str | None = None, kind: str | None = None) -> tuple[str, str]:
        """Replay a finding's full HTTP context (method, url, headers, body).

        C-03 hardening applied:
        1. Method allowlist.
        2. URL must match the target host (if target_url is provided).
        3. Redirects are disabled.
        4. Auth/Cookie headers are stripped.
        """
        import time
        import urllib.error
        import urllib.request
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

        method = (ctx.get("method") or "GET").upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            return "candidate", f"unsupported method {method!r}"

        url = ctx.get("url")
        if not isinstance(url, str):
            return "candidate", "request context has no valid url"

        # Check 2: Constrain destination URL to the authorized target
        if target_url:
            ctx_host = urlparse(url).netloc
            tgt_host = urlparse(target_url).netloc
            if ctx_host != tgt_host:
                return "candidate", f"context url host {ctx_host!r} does not match target host {tgt_host!r}"

        headers = ctx.get("headers") or {"User-Agent": "whaxon-validate/0.11"}
        
        # Check 4: Strip auth/cookie headers to prevent leaking them
        headers = {k: v for k, v in headers.items() if k.lower() not in ("authorization", "cookie")}
        if "User-Agent" not in headers and "user-agent" not in [k.lower() for k in headers]:
            headers["User-Agent"] = "whaxon-validate/0.11"

        param = ctx.get("parameter")
        body_template = ctx.get("body")

        payload = None
        if kind:
            payloads = self.loader.get_payloads(kind)
            if payloads:
                payload = payloads[0]

        if not payload:
            data = body_template.encode() if body_template and method in ("POST", "PUT", "PATCH") else None
            final_url = url
        elif method in ("POST", "PUT", "PATCH"):
            if body_template and "{payload}" in body_template:
                body_str = body_template.replace("{payload}", payload)
            elif body_template and param:
                pairs = dict(parse_qsl(body_template))
                pairs[param] = payload
                body_str = urlencode(pairs)
            else:
                body_str = urlencode({(param or "q"): payload})
            data = body_str.encode()
            final_url = url
        else:
            parsed = urlparse(url)
            q = dict(parse_qsl(parsed.query))
            q[param or "q"] = payload
            final_url = urlunparse(parsed._replace(query=urlencode(q)))
            data = None

        # Check 3: Disable redirects
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise urllib.error.HTTPError(
                    req.full_url, code, f"redirect to {newurl} blocked by validator", headers, fp
                )

        opener = urllib.request.build_opener(NoRedirect)

        try:
            t0 = time.monotonic()
            req = urllib.request.Request(final_url, data=data, headers=headers, method=method)
            with opener.open(req, timeout=10) as r:
                injected = r.read(20000).decode("utf-8", errors="replace")
            elapsed = time.monotonic() - t0
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                return "candidate", str(e)
            return "candidate", f"replay failed: HTTP {e.code}"
        except Exception as e:
            return "candidate", f"replay failed: {e}"

        if elapsed >= self.timing_threshold:
            return "verified", f"timing delta {elapsed:.2f}s >= {self.timing_threshold:.1f}s"

        injected_l = injected.lower()
        for m in self.SQL_ERROR_MARKERS:
            if m in injected_l:
                return "verified", f"sql marker {m!r} present"
        for m in self.XSS_MARKERS:
            if m in injected_l:
                return "verified", f"xss marker {m!r} present"
        return "candidate", "context replay returned no known marker"
