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
    def __init__(self, payload_dir: Path):
        self.loader = PayloadLoader(payload_dir)

    def validate(self, finding: Finding) -> str:
        """Returns 'verified', 'refuted', or 'candidate' (if ambiguous)."""
        # Placeholder: The actual validation logic will re-run the payload
        # via the runner and check the response. For now, we just verify
        # that we have a payload to run.
        payloads = self.loader.get_payloads(finding.kind)
        if not payloads:
            return "candidate"  # No known payloads for this kind
        
        # Deterministic check would go here:
        # 1. Pick first payload deterministically
        # 2. Re-run against finding.data['target']
        # 3. Check response signature
        return "candidate"  # Stubbed until runner integration
