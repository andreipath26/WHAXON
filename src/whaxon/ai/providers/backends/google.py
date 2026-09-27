"""Google Gemini backend. HTTP POST to generativelanguage.googleapis.com."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from .base import LLMBackend, BackendError


DEFAULT_HOST = "https://generativelanguage.googleapis.com"


class GoogleBackend(LLMBackend):
    name = "google"

    def __init__(self, model: str, host: str | None = None, api_key: str | None = None, **options) -> None:
        super().__init__(model, **options)
        self.host = (host or os.environ.get("WHAXON_GOOGLE_HOST") or DEFAULT_HOST).rstrip("/")
        self.api_key = (api_key or os.environ.get("GOOGLE_API_KEY")
                        or os.environ.get("GEMINI_API_KEY") or "")

    def available(self):
        if not self.api_key:
            return False, "GOOGLE_API_KEY (or GEMINI_API_KEY) not set"
        return True, ""

    def chat(self, messages, timeout=60.0):
        if not self.api_key:
            raise BackendError("GOOGLE_API_KEY not set")
        # Gemini uses systemInstruction + contents[{role, parts:[{text}]}]
        system_parts = []
        contents = []
        for m in messages:
            role = m.get("role")
            content = m.get("content", "")
            if role == "system":
                system_parts.append(content)
            elif role == "user":
                contents.append({"role": "user", "parts": [{"text": content}]})
            elif role == "assistant":
                contents.append({"role": "model", "parts": [{"text": content}]})
        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.options.get("temperature", 0.1),
                "maxOutputTokens": int(self.options.get("max_tokens", 1024)),
            },
        }
        if system_parts:
            payload["systemInstruction"] = {"parts": [{"text": chr(10).join(system_parts)}]}
        url = "%s/v1beta/models/%s:generateContent?key=%s" % (
            self.host, urllib.parse.quote(self.model, safe=""),
            urllib.parse.quote(self.api_key, safe=""),
        )
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raise BackendError("google HTTP %s: %s" % (e.code, e.reason)) from e
        except urllib.error.URLError as e:
            raise BackendError("google unreachable: %s" % (e.reason,)) from e
        try:
            obj = json.loads(body)
        except Exception as e:
            raise BackendError("google returned non-JSON") from e
        try:
            cands = obj["candidates"]
            parts = cands[0]["content"]["parts"]
            texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
        except (KeyError, IndexError, TypeError) as e:
            raise BackendError("google response missing candidates[0].content.parts") from e
        return chr(10).join(t for t in texts if t)
