"""Anthropic backend. HTTP POST to /v1/messages. Stdlib only."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import LLMBackend, BackendError


DEFAULT_HOST = "https://api.anthropic.com"
DEFAULT_VERSION = "2023-06-01"


class AnthropicBackend(LLMBackend):
    name = "anthropic"

    def __init__(self, model: str, host: str | None = None, api_key: str | None = None, **options) -> None:
        super().__init__(model, **options)
        self.host = (host or os.environ.get("WHAXON_ANTHROPIC_HOST") or DEFAULT_HOST).rstrip("/")
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY") or ""

    def available(self):
        if not self.api_key:
            return False, "ANTHROPIC_API_KEY not set"
        return True, ""

    def chat(self, messages, timeout=60.0):
        if not self.api_key:
            raise BackendError("ANTHROPIC_API_KEY not set")
        # Anthropic separates system from user/assistant turns
        system_parts = []
        convo = []
        for m in messages:
            role = m.get("role")
            content = m.get("content", "")
            if role == "system":
                system_parts.append(content)
            elif role in ("user", "assistant"):
                convo.append({"role": role, "content": content})
        payload = {
            "model": self.model,
            "messages": convo,
            "max_tokens": int(self.options.get("max_tokens", 1024)),
            "temperature": self.options.get("temperature", 0.1),
        }
        if system_parts:
            payload["system"] = chr(10).join(system_parts)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.host + "/v1/messages",
            data=data,
            headers={"Content-Type": "application/json",
                     "x-api-key": self.api_key,
                     "anthropic-version": DEFAULT_VERSION},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raise BackendError("anthropic HTTP %s: %s" % (e.code, e.reason)) from e
        except urllib.error.URLError as e:
            raise BackendError("anthropic unreachable: %s" % (e.reason,)) from e
        try:
            obj = json.loads(body)
        except Exception as e:
            raise BackendError("anthropic returned non-JSON") from e
        parts = obj.get("content") or []
        texts = [p.get("text", "") for p in parts if isinstance(p, dict) and p.get("type") == "text"]
        if not texts:
            raise BackendError("anthropic response has no text content")
        return chr(10).join(texts)
