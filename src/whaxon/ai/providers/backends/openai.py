"""OpenAI backend. HTTP POST to /v1/chat/completions. Stdlib only."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import BackendError, LLMBackend

DEFAULT_HOST = "https://api.openai.com"


class OpenAIBackend(LLMBackend):
    name = "openai"

    def __init__(self, model: str, host: str | None = None, api_key: str | None = None, **options) -> None:
        super().__init__(model, **options)
        self.host = (host or os.environ.get("WHAXON_OPENAI_HOST") or DEFAULT_HOST).rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY") or ""

    def available(self):
        if not self.api_key:
            return False, "OPENAI_API_KEY not set"
        return True, ""

    def chat(self, messages, timeout=60.0):
        if not self.api_key:
            raise BackendError("OPENAI_API_KEY not set")
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.options.get("temperature", 0.1),
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.host + "/v1/chat/completions",
            data=data,
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + self.api_key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raise BackendError("openai HTTP %s: %s" % (e.code, e.reason)) from e
        except urllib.error.URLError as e:
            raise BackendError("openai unreachable: %s" % (e.reason,)) from e
        try:
            obj = json.loads(body)
        except Exception as e:
            raise BackendError("openai returned non-JSON") from e
        try:
            content = obj["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise BackendError("openai response missing choices[0].message.content") from e
        if not isinstance(content, str):
            raise BackendError("openai content not a string")
        return content
