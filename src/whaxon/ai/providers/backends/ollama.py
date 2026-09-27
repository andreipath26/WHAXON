"""Ollama backend. HTTP POST to /api/chat. Stdlib only."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import LLMBackend, BackendError


DEFAULT_HOST = "http://127.0.0.1:11434"


class OllamaBackend(LLMBackend):
    name = "ollama"

    def __init__(self, model: str, host: str | None = None, **options) -> None:
        super().__init__(model, **options)
        self.host = (host or os.environ.get("WHAXON_OLLAMA_HOST") or DEFAULT_HOST).rstrip("/")

    def chat(self, messages, timeout=180.0):
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.options.get("temperature", 0.1)},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.host + "/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raise BackendError("ollama HTTP %s: %s" % (e.code, e.reason)) from e
        except urllib.error.URLError as e:
            raise BackendError("ollama unreachable at %s: %s" % (self.host, e.reason)) from e
        except Exception as e:
            raise BackendError("ollama error: %r" % (e,)) from e
        try:
            obj = json.loads(body)
        except Exception as e:
            raise BackendError("ollama returned non-JSON") from e
        msg = obj.get("message") or {}
        content = msg.get("content")
        if not isinstance(content, str):
            raise BackendError("ollama response missing message.content")
        return content

    def available(self):
        try:
            req = urllib.request.Request(self.host + "/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                body = resp.read().decode("utf-8")
            obj = json.loads(body)
            names = [m.get("name", "") for m in obj.get("models", [])]
            if self.model not in names:
                return False, "model %s not found at %s (have: %s)" % (
                    self.model, self.host, ", ".join(names[:5]) or "none")
            return True, ""
        except Exception as e:
            return False, "ollama not reachable: %r" % (e,)
