"""GoogleBackend request shape — verifies the x-goog-api-key header path.

New-format Gemini API keys (AQ.* prefix, issued by AI Studio since
May 2026) are rejected by the ?key= query param and by Bearer auth.
They must be sent in the x-goog-api-key header. This test locks that
behavior in.
"""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

from whaxon.ai.providers.backends.google import GoogleBackend


def _fake_response(body: dict):
    m = MagicMock()
    m.read.return_value = json.dumps(body).encode("utf-8")
    m.__enter__ = lambda self: self
    m.__exit__ = lambda self, *a: None
    return m


def test_google_chat_uses_header_not_query_param() -> None:
    backend = GoogleBackend(model="gemini-2.5-flash", api_key="AQ.test-key-1234")
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        return _fake_response({
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}]
        })

    with patch("urllib.request.urlopen", fake_urlopen):
        out = backend.chat([{"role": "user", "content": "hi"}])

    assert out == "ok"
    assert "?key=" not in captured["url"]
    # urllib normalizes header names to Title-Case
    headers_lower = {k.lower(): v for k, v in captured["headers"].items()}
    assert headers_lower.get("x-goog-api-key") == "AQ.test-key-1234"
    assert "authorization" not in headers_lower


def test_google_chat_url_shape() -> None:
    backend = GoogleBackend(model="gemini-2.5-flash", api_key="AQ.x")
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _fake_response({
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}]
        })

    with patch("urllib.request.urlopen", fake_urlopen):
        backend.chat([{"role": "user", "content": "hi"}])

    assert captured["url"].endswith("/v1beta/models/gemini-2.5-flash:generateContent")
    