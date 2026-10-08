"""LLM backends. Each speaks to a different provider API."""
from .anthropic import AnthropicBackend
from .base import BackendError, LLMBackend
from .google import GoogleBackend
from .ollama import OllamaBackend
from .openai import OpenAIBackend

BACKENDS = {
    "ollama": OllamaBackend,
    "openai": OpenAIBackend,
    "anthropic": AnthropicBackend,
    "google": GoogleBackend,
}

__all__ = [
    "BACKENDS",
    "AnthropicBackend",
    "BackendError",
    "GoogleBackend",
    "LLMBackend",
    "OllamaBackend",
    "OpenAIBackend",
]
