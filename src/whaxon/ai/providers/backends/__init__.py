"""LLM backends. Each speaks to a different provider API."""
from .base import LLMBackend, BackendError
from .ollama import OllamaBackend
from .openai import OpenAIBackend
from .anthropic import AnthropicBackend
from .google import GoogleBackend

BACKENDS = {
    "ollama": OllamaBackend,
    "openai": OpenAIBackend,
    "anthropic": AnthropicBackend,
    "google": GoogleBackend,
}

__all__ = ["LLMBackend", "BackendError", "BACKENDS",
           "OllamaBackend", "OpenAIBackend", "AnthropicBackend", "GoogleBackend"]
