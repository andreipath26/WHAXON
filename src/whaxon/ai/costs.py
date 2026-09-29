"""Rough LLM cost estimation. Design reference: docs/agent-architecture.md §14.

Token counts are heuristic: characters // 4. Real tokenizers vary, but
this is deterministic and close enough for a budget signal. Rates are
public list prices per 1M tokens as of the models' release. Unknown
models estimate to None (no cost shown, tokens still tracked).
"""
from __future__ import annotations

# (USD per 1M input tokens, USD per 1M output tokens)
RATES: dict[str, tuple[float, float]] = {
    # OpenAI
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    # Anthropic
    "claude-3-5-sonnet-20241022": (3.00, 15.00),
    "claude-3-5-haiku-20241022": (0.80, 4.00),
    # Google
    "gemini-1.5-flash": (0.075, 0.30),
    "gemini-2.0-flash": (0.10, 0.40),
    "gemini-2.5-flash": (0.30, 2.50),
    # Local (free)
    "qwen2.5:1.5b": (0.0, 0.0),
    "qwen2.5:7b": (0.0, 0.0),
    "llama3.2": (0.0, 0.0),
}


def estimate_tokens(text: str) -> int:
    """characters // 4, floor at 1 for non-empty strings."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def estimate_cost(model: str, tokens_in: int, tokens_out: int) -> float | None:
    """USD cost estimate, or None if the model rate is unknown."""
    rate = RATES.get(model)
    if rate is None:
        return None
    in_rate, out_rate = rate
    return (tokens_in * in_rate + tokens_out * out_rate) / 1_000_000.0