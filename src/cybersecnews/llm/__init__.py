"""LLM backends."""

from __future__ import annotations

from ..config import LLMConfig
from .anthropic_client import AnthropicClient
from .base import LLMClient


def build_llm(config: LLMConfig) -> LLMClient:
    if config.provider == "anthropic":
        return AnthropicClient(config)
    raise ValueError(f"Unsupported LLM provider: {config.provider!r}")


__all__ = ["LLMClient", "AnthropicClient", "build_llm"]
