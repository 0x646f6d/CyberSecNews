"""LLM backends."""

from __future__ import annotations

from ..config import LLMConfig
from .anthropic_client import AnthropicClient
from .azure_foundry import AzureFoundryClient
from .base import LLMClient


def build_llm(config: LLMConfig) -> LLMClient:
    if config.provider == "anthropic":
        return AnthropicClient(config)
    if config.provider == "azure_foundry":
        return AzureFoundryClient(config)
    raise ValueError(f"Unsupported LLM provider: {config.provider!r}")


__all__ = ["LLMClient", "AnthropicClient", "AzureFoundryClient", "build_llm"]
