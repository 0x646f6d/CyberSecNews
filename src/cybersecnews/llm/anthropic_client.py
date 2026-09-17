"""Anthropic Claude backends.

Two clients speak the Anthropic Messages API with identical prompts and parsing
(shared via :class:`~cybersecnews.llm.chat.ChatJSONClient`); they differ only in
which SDK client object they construct:

- :class:`AnthropicClient` — the first-party Anthropic API (Claude Haiku).
- :class:`AzureFoundryClient` (in ``azure_foundry.py``) — Claude hosted on Azure
  AI Foundry, via the ``AnthropicFoundry`` client.

Both reuse :class:`_AnthropicMessagesClient._text_call`, since ``AnthropicFoundry``
exposes the same ``messages.create`` surface as ``Anthropic``.
"""

from __future__ import annotations

from typing import Any, Optional

from ..config import LLMConfig
from ..logging_setup import get_logger
from .chat import ChatJSONClient

log = get_logger(__name__)


class _AnthropicMessagesClient(ChatJSONClient):
    """Shared classify/summarize call for any Anthropic-Messages-API client.

    Subclasses set ``self._client`` (an ``Anthropic``/``AnthropicFoundry``-style
    object), ``self._model`` and ``self._max_tokens`` in their ``__init__`` (and
    must call ``super().__init__()`` first).
    """

    _client: Any
    _model: str
    _max_tokens: int

    def _text_call(self, system: str, user: str) -> Optional[str]:
        try:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as exc:
            log.error("[llm] API call failed: %s", exc)
            return None
        parts = [b.text for b in resp.content if getattr(b, "type", None) == "text"]
        return "".join(parts)


class AnthropicClient(_AnthropicMessagesClient):
    def __init__(self, config: LLMConfig) -> None:
        super().__init__()
        if not config.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set; cannot use the Anthropic LLM backend."
            )
        # Imported lazily so the package can be imported without the SDK present
        # (e.g. for --dry-run with a stub, or in tests).
        from anthropic import Anthropic

        self._client = Anthropic(api_key=config.api_key)
        self._model = config.model
        self._max_tokens = config.max_tokens
