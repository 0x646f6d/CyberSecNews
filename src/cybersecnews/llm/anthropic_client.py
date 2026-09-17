"""Anthropic Claude backend (Claude Haiku).

One classify+extract call per prefiltered article, an optional semantic-match
call for dedup, and a summarize call per new item. Prompts, JSON extraction and
classification parsing are shared with the other backends via
:class:`~cybersecnews.llm.chat.ChatJSONClient`; this module only adds the
Anthropic API call.
"""

from __future__ import annotations

from typing import Optional

from ..config import LLMConfig
from ..logging_setup import get_logger
from .chat import ChatJSONClient

log = get_logger(__name__)


class AnthropicClient(ChatJSONClient):
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
