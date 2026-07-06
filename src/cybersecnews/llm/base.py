"""LLM client protocol.

The pipeline depends only on this interface, so a local (Ollama) backend can be
added later without touching pipeline code.
"""

from __future__ import annotations

from typing import Optional, Protocol

from ..models import Article, Classification, SeenRecord


class LLMClient(Protocol):
    def classify(self, article: Article) -> Classification:
        """Classify one article and extract structured identity fields."""
        ...

    def match_existing(
        self, article: Article, classification: Classification, candidates: list[SeenRecord]
    ) -> Optional[int]:
        """Return the id of the seen record describing the same underlying
        item, or None if this is a genuinely new item."""
        ...

    def summarize(self, article: Article, classification: Classification) -> str:
        """Produce a concise English summary for a new item."""
        ...
