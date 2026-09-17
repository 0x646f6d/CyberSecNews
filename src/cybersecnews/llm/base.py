"""LLM client protocol.

The pipeline depends only on this interface, so a local (Ollama) backend can be
added later without touching pipeline code.
"""

from __future__ import annotations

from typing import Optional, Protocol

from ..models import Article, Classification, SeenRecord


class LLMUnavailableError(RuntimeError):
    """Raised when the LLM backend appears systemically unreachable.

    Individual failed calls are tolerated (a single flaky article is dropped),
    but if *every* classify call in a run errors — e.g. the API key is invalid,
    the credit balance is exhausted, or the endpoint is wrong — the run produced
    nothing because the model was down, not because there was no news. The
    pipeline raises this so the CLI exits non-zero and the workflow goes red
    instead of silently reporting nothing.
    """


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
