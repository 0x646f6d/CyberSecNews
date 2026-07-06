"""Shared test helpers: fakes and builders."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from cybersecnews.models import (
    CATEGORY_VULNERABILITY,
    Article,
    Classification,
    SeenRecord,
    Vulnerability,
)


def make_article(
    title="Some flaw",
    url="https://example.com/1",
    summary="A vulnerability",
    source="test",
    published: Optional[datetime] = None,
) -> Article:
    return Article(
        source=source,
        title=title,
        url=url,
        summary=summary,
        published=published or datetime.now(timezone.utc),
    )


def make_vuln(
    title="Some flaw",
    url="https://example.com/1",
    category=CATEGORY_VULNERABILITY,
    canonical_key="acme:widget:rce",
    cve_ids=None,
    is_zero=False,
    summary="Summary text",
) -> Vulnerability:
    article = make_article(title=title, url=url)
    classification = Classification(
        category=category,
        canonical_key=canonical_key,
        one_line=title,
        is_zero_or_nday=is_zero,
        cve_ids=list(cve_ids or []),
    )
    return Vulnerability(
        article=article, classification=classification, summary=summary, urls=[url]
    )


class FakeLLM:
    """Programmable LLM stub implementing the LLMClient protocol.

    `classifications` maps article.url -> Classification.
    `semantic_matches` maps article.url -> record id (or None) for match_existing.
    """

    def __init__(self, classifications=None, semantic_matches=None):
        self.classifications = classifications or {}
        self.semantic_matches = semantic_matches or {}
        self.summarize_calls = 0

    def classify(self, article: Article) -> Classification:
        return self.classifications[article.url]

    def match_existing(
        self, article, classification, candidates: list[SeenRecord]
    ) -> Optional[int]:
        return self.semantic_matches.get(article.url)

    def summarize(self, article, classification) -> str:
        self.summarize_calls += 1
        return f"SUMMARY: {article.title}"
