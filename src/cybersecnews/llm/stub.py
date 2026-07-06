"""Heuristic, no-network LLM stub.

Used for --dry-run when no ANTHROPIC_API_KEY is available, and in tests. It makes
crude keyword-based classifications so the connector/prefilter/report path can be
exercised end-to-end without spending tokens. NOT a substitute for the real model.
"""

from __future__ import annotations

import re
from typing import Optional

from ..models import (
    CATEGORY_OTHER,
    CATEGORY_RED_TEAM,
    CATEGORY_VULNERABILITY,
    Article,
    Classification,
    SeenRecord,
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_RED_TEAM_TERMS = (
    "red team",
    "c2",
    "command and control",
    "cobalt strike",
    "sliver",
    "lateral movement",
    "edr evasion",
    "edr bypass",
    "post-exploitation",
    "beacon",
    "offensive security",
)
_VULN_TERMS = (
    "vulnerability",
    "zero-day",
    "0-day",
    "exploit",
    "rce",
    "remote code execution",
    "privilege escalation",
    "authentication bypass",
    "flaw",
    "patch",
)


class HeuristicLLM:
    """Implements the LLMClient protocol with simple heuristics."""

    def classify(self, article: Article) -> Classification:
        text = article.text.lower()
        cves = sorted({m.upper() for m in _CVE_RE.findall(article.text)})

        if any(t in text for t in _RED_TEAM_TERMS):
            category = CATEGORY_RED_TEAM
        elif cves or any(t in text for t in _VULN_TERMS):
            category = CATEGORY_VULNERABILITY
        else:
            category = CATEGORY_OTHER

        is_zero = "zero-day" in text or "0-day" in text or "zero day" in text
        key = _slug(article.title)
        return Classification(
            category=category,
            canonical_key=key or "unknown",
            one_line=article.title[:140],
            is_zero_or_nday=is_zero,
            cve_ids=cves,
        )

    def match_existing(
        self, article: Article, classification: Classification, candidates: list[SeenRecord]
    ) -> Optional[int]:
        # Heuristic: exact canonical_key match only (cheap layers already ran).
        for rec in candidates:
            if rec.canonical_key and rec.canonical_key == classification.canonical_key:
                return rec.id if rec.id >= 0 else -1
        return None

    def summarize(self, article: Article, classification: Classification) -> str:
        return article.summary or classification.one_line


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:80]
