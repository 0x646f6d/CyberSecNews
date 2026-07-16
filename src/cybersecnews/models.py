"""Core data structures passed through the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# Category values shared across the codebase.
CATEGORY_VULNERABILITY = "vulnerability"
CATEGORY_RED_TEAM = "red_team"
CATEGORY_OTHER = "other"


@dataclass
class Article:
    """A single news item as fetched from a connector, before classification."""

    source: str
    title: str
    url: str
    summary: str
    published: datetime

    @property
    def text(self) -> str:
        """Combined text used for keyword prefiltering and LLM input."""
        return f"{self.title}\n\n{self.summary}".strip()


@dataclass
class Classification:
    """Structured fields extracted by the LLM for one article."""

    category: str  # vulnerability | red_team | other
    canonical_key: str  # normalized identity slug, e.g. "ivanti:connect-secure:auth-bypass"
    one_line: str
    is_zero_or_nday: bool = False
    vendor: Optional[str] = None
    product: Optional[str] = None
    vuln_class: Optional[str] = None  # for red_team: technique/tactic
    affected_component: Optional[str] = None
    cve_ids: list[str] = field(default_factory=list)
    severity: Optional[str] = None
    # How relevant this item is to *us*, independent of raw CVSS severity: 1
    # (negligible — obscure/no-name product, tiny install base) .. 5 (critical —
    # ubiquitous / perimeter / actively exploited, e.g. Windows, VPN appliances).
    # None when the LLM did not score it (older records / stub); treated as
    # "unknown", which fails open (never filtered).
    relevance: Optional[int] = None

    @property
    def is_interesting(self) -> bool:
        return self.category in (CATEGORY_VULNERABILITY, CATEGORY_RED_TEAM)


@dataclass
class Vulnerability:
    """A classified, deduplicated item ready to be reported and/or stored.

    Named `Vulnerability` for historical reasons; also carries red-team items.
    """

    article: Article
    classification: Classification
    summary: str = ""  # LLM long-form summary; filled for new items
    # All source URLs seen for this item in the current run (primary first).
    urls: list[str] = field(default_factory=list)

    # --- convenience passthroughs -------------------------------------------------
    @property
    def category(self) -> str:
        return self.classification.category

    @property
    def canonical_key(self) -> str:
        return self.classification.canonical_key

    @property
    def cve_ids(self) -> list[str]:
        return self.classification.cve_ids

    @property
    def primary_url(self) -> str:
        return self.urls[0] if self.urls else self.article.url


@dataclass
class SeenRecord:
    """A row from the dedup database representing an already-reported item."""

    id: int
    category: str
    vendor: Optional[str]
    product: Optional[str]
    vuln_class: Optional[str]
    canonical_key: str
    cve_ids: list[str]
    description: str
    title: str
    source: str
    url: str
    first_seen_at: datetime
