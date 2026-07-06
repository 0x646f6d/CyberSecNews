"""Three-layer, CVE-independent deduplication.

Layer 1 (no LLM): article URL already seen, or any extracted CVE already stored.
Layer 2 (no LLM): canonical_key matches an existing item.
Layer 3 (one LLM call): semantic match against the recent window.

Layers are also applied against items accepted earlier in the SAME run, so two
articles about the same fresh zero-day in one batch collapse to one report entry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .db import Database
from .llm.base import LLMClient
from .logging_setup import get_logger
from .models import SeenRecord, Vulnerability

log = get_logger(__name__)


@dataclass
class DedupResult:
    is_duplicate: bool
    reason: str = ""
    # DB record id of the match (None if the match is an item accepted earlier
    # this run and not yet persisted).
    matched_record_id: Optional[int] = None


@dataclass
class DedupEngine:
    db: Database
    llm: LLMClient
    window_days: int = 45
    use_semantic: bool = True
    # Items accepted earlier in the current run (not yet persisted).
    _pending: list[SeenRecord] = field(default_factory=list)

    def check(self, vuln: Vulnerability) -> DedupResult:
        c = vuln.classification

        # -- Layer 1: url / CVE (against DB and this-run pending) ---------------
        if self.db.url_seen(vuln.primary_url):
            return DedupResult(True, "layer1:url-seen")
        for pend in self._pending:
            if pend.url == vuln.primary_url:
                return DedupResult(True, "layer1:url-seen(pending)")

        if c.cve_ids:
            rec = self.db.find_by_cve(c.cve_ids)
            if rec is not None:
                return DedupResult(True, "layer1:cve", rec.id)
            cveset = {x.upper() for x in c.cve_ids}
            for pend in self._pending:
                if cveset & {x.upper() for x in pend.cve_ids}:
                    return DedupResult(True, "layer1:cve(pending)")

        # -- Layer 2: canonical_key -------------------------------------------
        if c.canonical_key:
            rec = self.db.find_by_canonical_key(c.canonical_key)
            if rec is not None:
                return DedupResult(True, "layer2:canonical-key", rec.id)
            for pend in self._pending:
                if pend.canonical_key and pend.canonical_key == c.canonical_key:
                    return DedupResult(True, "layer2:canonical-key(pending)")

        # -- Layer 3: semantic match ------------------------------------------
        if self.use_semantic:
            candidates = self.db.recent_records(self.window_days) + self._pending
            if candidates:
                match_id = self.llm.match_existing(vuln.article, c, candidates)
                if match_id is not None:
                    # match_id may reference a pending (unpersisted, id<0) item.
                    real_id = match_id if match_id >= 0 else None
                    return DedupResult(True, "layer3:semantic", real_id)

        return DedupResult(False)

    def remember(self, vuln: Vulnerability) -> None:
        """Record an accepted item so later items this run can dedup against it.

        Uses a negative id to mark it as not-yet-persisted.
        """
        c = vuln.classification
        self._pending.append(
            SeenRecord(
                id=-(len(self._pending) + 1),
                category=c.category,
                vendor=c.vendor,
                product=c.product,
                vuln_class=c.vuln_class,
                canonical_key=c.canonical_key,
                cve_ids=list(c.cve_ids),
                description=vuln.summary or c.one_line,
                title=vuln.article.title,
                source=vuln.article.source,
                url=vuln.primary_url,
                first_seen_at=vuln.article.published,
            )
        )
