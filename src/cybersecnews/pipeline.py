"""Pipeline orchestration: fetch → prefilter → classify → dedup → summarize →
report → persist. Emits one log line per stage so runs are traceable.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .config import Config
from .connectors import build_connectors
from .db import Database
from .dedup import DedupEngine
from .llm.base import LLMClient
from .logging_setup import get_logger
from .models import Article, Vulnerability
from .report import Report, build_report

log = get_logger(__name__)


@dataclass
class RunStats:
    fetched: int = 0
    in_window: int = 0
    prefiltered: int = 0
    classified_interesting: int = 0
    new_items: int = 0
    duplicates: int = 0
    report: Report | None = None
    items: list[Vulnerability] = field(default_factory=list)


def run(config: Config, db: Database, llm: LLMClient, dry_run: bool = False) -> RunStats:
    stats = RunStats()
    since = datetime.now(timezone.utc) - timedelta(hours=config.since_hours)
    log.info(
        "starting run: since=%s (%dh), dry_run=%s",
        since.isoformat(),
        config.since_hours,
        dry_run,
    )

    # -- fetch (concurrent; each connector swallows its own errors) ------------
    enabled = config.enabled_connectors()
    connectors = build_connectors(enabled, timeout=config.fetch_timeout)
    articles: list[Article] = []
    if connectors:
        workers = min(config.fetch_workers, len(connectors))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(lambda c: c.fetch(since), connectors):
                articles.extend(result)
    stats.in_window = len(articles)
    log.info("fetched %d articles in window across all sources", stats.in_window)

    # -- prefilter -------------------------------------------------------------
    # Curated, trusted feeds skip the keyword gate and always reach the LLM.
    bypass = {c.name for c in enabled if c.bypass_prefilter}
    candidates = [
        a
        for a in articles
        if a.source in bypass or _passes_prefilter(a, config.prefilter)
    ]
    stats.prefiltered = len(candidates)
    log.info(
        "prefilter kept %d / %d articles", stats.prefiltered, stats.in_window
    )

    dedup = DedupEngine(
        db=db,
        llm=llm,
        window_days=config.dedup_window_days,
        use_semantic=config.llm.semantic_dedup,
    )

    new_items: list[Vulnerability] = []
    for article in candidates:
        classification = llm.classify(article)
        if not classification.is_interesting:
            log.debug("[classify] drop (%s): %s", classification.category, article.url)
            continue
        if classification.category not in config.categories:
            log.debug(
                "[classify] category %s not enabled: %s",
                classification.category,
                article.url,
            )
            continue
        stats.classified_interesting += 1

        vuln = Vulnerability(
            article=article, classification=classification, urls=[article.url]
        )

        result = dedup.check(vuln)
        if result.is_duplicate:
            stats.duplicates += 1
            log.info(
                "[dedup] duplicate (%s): %s [%s]",
                result.reason,
                article.title,
                classification.canonical_key,
            )
            # Backfill CVEs onto the matched record (e.g. zero-day got a CVE).
            if result.matched_record_id is not None and classification.cve_ids and not dry_run:
                db.add_cves(result.matched_record_id, classification.cve_ids)
            continue

        # New item: summarize and keep.
        vuln.summary = llm.summarize(article, classification)
        dedup.remember(vuln)
        new_items.append(vuln)
        log.info(
            "[new] %s [%s] (%s)",
            article.title,
            classification.canonical_key,
            classification.category,
        )

    stats.new_items = len(new_items)
    stats.items = new_items
    log.info(
        "classified interesting=%d, new=%d, duplicates=%d",
        stats.classified_interesting,
        stats.new_items,
        stats.duplicates,
    )

    # -- report ----------------------------------------------------------------
    report = build_report(new_items)
    stats.report = report

    # -- persist (only after the report is built, and never on dry runs) -------
    if not dry_run:
        for vuln in new_items:
            db.insert(vuln)
        log.info("persisted %d new items to the database", stats.new_items)
    else:
        log.info("dry run: not persisting or sending")

    return stats


def _passes_prefilter(article: Article, prefilter: dict[str, list[str]]) -> bool:
    """Cheap keyword gate. Passes if any configured term appears in the text.

    If no prefilter terms are configured at all, everything passes (the LLM then
    does all the filtering).
    """
    terms = [t.lower() for terms in prefilter.values() for t in terms]
    if not terms:
        return True
    haystack = article.text.lower()
    return any(term in haystack for term in terms)
