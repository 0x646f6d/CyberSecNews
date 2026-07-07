"""CISA Known Exploited Vulnerabilities (KEV) connector.

KEV is a JSON catalogue of *actively exploited* vulnerabilities — the highest-signal
fast source for the n-day use case. Each entry already carries a CVE, so the CVE in
the article text lets the LLM classifier extract it and dedup layer 1 catch repeats.

Feed shape:
    {"count": N, "vulnerabilities": [
        {"cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
         "shortDescription", "requiredAction", "knownRansomwareCampaignUse", ...}
    ]}
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ..logging_setup import get_logger
from ..models import Article
from .base import Connector
from .http import http_get

log = get_logger(__name__)


class CisaKevConnector(Connector):
    def __init__(self, name: str, url: str, timeout: int = 15) -> None:
        super().__init__(name)
        self.url = url
        self.timeout = timeout

    def fetch(self, since: datetime) -> list[Article]:
        since_date = _as_utc(since).date()
        log.info("[%s] fetching %s", self.name, self.url)
        try:
            body, _ = http_get(self.url, self.timeout)
            data = json.loads(body)
        except Exception as exc:  # network error, timeout, bad JSON …
            log.error("[%s] fetch failed: %s", self.name, exc)
            return []

        entries = data.get("vulnerabilities", [])
        articles: list[Article] = []
        for e in entries:
            added = _parse_date(e.get("dateAdded"))
            # dateAdded is day-granular; include the whole day of `since` so a
            # short look-back window never drops a same-day addition.
            if added is None or added.date() < since_date:
                continue
            article = _to_article(self.name, e, added)
            if article is not None:
                articles.append(article)

        log.info(
            "[%s] fetched %d / in-window %d",
            self.name,
            len(entries),
            len(articles),
        )
        return articles


def _to_article(source: str, e: dict, added: datetime) -> Article | None:
    cve = (e.get("cveID") or "").strip()
    vendor = (e.get("vendorProject") or "").strip()
    product = (e.get("product") or "").strip()
    name = (e.get("vulnerabilityName") or "").strip()
    if not cve:
        return None

    title = f"{vendor} {product}: {name}".strip(": ").strip()
    # Keep the CVE in the title so classify extracts it and dedup layer 1 works.
    title = f"{title} ({cve})" if cve not in title else title

    parts = [e.get("shortDescription", "").strip()]
    action = (e.get("requiredAction") or "").strip()
    if action:
        parts.append(f"Required action: {action}")
    if (e.get("knownRansomwareCampaignUse") or "").lower() == "known":
        parts.append("Known ransomware campaign use.")
    summary = f"CISA KEV — actively exploited. {cve}. " + " | ".join(p for p in parts if p)

    return Article(
        source=source,
        title=title or cve,
        url=f"https://nvd.nist.gov/vuln/detail/{cve}",
        summary=summary,
        published=added,
    )


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_date(value) -> datetime | None:
    """Parse a KEV 'YYYY-MM-DD' date into a UTC datetime at midnight."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
