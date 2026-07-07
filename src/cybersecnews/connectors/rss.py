"""Generic RSS/Atom connector built on feedparser.

Handles all v1 sources (heise, Golem, The Hacker News, BleepingComputer) — they
differ only by feed URL, which comes from config.
"""

from __future__ import annotations

import urllib.request
from datetime import datetime, timezone
from time import mktime
from typing import Optional

import feedparser

from ..logging_setup import get_logger
from ..models import Article
from .base import Connector

log = get_logger(__name__)

# Some feeds (heise, BleepingComputer) reject the default urllib User-Agent with
# a 403, so present a browser-like one.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 CyberSecNews/0.1"
)

# Default per-feed network timeout in seconds. feedparser.parse() has no timeout
# parameter, so we fetch the bytes ourselves (below) and hand them to feedparser.
_DEFAULT_TIMEOUT = 15


class RSSConnector(Connector):
    def __init__(self, name: str, url: str, timeout: int = _DEFAULT_TIMEOUT) -> None:
        super().__init__(name)
        self.url = url
        self.timeout = timeout

    def fetch(self, since: datetime) -> list[Article]:
        since = _as_utc(since)
        log.info("[%s] fetching %s", self.name, self.url)
        try:
            if self.url.startswith(("http://", "https://")):
                # Fetch bytes with an explicit timeout (feedparser.parse takes
                # none), then parse. Don't advertise gzip so we get plain text.
                request = urllib.request.Request(
                    self.url, headers={"User-Agent": _USER_AGENT}
                )
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
                parsed = feedparser.parse(raw)
            else:
                # Local path / non-HTTP source (used in tests) — let feedparser
                # handle it directly; no network timeout applies.
                parsed = feedparser.parse(self.url, agent=_USER_AGENT)
        except Exception as exc:  # network error, timeout, HTTP error, …
            log.error("[%s] fetch failed: %s", self.name, exc)
            return []

        if parsed.bozo and not parsed.entries:
            log.error(
                "[%s] feed could not be parsed: %s",
                self.name,
                getattr(parsed, "bozo_exception", "unknown error"),
            )
            return []

        total = len(parsed.entries)
        articles: list[Article] = []
        undated = 0
        for entry in parsed.entries:
            published = _entry_datetime(entry)
            if published is None:
                # No usable date: include it (better to over-include than miss a
                # zero-day) and let dedup handle repeats.
                undated += 1
                published = datetime.now(timezone.utc)
            elif published < since:
                continue

            link = entry.get("link", "").strip()
            if not link:
                continue

            articles.append(
                Article(
                    source=self.name,
                    title=_clean(entry.get("title", "(no title)")),
                    url=link,
                    summary=_clean(entry.get("summary", "")),
                    published=published,
                )
            )

        log.info(
            "[%s] fetched %d / in-window %d (undated included: %d)",
            self.name,
            total,
            len(articles),
            undated,
        )
        return articles


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _entry_datetime(entry) -> Optional[datetime]:
    """Extract a timezone-aware UTC datetime from a feedparser entry."""
    for key in ("published_parsed", "updated_parsed"):
        struct = entry.get(key)
        if struct:
            return datetime.fromtimestamp(mktime(struct), tz=timezone.utc)
    return None


def _clean(text: str) -> str:
    """Strip HTML tags and collapse whitespace from feed text."""
    import re

    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"\s+", " ", text)
    return text.strip()
