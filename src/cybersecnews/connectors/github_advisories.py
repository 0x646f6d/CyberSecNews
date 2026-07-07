"""GitHub global Security Advisories (GHSA) connector.

Pulls reviewed advisories from the REST API, newest first, filtered to a severity
allow-list (default: critical only, to avoid the long-tail package-CVE noise). Each
advisory carries a CVE and an html_url, so it flows through the normal pipeline
(classify → dedup → summarize) and dedup layer 1 catches repeats via the CVE.

API: GET https://api.github.com/advisories
     ?type=reviewed&severity=critical&sort=published&direction=desc&per_page=100
Cursor pagination via the `Link: rel="next"` response header. Works unauthenticated
(60 req/h); an optional token (env var, default GITHUB_TOKEN) raises it to 5000/h.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlencode

from ..logging_setup import get_logger
from ..models import Article
from .base import Connector
from .http import http_get

log = get_logger(__name__)

_NEXT_LINK = re.compile(r'<([^>]+)>;\s*rel="next"')


class GitHubAdvisoriesConnector(Connector):
    def __init__(
        self, name: str, url: str, timeout: int = 15, options: dict | None = None
    ) -> None:
        super().__init__(name)
        self.url = url
        self.timeout = timeout
        options = options or {}
        self.severities = {
            s.lower() for s in (options.get("severities") or ["critical"])
        }
        self.type = options.get("type", "reviewed")
        self.max_pages = int(options.get("max_pages", 3))
        self.token_env = options.get("token_env", "GITHUB_TOKEN")

    def fetch(self, since: datetime) -> list[Article]:
        since = _as_utc(since)
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get(self.token_env) if self.token_env else None
        if token:
            headers["Authorization"] = f"Bearer {token}"

        params = {
            "type": self.type,
            "sort": "published",
            "direction": "desc",
            "per_page": "100",
        }
        # The API severity filter takes a single value; only send it when the
        # allow-list is a single severity. Otherwise rely on the client filter.
        if len(self.severities) == 1:
            params["severity"] = next(iter(self.severities))
        next_url = f"{self.url}?{urlencode(params)}"

        log.info("[%s] fetching %s", self.name, self.url)
        articles: list[Article] = []
        seen = 0
        for _ in range(self.max_pages):
            if not next_url:
                break
            try:
                body, resp_headers = http_get(next_url, self.timeout, headers)
                page = json.loads(body)
            except Exception as exc:  # network error, timeout, bad JSON, rate limit
                log.error("[%s] fetch failed: %s", self.name, exc)
                break

            stop = False
            for adv in page:
                seen += 1
                published = _parse_dt(adv.get("published_at"))
                if published is None:
                    continue
                if published < since:
                    stop = True  # sorted desc → everything after is older too
                    break
                if (adv.get("severity") or "").lower() not in self.severities:
                    continue
                article = _to_article(self.name, adv, published)
                if article is not None:
                    articles.append(article)

            if stop:
                break
            next_url = _next_link(resp_headers.get("Link"))

        log.info("[%s] fetched %d / in-window %d", self.name, seen, len(articles))
        return articles


def _to_article(source: str, adv: dict, published: datetime) -> Article | None:
    summary_text = (adv.get("summary") or "").strip()
    html_url = (adv.get("html_url") or "").strip()
    if not html_url:
        return None
    cve = (adv.get("cve_id") or "").strip()
    severity = (adv.get("severity") or "").strip()

    title = summary_text or adv.get("ghsa_id", "GitHub advisory")
    if cve and cve not in title:
        title = f"{title} ({cve})"

    pkgs = []
    for v in adv.get("vulnerabilities") or []:
        pkg = (v or {}).get("package") or {}
        eco, pname = pkg.get("ecosystem"), pkg.get("name")
        if pname:
            pkgs.append(f"{eco}/{pname}" if eco else pname)

    parts = [f"GitHub Security Advisory. Severity: {severity}."]
    if cve:
        parts.append(cve)
    desc = (adv.get("description") or "").strip()
    if desc:
        parts.append(desc[:500])
    if pkgs:
        parts.append("Affected: " + ", ".join(sorted(set(pkgs))[:8]))
    summary = " ".join(parts)

    return Article(
        source=source, title=title, url=html_url, summary=summary, published=published
    )


def _next_link(link_header) -> str | None:
    if not link_header:
        return None
    m = _NEXT_LINK.search(link_header)
    return m.group(1) if m else None


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_dt(value) -> datetime | None:
    """Parse an ISO-8601 timestamp (e.g. '2026-07-07T13:01:01Z') to UTC."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except (ValueError, TypeError):
        return None
