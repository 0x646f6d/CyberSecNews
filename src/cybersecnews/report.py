"""Build the ntfy notifications for the new items of a run.

One notification **per item** — not one combined digest. The ntfy Android app
crops long message bodies in its detail view (binwiederhier/ntfy#1515), so a
single multi-item report is unreadable on the phone even though the web app
renders it fully. Short, per-item messages always display completely, and each
tap opens that item's message in the app. Each item keeps its Markdown so the
web app still renders it nicely.

An empty run produces a single heartbeat message.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .models import CATEGORY_RED_TEAM, CATEGORY_VULNERABILITY, Vulnerability

# category -> (ntfy emoji tags, sort order). ntfy renders the tags as emoji in
# front of the title, so the title text itself stays plain ASCII (emoji in the
# Title header get stripped by Latin-1 encoding).
_CATEGORY_META = {
    CATEGORY_VULNERABILITY: ("shield,rotating_light", 0),
    CATEGORY_RED_TEAM: ("dart,crossed_swords", 1),
}
_DEFAULT_META = ("newspaper", 2)


@dataclass
class Message:
    """A single ntfy notification (one news item, or the empty heartbeat)."""

    title: str
    body: str
    tags: str  # comma-separated ntfy emoji tag names


@dataclass
class Report:
    """All notifications produced by one run, plus the new-item count."""

    messages: list[Message]
    count: int

    @property
    def is_empty(self) -> bool:
        return self.count == 0


def build_report(items: list[Vulnerability], report_date: date | None = None) -> Report:
    report_date = report_date or date.today()

    if not items:
        title = f"CyberSecNews {report_date.isoformat()} - 0 new"
        body = "No new vulnerabilities or red-team items in the last run."
        heartbeat = Message(title=title, body=body, tags="shield")
        return Report(messages=[heartbeat], count=0)

    # Vulnerabilities first, then red-team, then anything else; stable within a
    # group so notifications arrive in a predictable order.
    ordered = sorted(items, key=lambda it: _CATEGORY_META.get(it.category, _DEFAULT_META)[1])
    messages = [_format_item(item) for item in ordered]
    return Report(messages=messages, count=len(items))


def _format_item(item: Vulnerability) -> Message:
    c = item.classification
    tags, _order = _CATEGORY_META.get(c.category, _DEFAULT_META)

    # Title: product/tool identity — short enough to display fully on mobile.
    # The category emoji is supplied by ntfy from `tags`, not embedded here.
    title = c.product or c.vendor or c.canonical_key or item.article.title

    meta: list[str] = []
    if c.is_zero_or_nday:
        meta.append("zero/n-day")
    if c.severity:
        meta.append(c.severity)
    if c.vuln_class:
        meta.append(c.vuln_class)
    if c.cve_ids:
        meta.append(", ".join(c.cve_ids))

    summary = item.summary or c.one_line

    # Source link(s): all URLs seen for this item this run.
    links = item.urls or [item.article.url]
    if len(links) == 1:
        link_line = f"[Read more]({links[0]})"
    else:
        link_line = "Sources: " + " · ".join(
            f"[{i + 1}]({u})" for i, u in enumerate(links)
        )

    parts: list[str] = []
    if meta:
        parts.append(f"_{' · '.join(meta)}_")
    parts.append(summary)
    parts.append(link_line)
    return Message(title=title, body="\n\n".join(parts), tags=tags)
