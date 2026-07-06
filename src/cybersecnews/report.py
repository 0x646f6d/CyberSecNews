"""Build the English ntfy digest from the new items of a run.

Two markdown sections — vulnerabilities and red-team — each item as a block that
ends with a link to its source article. Empty sections are omitted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .models import CATEGORY_RED_TEAM, CATEGORY_VULNERABILITY, Vulnerability

_SECTIONS = [
    (CATEGORY_VULNERABILITY, "🛡️ Vulnerabilities (zero/n-day)"),
    (CATEGORY_RED_TEAM, "🎯 Red Team / Offensive"),
]


@dataclass
class Report:
    title: str
    body: str
    click_url: str | None
    count: int

    @property
    def is_empty(self) -> bool:
        return self.count == 0


def build_report(items: list[Vulnerability], report_date: date | None = None) -> Report:
    report_date = report_date or date.today()
    by_cat: dict[str, list[Vulnerability]] = {c: [] for c, _ in _SECTIONS}
    for item in items:
        by_cat.setdefault(item.category, []).append(item)

    n_vuln = len(by_cat.get(CATEGORY_VULNERABILITY, []))
    n_red = len(by_cat.get(CATEGORY_RED_TEAM, []))
    total = n_vuln + n_red

    title = f"CyberSecNews {report_date.isoformat()} — {total} new"
    if total:
        title += f" ({n_vuln} vuln, {n_red} red-team)"

    if total == 0:
        return Report(
            title=title,
            body="No new vulnerabilities or red-team items in the last run.",
            click_url=None,
            count=0,
        )

    blocks: list[str] = []
    for cat, heading in _SECTIONS:
        cat_items = by_cat.get(cat, [])
        if not cat_items:
            continue
        blocks.append(f"## {heading} ({len(cat_items)})")
        for item in cat_items:
            blocks.append(_format_item(item))

    click_url = items[0].primary_url if items else None
    body = "\n\n".join(blocks).strip()
    return Report(title=title, body=body, click_url=click_url, count=total)


def _format_item(item: Vulnerability) -> str:
    c = item.classification
    # Headline line: product/tool + severity/technique
    name = c.product or c.vendor or c.canonical_key or item.article.title
    tags: list[str] = []
    if c.is_zero_or_nday:
        tags.append("zero/n-day")
    if c.severity:
        tags.append(c.severity)
    if c.vuln_class:
        tags.append(c.vuln_class)
    if c.cve_ids:
        tags.append(", ".join(c.cve_ids))
    meta = f" — _{' · '.join(tags)}_" if tags else ""

    summary = item.summary or c.one_line

    # Source link(s): all URLs seen for this item this run.
    links = item.urls or [item.article.url]
    if len(links) == 1:
        link_line = f"[Read more]({links[0]})"
    else:
        link_line = "Sources: " + " · ".join(
            f"[{i + 1}]({u})" for i, u in enumerate(links)
        )

    return f"### {name}{meta}\n{summary}\n{link_line}"
