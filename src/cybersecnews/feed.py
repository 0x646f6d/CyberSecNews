"""Render the reported items as an Atom feed.

ntfy is a fire-and-forget notification bus: it has no notion of read/unread, no
archive, no search. An Atom feed is the opposite — every mature feed reader
(NetNewsWire, Feedly, Miniflux, FreshRSS, Inoreader…) tracks read/unread per
entry, stars items and syncs across devices for free. That is exactly the
"which news have I already seen?" problem ntfy can't solve.

This module turns the persistent dedup store (`data/seen.db`) into a static
`atom.xml`. It fits the serverless model: the daily workflow already commits the
DB back, so it can just as easily publish this file to GitHub Pages. ntfy stays
on as a lightweight "there's something new" ping.

The entry `<id>` is a stable URN derived from the DB row id, so regenerating the
feed never disturbs a reader's read/unread state for items it already knows.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from .config import FeedConfig
from .logging_setup import get_logger
from .models import CATEGORY_RED_TEAM, CATEGORY_VULNERABILITY, SeenRecord

log = get_logger(__name__)

_ATOM_NS = "http://www.w3.org/2005/Atom"
_FEED_URN = "urn:cybersecnews:feed"

# Human-readable category label shown in the entry body / <category term>.
_CATEGORY_LABEL = {
    CATEGORY_VULNERABILITY: "vulnerability",
    CATEGORY_RED_TEAM: "red-team",
}


def build_atom_feed(records: list[SeenRecord], config: FeedConfig) -> str:
    """Render the given records (newest first) as an Atom 1.0 document string."""
    ET.register_namespace("", _ATOM_NS)
    feed = ET.Element(f"{{{_ATOM_NS}}}feed")

    _text(feed, "title", config.title)
    _text(feed, "id", config.site_url or _FEED_URN)
    _text(feed, "generator", "CyberSecNews")

    # The feed's <updated> is the newest entry's timestamp, or now if empty.
    newest = records[0].first_seen_at if records else datetime.now(timezone.utc)
    _text(feed, "updated", _rfc3339(newest))

    if config.site_url:
        _link(feed, config.site_url, rel="self")

    for record in records:
        _append_entry(feed, record)

    ET.indent(feed)
    xml = ET.tostring(feed, encoding="unicode", xml_declaration=True)
    # ET emits a single-quoted declaration; keep a trailing newline for tidy files.
    return xml if xml.endswith("\n") else xml + "\n"


def write_atom_feed(records: list[SeenRecord], config: FeedConfig) -> Path:
    """Render the feed and write it to `config.path`, creating parent dirs."""
    path = Path(config.path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_atom_feed(records, config), encoding="utf-8")
    log.info("[feed] wrote %d entries to %s", len(records), path)
    return path


def _append_entry(feed: ET.Element, record: SeenRecord) -> None:
    entry = ET.SubElement(feed, f"{{{_ATOM_NS}}}entry")
    _text(entry, "title", record.title or record.product or record.canonical_key)
    # Stable per-item id: derived from the DB row so it never changes across
    # regenerations, which is what keeps a reader's read/unread state intact.
    _text(entry, "id", f"urn:cybersecnews:item:{record.id}")
    stamp = _rfc3339(record.first_seen_at)
    _text(entry, "published", stamp)
    _text(entry, "updated", stamp)
    if record.url:
        _link(entry, record.url, rel="alternate")
    label = _CATEGORY_LABEL.get(record.category, record.category)
    ET.SubElement(entry, f"{{{_ATOM_NS}}}category", {"term": label})

    content = ET.SubElement(entry, f"{{{_ATOM_NS}}}content", {"type": "html"})
    content.text = _entry_html(record, label)


def _entry_html(record: SeenRecord, label: str) -> str:
    """Build the entry body as an HTML string (ElementTree escapes it for us)."""
    meta: list[str] = [label]
    if record.vuln_class:
        meta.append(record.vuln_class)
    if record.cve_ids:
        meta.append(", ".join(record.cve_ids))

    parts = [f"<p><em>{' · '.join(meta)}</em></p>"]
    if record.description:
        parts.append(f"<p>{record.description}</p>")
    footer = []
    if record.url:
        footer.append(f'<a href="{record.url}">Read more</a>')
    if record.source:
        footer.append(f"Source: {record.source}")
    if footer:
        parts.append(f"<p>{' · '.join(footer)}</p>")
    return "".join(parts)


def _text(parent: ET.Element, tag: str, value: str) -> ET.Element:
    el = ET.SubElement(parent, f"{{{_ATOM_NS}}}{tag}")
    el.text = value
    return el


def _link(parent: ET.Element, href: str, rel: str) -> None:
    ET.SubElement(parent, f"{{{_ATOM_NS}}}link", {"href": href, "rel": rel})


def _rfc3339(dt: datetime) -> str:
    """Atom timestamps must be RFC 3339. Assume UTC for any naive datetime."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
