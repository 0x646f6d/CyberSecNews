"""Atom feed rendering from the dedup store."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from cybersecnews.config import FeedConfig
from cybersecnews.feed import build_atom_feed, write_atom_feed
from cybersecnews.models import (
    CATEGORY_RED_TEAM,
    CATEGORY_VULNERABILITY,
    SeenRecord,
)

_ATOM = "{http://www.w3.org/2005/Atom}"


def _record(
    id: int,
    title="Acme Widget RCE",
    category=CATEGORY_VULNERABILITY,
    vuln_class="rce",
    cve_ids=None,
    description="A remote code execution flaw.",
    source="test",
    url="https://example.com/1",
    first_seen_at=None,
) -> SeenRecord:
    return SeenRecord(
        id=id,
        category=category,
        vendor="acme",
        product="widget",
        vuln_class=vuln_class,
        canonical_key="acme:widget:rce",
        cve_ids=list(cve_ids or []),
        description=description,
        title=title,
        source=source,
        url=url,
        first_seen_at=first_seen_at or datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc),
    )


def _parse(xml: str) -> ET.Element:
    return ET.fromstring(xml)


def test_feed_has_one_entry_per_record_with_links_and_categories():
    records = [
        _record(1, title="Acme RCE", category=CATEGORY_VULNERABILITY, cve_ids=["CVE-2026-1"]),
        _record(2, title="C2 tradecraft", category=CATEGORY_RED_TEAM, vuln_class="c2"),
    ]
    feed = _parse(build_atom_feed(records, FeedConfig()))

    entries = feed.findall(f"{_ATOM}entry")
    assert len(entries) == 2

    titles = [e.findtext(f"{_ATOM}title") for e in entries]
    assert titles == ["Acme RCE", "C2 tradecraft"]

    # Each entry links to its article and carries its category label.
    first = entries[0]
    assert first.find(f"{_ATOM}link").get("href") == "https://example.com/1"
    assert first.find(f"{_ATOM}category").get("term") == "vulnerability"
    assert entries[1].find(f"{_ATOM}category").get("term") == "red-team"


def test_entry_id_is_stable_and_derived_from_db_id():
    # The stable per-item id is what keeps a reader's read/unread state intact
    # across regenerations — it must not depend on the url or title.
    feed = _parse(build_atom_feed([_record(42)], FeedConfig()))
    entry = feed.find(f"{_ATOM}entry")
    assert entry.findtext(f"{_ATOM}id") == "urn:cybersecnews:item:42"


def test_content_includes_meta_description_and_source():
    feed = _parse(
        build_atom_feed([_record(1, cve_ids=["CVE-2026-9"])], FeedConfig())
    )
    content = feed.find(f"{_ATOM}entry").findtext(f"{_ATOM}content")
    # content is type="html"; ElementTree returns it unescaped.
    assert "rce" in content
    assert "CVE-2026-9" in content
    assert "A remote code execution flaw." in content
    assert "https://example.com/1" in content
    assert "Source: test" in content


def test_site_url_sets_feed_id_and_self_link():
    config = FeedConfig(site_url="https://user.github.io/repo/atom.xml")
    feed = _parse(build_atom_feed([_record(1)], config))
    assert feed.findtext(f"{_ATOM}id") == "https://user.github.io/repo/atom.xml"
    self_links = [
        l for l in feed.findall(f"{_ATOM}link") if l.get("rel") == "self"
    ]
    assert self_links and self_links[0].get("href") == config.site_url


def test_empty_store_produces_valid_feed_with_no_entries():
    feed = _parse(build_atom_feed([], FeedConfig()))
    assert feed.findall(f"{_ATOM}entry") == []
    # A feed still needs a title, id and updated to be valid Atom.
    assert feed.findtext(f"{_ATOM}title")
    assert feed.findtext(f"{_ATOM}id")
    assert feed.findtext(f"{_ATOM}updated")


def test_feed_updated_matches_newest_entry():
    newest = datetime(2026, 7, 5, 8, 0, tzinfo=timezone.utc)
    older = datetime(2026, 7, 1, 8, 0, tzinfo=timezone.utc)
    records = [_record(2, first_seen_at=newest), _record(1, first_seen_at=older)]
    feed = _parse(build_atom_feed(records, FeedConfig()))
    assert feed.findtext(f"{_ATOM}updated") == newest.isoformat()


def test_naive_timestamp_is_treated_as_utc():
    naive = datetime(2026, 7, 1, 12, 0)  # no tzinfo
    feed = _parse(build_atom_feed([_record(1, first_seen_at=naive)], FeedConfig()))
    stamp = feed.find(f"{_ATOM}entry").findtext(f"{_ATOM}published")
    assert stamp.endswith("+00:00")


def test_write_atom_feed_creates_file(tmp_path):
    out = tmp_path / "nested" / "atom.xml"
    config = FeedConfig(path=str(out))
    write_atom_feed([_record(1)], config)
    assert out.exists()
    # The written file is parseable Atom with our entry.
    feed = ET.parse(out).getroot()
    assert feed.find(f"{_ATOM}entry").findtext(f"{_ATOM}id") == "urn:cybersecnews:item:1"
