"""RSS connector parsing and 24h-window filtering."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

from cybersecnews.connectors.rss import RSSConnector


def _entry(title: str, link: str, when: datetime, summary: str = "") -> str:
    return (
        "<item>"
        f"<title>{title}</title>"
        f"<link>{link}</link>"
        f"<description>{summary}</description>"
        f"<pubDate>{format_datetime(when)}</pubDate>"
        "</item>"
    )


def _write_feed(path, entries: list[str]) -> str:
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rss version="2.0"><channel><title>Test</title>'
        + "".join(entries)
        + "</channel></rss>"
    )
    path.write_text(xml, encoding="utf-8")
    return str(path)


def test_in_window_filtering(tmp_path):
    now = datetime.now(timezone.utc)
    feed = _write_feed(
        tmp_path / "feed.xml",
        [
            _entry("Recent A", "https://example.com/a", now - timedelta(hours=2), "vuln"),
            _entry("Recent B", "https://example.com/b", now - timedelta(hours=20)),
            _entry("Old C", "https://example.com/c", now - timedelta(days=3)),
        ],
    )
    connector = RSSConnector(name="test", url=feed)

    articles = connector.fetch(since=now - timedelta(hours=24))

    urls = {a.url for a in articles}
    assert urls == {"https://example.com/a", "https://example.com/b"}
    assert all(a.source == "test" for a in articles)


def test_fields_are_extracted_and_cleaned(tmp_path):
    now = datetime.now(timezone.utc)
    feed = _write_feed(
        tmp_path / "feed.xml",
        [
            _entry(
                "CVE-2024-9999 RCE",
                "https://example.com/x",
                now - timedelta(hours=1),
                summary="<p>A <b>critical</b> flaw</p>",
            )
        ],
    )
    article = RSSConnector(name="t", url=feed).fetch(since=now - timedelta(hours=24))[0]

    assert article.title == "CVE-2024-9999 RCE"
    assert "critical" in article.summary
    assert "<" not in article.summary  # HTML stripped


def test_bad_feed_returns_empty(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("not xml at all <<<", encoding="utf-8")
    articles = RSSConnector(name="t", url=str(bad)).fetch(
        since=datetime.now(timezone.utc) - timedelta(hours=24)
    )
    assert articles == []
