"""Report formatting: one notification per item, links, tags, empty case."""

from __future__ import annotations

from datetime import date

from cybersecnews.models import CATEGORY_RED_TEAM, CATEGORY_VULNERABILITY
from cybersecnews.report import build_report
from conftest import make_vuln


def test_empty_report():
    report = build_report([], report_date=date(2026, 7, 6))
    assert report.is_empty
    assert report.count == 0
    # A single heartbeat notification.
    assert len(report.messages) == 1
    assert "No new" in report.messages[0].body


def test_one_message_per_item_ordered():
    items = [
        make_vuln(
            title="New Sliver beacon",
            url="https://a/2",
            category=CATEGORY_RED_TEAM,
            canonical_key="sliver:c2:beacon",
        ),
        make_vuln(
            title="Ivanti auth bypass",
            url="https://a/1",
            category=CATEGORY_VULNERABILITY,
            canonical_key="ivanti:cs:auth-bypass",
            is_zero=True,
        ),
    ]
    report = build_report(items, report_date=date(2026, 7, 6))

    assert report.count == 2
    # One notification per item, vulnerabilities ordered before red-team.
    assert len(report.messages) == 2
    vuln_msg, red_msg = report.messages
    # Vulnerability first (identity in the title; emoji comes from ntfy tags).
    assert vuln_msg.title == "ivanti:cs:auth-bypass"
    assert red_msg.title == "sliver:c2:beacon"
    # Each notification links to its own source.
    assert "[Read more](https://a/1)" in vuln_msg.body
    assert "[Read more](https://a/2)" in red_msg.body
    # zero-day tag surfaces on the vulnerability item.
    assert "zero/n-day" in vuln_msg.body
    # Category-specific ntfy tags.
    assert vuln_msg.tags == "shield,rotating_light"
    assert red_msg.tags == "dart,crossed_swords"


def test_multiple_sources_listed():
    v = make_vuln(url="https://a/1", category=CATEGORY_VULNERABILITY)
    v.urls = ["https://a/1", "https://b/2"]
    report = build_report([v])
    assert len(report.messages) == 1
    body = report.messages[0].body
    assert "Sources:" in body
    assert "https://a/1" in body and "https://b/2" in body
