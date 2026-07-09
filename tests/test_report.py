"""Report formatting: sections, source links, counts, empty case."""

from __future__ import annotations

from datetime import date

from cybersecnews.models import CATEGORY_RED_TEAM, CATEGORY_VULNERABILITY
from cybersecnews.report import build_report
from conftest import make_vuln


def test_empty_report():
    report = build_report([], report_date=date(2026, 7, 6))
    assert report.is_empty
    assert report.count == 0
    assert "No new" in report.body


def test_two_sections_and_counts():
    items = [
        make_vuln(
            title="Ivanti auth bypass",
            url="https://a/1",
            category=CATEGORY_VULNERABILITY,
            canonical_key="ivanti:cs:auth-bypass",
            is_zero=True,
        ),
        make_vuln(
            title="New Sliver beacon",
            url="https://a/2",
            category=CATEGORY_RED_TEAM,
            canonical_key="sliver:c2:beacon",
        ),
    ]
    report = build_report(items, report_date=date(2026, 7, 6))

    assert report.count == 2
    assert "1 vuln, 1 red-team" in report.title
    assert "🛡️ Vulnerabilities" in report.body
    assert "🎯 Red Team" in report.body
    # Every item links to its source.
    assert "[Read more](https://a/1)" in report.body
    assert "[Read more](https://a/2)" in report.body
    # zero-day tag surfaces.
    assert "zero/n-day" in report.body


def test_empty_section_omitted():
    items = [make_vuln(url="https://a/1", category=CATEGORY_VULNERABILITY)]
    report = build_report(items)
    assert "🛡️ Vulnerabilities" in report.body
    assert "🎯 Red Team" not in report.body


def test_multiple_sources_listed():
    v = make_vuln(url="https://a/1", category=CATEGORY_VULNERABILITY)
    v.urls = ["https://a/1", "https://b/2"]
    report = build_report([v])
    assert "Sources:" in report.body
    assert "https://a/1" in report.body and "https://b/2" in report.body
