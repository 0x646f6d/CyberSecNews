"""ntfy sender with mocked HTTP."""

from __future__ import annotations

import pytest
import responses

from cybersecnews.config import NtfyConfig
from cybersecnews.notify import NtfyError, _header_safe, _split_body, send_report
from cybersecnews.report import Report, build_report
from conftest import make_vuln


def _big_report(n=40):
    """A report whose body comfortably exceeds a small message limit."""
    items = [
        make_vuln(
            title=f"Flaw number {i}",
            url=f"https://example.com/{i}",
            canonical_key=f"acme:widget{i}:rce",
            summary="Detailed summary text " * 8,
        )
        for i in range(n)
    ]
    return build_report(items)


@responses.activate
def test_send_posts_to_topic_with_headers():
    responses.add(responses.POST, "https://ntfy.sh/mytopic", status=200)
    report = build_report([make_vuln(url="https://a/1")])
    cfg = NtfyConfig(base_url="https://ntfy.sh", topic="mytopic", token="secret")

    send_report(report, cfg)

    assert len(responses.calls) == 1
    req = responses.calls[0].request
    assert req.headers["Title"] == report.title
    assert req.headers["Markdown"] == "yes"
    assert req.headers["Authorization"] == "Bearer secret"
    assert req.headers["Click"] == "https://a/1"


def test_missing_topic_raises():
    report = build_report([make_vuln()])
    with pytest.raises(NtfyError):
        send_report(report, NtfyConfig(topic=None))


@responses.activate
def test_http_error_raises():
    responses.add(responses.POST, "https://ntfy.sh/t", status=500)
    report = build_report([make_vuln()])
    with pytest.raises(NtfyError):
        send_report(report, NtfyConfig(topic="t"))


def test_header_safe_transliterates_and_is_latin1():
    out = _header_safe("CyberSecNews 2026-07-06 — 1 new … “quote”")
    out.encode("latin-1")  # must not raise
    assert "—" not in out and "…" not in out


def test_split_body_keeps_item_blocks_whole_and_under_limit():
    report = _big_report()
    limit = 800
    chunks = _split_body(report.body, limit)

    assert len(chunks) > 1
    for chunk in chunks:
        assert len(chunk.encode("utf-8")) <= limit
    # No item block (a "### ..." block) was cut in half: every "### " marker
    # still starts a line, and reassembled chunks reproduce the whole body.
    assert "\n\n".join(chunks) == report.body


@responses.activate
def test_send_splits_large_report_into_numbered_messages():
    responses.add(responses.POST, "https://ntfy.sh/t", status=200)
    report = _big_report()
    cfg = NtfyConfig(topic="t", max_message_bytes=800)

    send_report(report, cfg)

    total = len(responses.calls)
    assert total > 1
    for i, call in enumerate(responses.calls, start=1):
        assert len(call.request.body) <= 800
        assert call.request.headers["Title"].endswith(f"({i}/{total})")
        assert call.request.headers["Markdown"] == "yes"
    # Click only attached to the first message.
    assert "Click" in responses.calls[0].request.headers
    assert "Click" not in responses.calls[1].request.headers


@responses.activate
def test_send_small_report_stays_single_message():
    responses.add(responses.POST, "https://ntfy.sh/t", status=200)
    report = build_report([make_vuln(url="https://a/1")])

    send_report(report, NtfyConfig(topic="t"))

    assert len(responses.calls) == 1
    # Unnumbered title when it fits in one message.
    assert "(1/1)" not in responses.calls[0].request.headers["Title"]


@responses.activate
def test_send_with_unicode_title_does_not_crash():
    """Regression: an em dash in the Title header must not abort the request."""
    responses.add(responses.POST, "https://ntfy.sh/t", status=200)
    report = Report(
        title="CyberSecNews 2026-07-06 — 1 new",  # em dash, not Latin-1
        body="body",
        click_url="https://a/1",
        count=1,
    )
    send_report(report, NtfyConfig(topic="t"))
    sent_title = responses.calls[0].request.headers["Title"]
    sent_title.encode("latin-1")  # the header actually sent is encodable
    assert "—" not in sent_title
