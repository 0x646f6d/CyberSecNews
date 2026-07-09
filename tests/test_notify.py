"""ntfy sender with mocked HTTP."""

from __future__ import annotations

import pytest
import responses

from cybersecnews.config import NtfyConfig
from cybersecnews.notify import NtfyError, _header_safe, send_report
from cybersecnews.report import Message, Report, build_report
from conftest import make_vuln
from cybersecnews.models import CATEGORY_RED_TEAM, CATEGORY_VULNERABILITY


@responses.activate
def test_send_posts_to_topic_with_headers():
    responses.add(responses.POST, "https://ntfy.sh/mytopic", status=200)
    report = build_report([make_vuln(url="https://a/1")])
    cfg = NtfyConfig(base_url="https://ntfy.sh", topic="mytopic", token="secret")

    send_report(report, cfg)

    assert len(responses.calls) == 1
    req = responses.calls[0].request
    msg = report.messages[0]
    assert req.headers["Title"] == msg.title
    assert req.headers["Markdown"] == "yes"
    assert req.headers["Tags"] == msg.tags
    assert req.headers["Authorization"] == "Bearer secret"
    # No Click header: a tap must open the message in the ntfy app, not a website.
    assert "Click" not in req.headers


@responses.activate
def test_each_item_is_its_own_notification():
    responses.add(responses.POST, "https://ntfy.sh/t", status=200)
    report = build_report(
        [
            make_vuln(url="https://a/1", category=CATEGORY_VULNERABILITY),
            make_vuln(url="https://a/2", category=CATEGORY_RED_TEAM),
        ]
    )
    send_report(report, NtfyConfig(topic="t"))
    # Two items -> two separate ntfy notifications.
    assert len(responses.calls) == 2


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


@responses.activate
def test_send_with_unicode_title_does_not_crash():
    """Regression: an em dash in the Title header must not abort the request."""
    responses.add(responses.POST, "https://ntfy.sh/t", status=200)
    report = Report(
        messages=[
            Message(
                title="CyberSecNews 2026-07-06 — 1 new",  # em dash, not Latin-1
                body="body",
                tags="shield",
            )
        ],
        count=1,
    )
    send_report(report, NtfyConfig(topic="t"))
    sent_title = responses.calls[0].request.headers["Title"]
    sent_title.encode("latin-1")  # the header actually sent is encodable
    assert "—" not in sent_title
