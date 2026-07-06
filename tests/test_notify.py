"""ntfy sender with mocked HTTP."""

from __future__ import annotations

import pytest
import responses

from cybersecnews.config import NtfyConfig
from cybersecnews.notify import NtfyError, send_report
from cybersecnews.report import build_report
from conftest import make_vuln


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
