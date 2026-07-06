"""Send a report to ntfy.sh."""

from __future__ import annotations

import requests

from .config import NtfyConfig
from .logging_setup import get_logger
from .report import Report

log = get_logger(__name__)


class NtfyError(Exception):
    pass


def send_report(report: Report, config: NtfyConfig) -> None:
    """POST the report to ntfy. Raises NtfyError on failure."""
    if not config.topic:
        raise NtfyError(
            "No ntfy topic configured (set the NTFY_TOPIC environment variable)."
        )

    url = f"{config.base_url}/{config.topic}"
    headers = {
        "Title": report.title,
        "Priority": config.priority,
        "Markdown": "yes",
        "Tags": "shield,rotating_light",
    }
    if report.click_url:
        headers["Click"] = report.click_url
    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"

    log.info("[ntfy] sending report to %s (%d items)", url, report.count)
    try:
        resp = requests.post(
            url,
            data=report.body.encode("utf-8"),
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise NtfyError(f"Failed to send ntfy report: {exc}") from exc
    log.info("[ntfy] report sent successfully")
