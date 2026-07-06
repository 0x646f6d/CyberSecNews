"""Send a report to ntfy.sh."""

from __future__ import annotations

import unicodedata

import requests

from .config import NtfyConfig
from .logging_setup import get_logger
from .report import Report

log = get_logger(__name__)

# Common non-Latin-1 punctuation → ASCII, so header values survive HTTP encoding.
_TRANSLITERATE = {
    "—": "-",  # em dash
    "–": "-",  # en dash
    "‘": "'",  # left single quote
    "’": "'",  # right single quote
    "“": '"',  # left double quote
    "”": '"',  # right double quote
    "…": "...",  # ellipsis
    " ": " ",  # non-breaking space
}


class NtfyError(Exception):
    pass


def _header_safe(value: str) -> str:
    """Make a string safe for an HTTP header value.

    HTTP headers are encoded as Latin-1 by the http stack, so any character
    outside that range (e.g. an em dash) raises UnicodeEncodeError and aborts the
    request. Transliterate the common offenders, then drop anything still
    non-encodable.
    """
    value = "".join(_TRANSLITERATE.get(ch, ch) for ch in value)
    try:
        value.encode("latin-1")
        return value
    except UnicodeEncodeError:
        # Decompose accents where possible, then drop the rest.
        decomposed = unicodedata.normalize("NFKD", value)
        return decomposed.encode("latin-1", "ignore").decode("latin-1")


def send_report(report: Report, config: NtfyConfig) -> None:
    """POST the report to ntfy. Raises NtfyError on failure."""
    if not config.topic:
        raise NtfyError(
            "No ntfy topic configured (set the NTFY_TOPIC environment variable)."
        )

    url = f"{config.base_url}/{config.topic}"
    headers = {
        "Title": _header_safe(report.title),
        "Priority": config.priority,
        "Markdown": "yes",
        "Tags": "shield,rotating_light",
    }
    if report.click_url:
        headers["Click"] = _header_safe(report.click_url)
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
