"""Send a report to ntfy.sh."""

from __future__ import annotations

import unicodedata

import requests

from .config import NtfyConfig
from .logging_setup import get_logger
from .report import Message, Report

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
    except UnicodeEncodeError:
        # Decompose accents where possible, then drop the rest.
        decomposed = unicodedata.normalize("NFKD", value)
        value = decomposed.encode("latin-1", "ignore").decode("latin-1")
    # Dropping non-encodable chars (e.g. an emoji) can leave stray leading or
    # trailing whitespace, which the http stack rejects in a header value.
    return value.strip()


def send_report(report: Report, config: NtfyConfig) -> None:
    """POST each of the report's messages to ntfy as its own notification.

    One notification per item keeps every message short enough to display in
    full on the ntfy Android app (which crops long bodies). Raises NtfyError on
    the first send failure.
    """
    if not config.topic:
        raise NtfyError(
            "No ntfy topic configured (set the NTFY_TOPIC environment variable)."
        )

    url = f"{config.base_url}/{config.topic}"
    log.info(
        "[ntfy] sending %d notification(s) to %s", len(report.messages), url
    )
    for message in report.messages:
        _send_message(url, message, config)
    log.info("[ntfy] all notifications sent successfully")


def _send_message(url: str, message: Message, config: NtfyConfig) -> None:
    # No Click header: with one set, tapping the notification on the ntfy phone
    # app opens that URL in the browser instead of the message, so the reader
    # never sees the item. Without it, a tap opens the message in the app.
    headers = {
        "Title": _header_safe(message.title),
        "Priority": config.priority,
        "Markdown": "yes",
        "Tags": message.tags,
    }
    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"

    try:
        resp = requests.post(
            url,
            data=message.body.encode("utf-8"),
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise NtfyError(f"Failed to send ntfy notification: {exc}") from exc
