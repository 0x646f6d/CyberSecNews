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


def _byte_len(value: str) -> int:
    return len(value.encode("utf-8"))


def _hard_split_block(block: str, limit: int) -> list[str]:
    """Split a single oversized block so no piece exceeds `limit` bytes.

    Only reached when one item block is on its own larger than the whole limit
    (e.g. a very long summary). Break on line boundaries first, then, if a single
    line is still too big, on character boundaries (keeping UTF-8 codepoints
    whole so we never emit half a multi-byte character).
    """
    pieces: list[str] = []
    current = ""
    for line in block.split("\n"):
        candidate = f"{current}\n{line}" if current else line
        if current and _byte_len(candidate) > limit:
            pieces.append(current)
            current = line
        else:
            current = candidate
        while _byte_len(current) > limit:
            # A single line exceeds the limit — peel off as many chars as fit.
            head = current
            while _byte_len(head) > limit:
                head = head[:-1]
            pieces.append(head)
            current = current[len(head):]
    if current:
        pieces.append(current)
    return pieces


def _split_body(body: str, limit: int) -> list[str]:
    """Pack the report body into chunks each <= `limit` UTF-8 bytes.

    The body is a sequence of `\\n\\n`-separated blocks (section headings and
    per-item blocks; see report.build_report). Blocks are kept whole and packed
    greedily so items are never cut mid-block. A block larger than the limit on
    its own is hard-split as a last resort.
    """
    if _byte_len(body) <= limit:
        return [body]

    chunks: list[str] = []
    current = ""
    for block in body.split("\n\n"):
        for piece in (
            [block] if _byte_len(block) <= limit else _hard_split_block(block, limit)
        ):
            candidate = f"{current}\n\n{piece}" if current else piece
            if current and _byte_len(candidate) > limit:
                chunks.append(current)
                current = piece
            else:
                current = candidate
    if current:
        chunks.append(current)
    return chunks


def _post(url: str, body: str, headers: dict[str, str]) -> None:
    """POST one message body to ntfy. Raises NtfyError on failure."""
    try:
        resp = requests.post(
            url,
            data=body.encode("utf-8"),
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise NtfyError(f"Failed to send ntfy report: {exc}") from exc


def send_report(report: Report, config: NtfyConfig) -> None:
    """POST the report to ntfy, splitting oversized bodies. Raises NtfyError."""
    if not config.topic:
        raise NtfyError(
            "No ntfy topic configured (set the NTFY_TOPIC environment variable)."
        )

    url = f"{config.base_url}/{config.topic}"
    base_headers = {
        "Priority": config.priority,
        "Markdown": "yes",
        "Tags": "shield,rotating_light",
    }
    if config.token:
        base_headers["Authorization"] = f"Bearer {config.token}"

    chunks = _split_body(report.body, config.max_message_bytes)
    total = len(chunks)
    log.info(
        "[ntfy] sending report to %s (%d items, %d message%s)",
        url,
        report.count,
        total,
        "" if total == 1 else "s",
    )

    for i, chunk in enumerate(chunks, start=1):
        title = report.title if total == 1 else f"{report.title} ({i}/{total})"
        headers = {**base_headers, "Title": _header_safe(title)}
        # Click points at the lead article; only worth attaching to the first
        # message so a tapped notification opens something sensible.
        if report.click_url and i == 1:
            headers["Click"] = _header_safe(report.click_url)
        _post(url, chunk, headers)

    log.info("[ntfy] report sent successfully")
