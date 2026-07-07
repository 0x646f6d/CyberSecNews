"""Shared HTTP helper for JSON API connectors (CISA KEV, GitHub Advisories).

A thin wrapper over urllib that applies a browser-like User-Agent and an explicit
timeout — mirroring the resilience approach in rss.py — and returns the raw body
plus response headers (the GitHub advisories connector needs the Link header for
cursor pagination).
"""

from __future__ import annotations

import urllib.request
from typing import Optional

# Same UA rationale as rss.py: some hosts reject the default urllib agent.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 CyberSecNews/0.1"
)


def http_get(
    url: str, timeout: int, headers: Optional[dict] = None
) -> tuple[bytes, "object"]:
    """GET a URL with a timeout. Returns (body_bytes, response_headers).

    Raises on network/HTTP error — callers are expected to catch and degrade to an
    empty result (connectors must never crash the whole run).
    """
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, **(headers or {})}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(), response.headers
