"""Structured, traceable logging.

Logs go to stdout so they are captured by GitHub Actions. The format is
deliberately grep-friendly: every pipeline stage emits one line per source with
counts, which makes it easy to answer "why did no news come in?".
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def configure(verbose: bool = False) -> None:
    """Configure the root logger. Idempotent."""
    global _CONFIGURED
    level = logging.DEBUG if verbose else logging.INFO

    root = logging.getLogger()
    root.setLevel(level)

    if not _CONFIGURED:
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )
        root.addHandler(handler)
        _CONFIGURED = True
    else:
        for handler in root.handlers:
            handler.setLevel(level)

    # anthropic/httpx are chatty at DEBUG; keep them at WARNING unless needed.
    for noisy in ("httpx", "httpcore", "anthropic", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
