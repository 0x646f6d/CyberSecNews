"""Connector abstraction.

A connector knows how to fetch recent news from one source. Adding a new source
(e.g. an X/Twitter connector later) means implementing `fetch` and registering
the connector type — nothing else in the pipeline changes.
"""

from __future__ import annotations

import abc
from datetime import datetime

from ..models import Article


class Connector(abc.ABC):
    """Base class for all news source connectors."""

    def __init__(self, name: str) -> None:
        self.name = name

    @abc.abstractmethod
    def fetch(self, since: datetime) -> list[Article]:
        """Return articles published at or after `since`.

        Implementations should be resilient: network/parse errors for a single
        source must not crash the whole run. Log and return what you have.
        """
        raise NotImplementedError
