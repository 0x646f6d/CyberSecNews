"""Connector registry.

Maps a connector `type` string from config to a concrete Connector class.
Register new source types here.
"""

from __future__ import annotations

from ..config import ConnectorConfig
from ..logging_setup import get_logger
from .base import Connector
from .rss import RSSConnector

log = get_logger(__name__)

_REGISTRY = {
    "rss": lambda c: RSSConnector(name=c.name, url=c.url),
}


def build_connectors(configs: list[ConnectorConfig]) -> list[Connector]:
    """Instantiate connectors for the enabled config entries."""
    connectors: list[Connector] = []
    for cfg in configs:
        factory = _REGISTRY.get(cfg.type)
        if factory is None:
            log.warning(
                "[%s] unknown connector type %r — skipping", cfg.name, cfg.type
            )
            continue
        connectors.append(factory(cfg))
    return connectors


__all__ = ["Connector", "RSSConnector", "build_connectors"]
