"""Connector registry.

Maps a connector `type` string from config to a concrete Connector class.
Register new source types here.
"""

from __future__ import annotations

from ..config import ConnectorConfig
from ..logging_setup import get_logger
from .base import Connector
from .cisa_kev import CisaKevConnector
from .github_advisories import GitHubAdvisoriesConnector
from .rss import RSSConnector

log = get_logger(__name__)

_REGISTRY = {
    "rss": lambda c, timeout: RSSConnector(name=c.name, url=c.url, timeout=timeout),
    "cisa_kev": lambda c, timeout: CisaKevConnector(
        name=c.name, url=c.url, timeout=timeout
    ),
    "github_advisories": lambda c, timeout: GitHubAdvisoriesConnector(
        name=c.name, url=c.url, timeout=timeout, options=c.options
    ),
}


def build_connectors(
    configs: list[ConnectorConfig], timeout: int = 15
) -> list[Connector]:
    """Instantiate connectors for the enabled config entries."""
    connectors: list[Connector] = []
    for cfg in configs:
        factory = _REGISTRY.get(cfg.type)
        if factory is None:
            log.warning(
                "[%s] unknown connector type %r — skipping", cfg.name, cfg.type
            )
            continue
        connectors.append(factory(cfg, timeout))
    return connectors


__all__ = [
    "Connector",
    "RSSConnector",
    "CisaKevConnector",
    "GitHubAdvisoriesConnector",
    "build_connectors",
]
