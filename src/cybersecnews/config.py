"""Configuration loading and validation.

Non-secret settings live in a YAML file (config.yaml, falling back to
config.example.yaml). Secrets are read from the environment so they never touch
the repository: ANTHROPIC_API_KEY, plus the ntfy topic/token whose env var names
are given in the YAML.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


@dataclass
class ConnectorConfig:
    name: str
    type: str
    url: str
    enabled: bool = True
    # If true, this source's articles skip the keyword prefilter and always reach
    # the LLM classifier. Use for curated, low-volume feeds (e.g. red-team research
    # blogs) whose posts rarely contain the prefilter keywords verbatim.
    bypass_prefilter: bool = False
    # Connector-type-specific parameters (e.g. GHSA severity filter, page cap,
    # token env var). Ignored by connectors that don't need it (e.g. rss).
    options: dict = field(default_factory=dict)


@dataclass
class LLMConfig:
    provider: str = "anthropic"
    model: str = "claude-haiku-4-5-20251001"
    max_tokens: int = 1024
    semantic_dedup: bool = True
    api_key: Optional[str] = None  # from ANTHROPIC_API_KEY


@dataclass
class NtfyConfig:
    base_url: str = "https://ntfy.sh"
    topic: Optional[str] = None  # resolved from env
    token: Optional[str] = None  # resolved from env
    priority: str = "default"
    quiet_heartbeat: bool = False


@dataclass
class FeedConfig:
    """Atom-feed output settings.

    The feed is a read/unread-capable reading surface (any feed reader tracks
    that per entry), complementing the ntfy "there's something new" ping. It is
    rendered from the persisted dedup store and written to `path` for the daily
    workflow to publish (e.g. to GitHub Pages).
    """

    enabled: bool = False
    path: str = "public/atom.xml"
    max_items: int = 100
    title: str = "CyberSecNews - zero/n-day & red-team"
    # Public URL where the feed will be served, e.g.
    # https://<user>.github.io/<repo>/atom.xml. Used for the <link rel="self">
    # and the feed id. Optional: a urn is used when unset.
    site_url: Optional[str] = None


@dataclass
class Config:
    since_hours: int = 24
    categories: list[str] = field(default_factory=lambda: ["vulnerability", "red_team"])
    connectors: list[ConnectorConfig] = field(default_factory=list)
    prefilter: dict[str, list[str]] = field(default_factory=dict)
    llm: LLMConfig = field(default_factory=LLMConfig)
    dedup_window_days: int = 45
    database: str = "data/seen.db"
    ntfy: NtfyConfig = field(default_factory=NtfyConfig)
    feed: FeedConfig = field(default_factory=FeedConfig)
    # Per-feed network timeout (seconds). Guards against a single hanging source
    # stalling the whole run now that many feeds are fetched concurrently.
    fetch_timeout: int = 15
    # Max concurrent feed fetches.
    fetch_workers: int = 10

    def enabled_connectors(self) -> list[ConnectorConfig]:
        return [c for c in self.connectors if c.enabled]


def _default_config_path() -> Path:
    """Prefer config.yaml, fall back to config.example.yaml."""
    root = Path.cwd()
    for name in ("config.yaml", "config.example.yaml"):
        candidate = root / name
        if candidate.exists():
            return candidate
    raise ConfigError(
        "No config.yaml or config.example.yaml found in the working directory."
    )


def load_config(path: Optional[str | Path] = None) -> Config:
    """Load and validate configuration from YAML + environment."""
    config_path = Path(path) if path else _default_config_path()
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    connectors = [
        ConnectorConfig(
            name=c["name"],
            type=c.get("type", "rss"),
            url=c["url"],
            enabled=c.get("enabled", True),
            bypass_prefilter=c.get("bypass_prefilter", False),
            options=c.get("options", {}) or {},
        )
        for c in raw.get("connectors", [])
    ]

    llm_raw = raw.get("llm", {})
    llm = LLMConfig(
        provider=llm_raw.get("provider", "anthropic"),
        model=llm_raw.get("model", "claude-haiku-4-5-20251001"),
        max_tokens=llm_raw.get("max_tokens", 1024),
        semantic_dedup=llm_raw.get("semantic_dedup", True),
        api_key=os.environ.get("ANTHROPIC_API_KEY"),
    )

    ntfy_raw = raw.get("ntfy", {})
    topic_env = ntfy_raw.get("topic_env", "NTFY_TOPIC")
    token_env = ntfy_raw.get("token_env", "NTFY_TOKEN")
    ntfy = NtfyConfig(
        base_url=ntfy_raw.get("base_url", "https://ntfy.sh").rstrip("/"),
        topic=os.environ.get(topic_env),
        token=os.environ.get(token_env),
        priority=ntfy_raw.get("priority", "default"),
        quiet_heartbeat=ntfy_raw.get("quiet_heartbeat", False),
    )

    feed_raw = raw.get("feed", {})
    feed = FeedConfig(
        enabled=feed_raw.get("enabled", False),
        path=feed_raw.get("path", "public/atom.xml"),
        max_items=feed_raw.get("max_items", 100),
        title=feed_raw.get("title", "CyberSecNews - zero/n-day & red-team"),
        site_url=feed_raw.get("site_url"),
    )

    config = Config(
        since_hours=raw.get("since_hours", 24),
        categories=raw.get("categories", ["vulnerability", "red_team"]),
        connectors=connectors,
        prefilter=raw.get("prefilter", {}),
        llm=llm,
        dedup_window_days=raw.get("dedup_window_days", 45),
        database=raw.get("database", "data/seen.db"),
        ntfy=ntfy,
        feed=feed,
        fetch_timeout=raw.get("fetch_timeout", 15),
        fetch_workers=raw.get("fetch_workers", 10),
    )
    _validate(config)
    return config


def _validate(config: Config) -> None:
    if not config.enabled_connectors():
        raise ConfigError("No enabled connectors configured.")
    if config.since_hours <= 0:
        raise ConfigError("since_hours must be positive.")
    if not config.categories:
        raise ConfigError("At least one category must be enabled.")
