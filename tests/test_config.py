"""Config loading of the new per-connector and fetch settings."""

from __future__ import annotations

import textwrap

from cybersecnews.config import load_config


def _write(tmp_path, body: str):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def test_defaults_when_fields_absent(tmp_path):
    path = _write(
        tmp_path,
        """
        connectors:
          - name: a
            url: https://example.com/a
        """,
    )
    config = load_config(path)
    assert config.fetch_timeout == 15
    assert config.fetch_workers == 10
    # bypass_prefilter defaults to False so existing configs keep working.
    assert config.connectors[0].bypass_prefilter is False
    # Feed is off by default so existing configs keep their ntfy-only behaviour.
    assert config.feed.enabled is False
    assert config.feed.path == "public/atom.xml"
    assert config.feed.max_items == 100
    assert config.feed.site_url is None


def test_new_fields_are_loaded(tmp_path):
    path = _write(
        tmp_path,
        """
        fetch_timeout: 8
        fetch_workers: 4
        connectors:
          - name: a
            type: github_advisories
            url: https://api.github.com/advisories
            bypass_prefilter: true
            options:
              severities: [critical]
              max_pages: 2
          - name: b
            url: https://example.com/b
        """,
    )
    config = load_config(path)
    assert config.fetch_timeout == 8
    assert config.fetch_workers == 4
    assert config.connectors[0].bypass_prefilter is True
    assert config.connectors[0].options == {"severities": ["critical"], "max_pages": 2}
    assert config.connectors[1].bypass_prefilter is False
    assert config.connectors[1].options == {}  # default, backwards-compatible


def test_feed_settings_are_loaded(tmp_path):
    path = _write(
        tmp_path,
        """
        feed:
          enabled: true
          path: out/feed.xml
          max_items: 25
          site_url: https://user.github.io/repo/atom.xml
        connectors:
          - name: a
            url: https://example.com/a
        """,
    )
    config = load_config(path)
    assert config.feed.enabled is True
    assert config.feed.path == "out/feed.xml"
    assert config.feed.max_items == 25
    assert config.feed.site_url == "https://user.github.io/repo/atom.xml"
