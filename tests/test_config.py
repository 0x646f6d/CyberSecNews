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


def test_new_fields_are_loaded(tmp_path):
    path = _write(
        tmp_path,
        """
        fetch_timeout: 8
        fetch_workers: 4
        connectors:
          - name: a
            url: https://example.com/a
            bypass_prefilter: true
          - name: b
            url: https://example.com/b
        """,
    )
    config = load_config(path)
    assert config.fetch_timeout == 8
    assert config.fetch_workers == 4
    assert config.connectors[0].bypass_prefilter is True
    assert config.connectors[1].bypass_prefilter is False
