"""Config loading, focused on the env-var overrides for the LLM block.

These let the non-secret config be driven from the environment (GitHub Actions),
where no config.yaml is committed and config.example.yaml is the base.
"""

from __future__ import annotations

import textwrap

import pytest

from cybersecnews.config import load_config


def _write(tmp_path, body: str) -> str:
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(p)


_BASE = """
    connectors:
      - name: x
        type: rss
        url: https://example.com/feed
    llm:
      provider: anthropic
      model: claude-haiku-4-5-20251001
"""


def test_env_overrides_switch_provider_to_azure(tmp_path, monkeypatch):
    path = _write(tmp_path, _BASE)
    monkeypatch.setenv("LLM_PROVIDER", "azure_foundry")
    monkeypatch.setenv("LLM_MODEL", "Llama-3.3-70B-Instruct")
    monkeypatch.setenv("LLM_ENDPOINT", "https://res.services.ai.azure.com/models")
    monkeypatch.setenv("LLM_API_VERSION", "2024-05-01-preview")
    monkeypatch.setenv("AZURE_AI_API_KEY", "secret-key")  # default key env for azure
    monkeypatch.setenv("NTFY_TOPIC", "t")

    cfg = load_config(path)

    assert cfg.llm.provider == "azure_foundry"
    assert cfg.llm.model == "Llama-3.3-70B-Instruct"
    assert cfg.llm.endpoint == "https://res.services.ai.azure.com/models"
    assert cfg.llm.api_version == "2024-05-01-preview"
    # azure default key env is AZURE_AI_API_KEY, resolved from the environment
    assert cfg.llm.api_key_env == "AZURE_AI_API_KEY"
    assert cfg.llm.api_key == "secret-key"


def test_empty_env_values_are_ignored(tmp_path, monkeypatch):
    # Actions passes "" for an unset vars.X; that must fall back to the YAML.
    path = _write(tmp_path, _BASE)
    monkeypatch.setenv("LLM_PROVIDER", "")
    monkeypatch.setenv("LLM_MODEL", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    cfg = load_config(path)

    assert cfg.llm.provider == "anthropic"
    assert cfg.llm.model == "claude-haiku-4-5-20251001"


def test_custom_api_key_env_override(tmp_path, monkeypatch):
    path = _write(tmp_path, _BASE)
    monkeypatch.setenv("LLM_API_KEY_ENV", "MY_KEY")
    monkeypatch.setenv("MY_KEY", "abc123")

    cfg = load_config(path)

    assert cfg.llm.api_key_env == "MY_KEY"
    assert cfg.llm.api_key == "abc123"
