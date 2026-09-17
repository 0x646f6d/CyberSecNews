"""LLM backend wiring + shared chat-client parsing.

All offline: the shared ChatJSONClient logic (prompt orchestration, JSON
extraction, classification parsing) is exercised through a fake subclass, and
provider dispatch/validation is checked without any provider SDK installed.
"""

from __future__ import annotations

import pytest

from cybersecnews.config import ConfigError, LLMConfig, _validate, Config, ConnectorConfig
from cybersecnews.llm import build_llm
from cybersecnews.llm.chat import ChatJSONClient
from cybersecnews.models import (
    CATEGORY_OTHER,
    CATEGORY_VULNERABILITY,
    SeenRecord,
)

from conftest import make_article


class ScriptedChatClient(ChatJSONClient):
    """ChatJSONClient whose raw API responses are supplied verbatim."""

    def __init__(self, responses: list[str | None]):
        super().__init__()
        self._responses = list(responses)

    def _text_call(self, system, user):
        return self._responses.pop(0)


def test_classify_parses_json_with_fences_and_prose():
    raw = (
        "Sure, here you go:\n"
        '```json\n{"category": "vulnerability", "vendor": "Ivanti", '
        '"product": "Connect Secure", "vuln_class": "auth-bypass", '
        '"cve_ids": ["cve-2024-1234"], "relevance": 9, '
        '"canonical_key": "Ivanti:Connect-Secure:Auth-Bypass", '
        '"one_line": "Auth bypass"}\n```'
    )
    client = ScriptedChatClient([raw])
    c = client.classify(make_article())
    assert c.category == CATEGORY_VULNERABILITY
    assert c.cve_ids == ["CVE-2024-1234"]           # normalized/upper-cased
    assert c.canonical_key == "ivanti:connect-secure:auth-bypass"  # lower-cased
    assert c.relevance == 5                          # clamped 1..5


def test_classify_failed_call_drops_to_other():
    client = ScriptedChatClient([None])              # simulate an API error
    c = client.classify(make_article(title="X"))
    assert c.category == CATEGORY_OTHER
    assert c.canonical_key == ""


def test_classify_counters_distinguish_error_from_unparseable():
    # None (API error) counts as an availability failure; a non-JSON response
    # is dropped but does NOT count as the LLM being unavailable.
    client = ScriptedChatClient([None, "not json at all", '{"category": "other", "canonical_key": "", "one_line": "x"}'])
    client.classify(make_article())   # API error
    client.classify(make_article())   # unparseable
    client.classify(make_article())   # ok
    assert client.classify_calls == 3
    assert client.classify_errors == 1


def _seen(rec_id: int) -> SeenRecord:
    from datetime import datetime, timezone

    return SeenRecord(
        id=rec_id,
        category=CATEGORY_VULNERABILITY,
        vendor=None,
        product=None,
        vuln_class=None,
        canonical_key="k",
        cve_ids=[],
        description="d",
        title="t",
        source="s",
        url="https://example.com/seen",
        first_seen_at=datetime.now(timezone.utc),
    )


def test_match_existing_parses_id_and_guards_bool():
    art = make_article()
    cand = [_seen(7)]
    from cybersecnews.models import Classification

    cls = Classification(category=CATEGORY_VULNERABILITY, canonical_key="k", one_line="x")
    assert ScriptedChatClient(['{"match_id": 7}']).match_existing(art, cls, cand) == 7
    assert ScriptedChatClient(['{"match_id": null}']).match_existing(art, cls, cand) is None
    assert ScriptedChatClient(['{"match_id": true}']).match_existing(art, cls, cand) is None
    # no candidates -> no call needed
    assert ScriptedChatClient([]).match_existing(art, cls, []) is None


def test_summarize_falls_back_to_one_line_on_failure():
    from cybersecnews.models import Classification

    cls = Classification(category=CATEGORY_VULNERABILITY, canonical_key="k", one_line="fallback")
    assert ScriptedChatClient([None]).summarize(make_article(), cls) == "fallback"


def _cfg(**llm_kwargs) -> Config:
    return Config(
        connectors=[ConnectorConfig(name="c", type="rss", url="http://x")],
        llm=LLMConfig(**llm_kwargs),
    )


def test_build_llm_rejects_unknown_provider():
    with pytest.raises(ValueError):
        build_llm(LLMConfig(provider="bogus"))


def test_validate_rejects_unknown_provider():
    with pytest.raises(ConfigError):
        _validate(_cfg(provider="bogus"))


def test_validate_requires_endpoint_for_azure():
    with pytest.raises(ConfigError):
        _validate(_cfg(provider="azure_foundry", endpoint=None))
    # with an endpoint it validates fine
    _validate(_cfg(provider="azure_foundry", endpoint="https://x.services.ai.azure.com/models"))


def test_build_azure_requires_key_before_sdk_import():
    # No api_key -> ValueError raised before the Azure SDK is imported, so this
    # passes even when azure-ai-inference is not installed.
    cfg = LLMConfig(
        provider="azure_foundry",
        endpoint="https://x.services.ai.azure.com/models",
        api_key=None,
    )
    with pytest.raises(ValueError):
        build_llm(cfg)
