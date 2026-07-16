"""End-to-end pipeline with fake connectors and a fake LLM."""

from __future__ import annotations

from datetime import datetime, timezone

import cybersecnews.pipeline as pipeline
from cybersecnews.config import Config, ConnectorConfig, LLMConfig, NtfyConfig
from cybersecnews.db import Database
from cybersecnews.models import (
    CATEGORY_OTHER,
    CATEGORY_RED_TEAM,
    CATEGORY_VULNERABILITY,
    Article,
    Classification,
)
from conftest import FakeLLM


def _config(tmp_path) -> Config:
    return Config(
        since_hours=24,
        categories=[CATEGORY_VULNERABILITY, CATEGORY_RED_TEAM],
        connectors=[ConnectorConfig(name="fake", type="fake", url="x")],
        prefilter={},  # empty -> everything passes to the LLM
        llm=LLMConfig(semantic_dedup=False),
        database=str(tmp_path / "seen.db"),
        ntfy=NtfyConfig(topic="t"),
    )


def _article(url, title="t", summary="s"):
    return Article(
        source="fake",
        title=title,
        url=url,
        summary=summary,
        published=datetime.now(timezone.utc),
    )


def _cls(category, key, cve=None, relevance=None):
    return Classification(
        category=category,
        canonical_key=key,
        one_line="x",
        cve_ids=list(cve or []),
        relevance=relevance,
    )


def _patch_connectors(monkeypatch, articles):
    class FakeConnector:
        def fetch(self, since):
            return articles

    monkeypatch.setattr(
        pipeline, "build_connectors", lambda cfgs, **kwargs: [FakeConnector()]
    )


def test_only_interesting_new_items_reported(tmp_path, monkeypatch):
    articles = [
        _article("https://n/1", "vuln one"),
        _article("https://n/2", "red team tool"),
        _article("https://n/3", "politics blah"),
    ]
    _patch_connectors(monkeypatch, articles)
    llm = FakeLLM(
        classifications={
            "https://n/1": _cls(CATEGORY_VULNERABILITY, "a:b:rce", ["CVE-2025-1"]),
            "https://n/2": _cls(CATEGORY_RED_TEAM, "sliver:c2:beacon"),
            "https://n/3": _cls(CATEGORY_OTHER, ""),
        }
    )
    config = _config(tmp_path)
    db = Database(config.database)

    stats = pipeline.run(config, db, llm, dry_run=False)

    assert stats.new_items == 2  # the "other" item dropped
    assert stats.report.count == 2
    assert llm.summarize_calls == 2  # only new items get summarized
    db.close()


def test_second_run_dedupes(tmp_path, monkeypatch):
    articles = [_article("https://n/1", "vuln one")]
    _patch_connectors(monkeypatch, articles)
    llm = FakeLLM(
        classifications={"https://n/1": _cls(CATEGORY_VULNERABILITY, "a:b:rce")}
    )
    config = _config(tmp_path)

    db = Database(config.database)
    first = pipeline.run(config, db, llm, dry_run=False)
    db.close()
    assert first.new_items == 1

    # Same article, a fresh DB connection to the same file.
    db2 = Database(config.database)
    second = pipeline.run(config, db2, llm, dry_run=False)
    db2.close()
    assert second.new_items == 0
    assert second.duplicates == 1


def test_dry_run_does_not_persist(tmp_path, monkeypatch):
    articles = [_article("https://n/1", "vuln one")]
    _patch_connectors(monkeypatch, articles)
    llm = FakeLLM(
        classifications={"https://n/1": _cls(CATEGORY_VULNERABILITY, "a:b:rce")}
    )
    config = _config(tmp_path)

    db = Database(config.database)
    pipeline.run(config, db, llm, dry_run=True)
    # Nothing persisted -> a real run afterwards still sees it as new.
    second = pipeline.run(config, db, llm, dry_run=False)
    assert second.new_items == 1
    db.close()


def test_prefilter_gates_llm(tmp_path, monkeypatch):
    articles = [_article("https://n/1", "cooking recipe", "no security here")]
    _patch_connectors(monkeypatch, articles)
    llm = FakeLLM(classifications={})  # would KeyError if classify were called
    config = _config(tmp_path)
    config.prefilter = {"vulnerability": ["exploit", "cve-"]}

    db = Database(config.database)
    stats = pipeline.run(config, db, llm, dry_run=True)
    assert stats.prefiltered == 0
    assert stats.new_items == 0
    db.close()


def test_bypass_prefilter_reaches_llm(tmp_path, monkeypatch):
    # Article has no prefilter keyword, but its source is a bypass feed, so it must
    # still reach the classifier (the red-team-research use case).
    articles = [_article("https://n/1", "Abusing AD CS ESC13", "no keywords here")]
    _patch_connectors(monkeypatch, articles)
    llm = FakeLLM(
        classifications={"https://n/1": _cls(CATEGORY_RED_TEAM, "adcs:esc13:abuse")}
    )
    config = _config(tmp_path)
    config.prefilter = {"vulnerability": ["exploit", "cve-"]}  # would drop the article
    config.connectors = [
        ConnectorConfig(name="fake", type="fake", url="x", bypass_prefilter=True)
    ]

    db = Database(config.database)
    stats = pipeline.run(config, db, llm, dry_run=True)
    assert stats.prefiltered == 1
    assert stats.new_items == 1
    db.close()


def test_min_relevance_filters_low_items(tmp_path, monkeypatch):
    # A high-relevance Windows flaw and a low-relevance no-name plugin flaw.
    articles = [
        _article("https://n/1", "Windows RCE"),
        _article("https://n/2", "Obscure CMS plugin flaw"),
    ]
    _patch_connectors(monkeypatch, articles)
    llm = FakeLLM(
        classifications={
            "https://n/1": _cls(CATEGORY_VULNERABILITY, "microsoft:windows:rce", relevance=5),
            "https://n/2": _cls(CATEGORY_VULNERABILITY, "noname:plugin:xss", relevance=1),
        }
    )
    config = _config(tmp_path)
    config.min_relevance = 3

    db = Database(config.database)
    stats = pipeline.run(config, db, llm, dry_run=True)

    assert stats.classified_interesting == 2
    assert stats.low_relevance == 1  # the plugin flaw dropped
    assert stats.new_items == 1
    assert stats.items[0].canonical_key == "microsoft:windows:rce"
    db.close()


def test_unscored_relevance_fails_open(tmp_path, monkeypatch):
    # relevance=None (e.g. the LLM didn't score it) must never be filtered.
    articles = [_article("https://n/1", "some flaw")]
    _patch_connectors(monkeypatch, articles)
    llm = FakeLLM(
        classifications={"https://n/1": _cls(CATEGORY_VULNERABILITY, "a:b:rce")}
    )
    config = _config(tmp_path)
    config.min_relevance = 5

    db = Database(config.database)
    stats = pipeline.run(config, db, llm, dry_run=True)
    assert stats.low_relevance == 0
    assert stats.new_items == 1
    db.close()


def test_multiple_connectors_are_aggregated(tmp_path, monkeypatch):
    class FakeConnector:
        def __init__(self, arts):
            self._arts = arts

        def fetch(self, since):
            return self._arts

    conns = [
        FakeConnector([_article("https://n/1", "vuln one")]),
        FakeConnector([_article("https://n/2", "red team tool")]),
    ]
    monkeypatch.setattr(pipeline, "build_connectors", lambda cfgs, **kwargs: conns)
    llm = FakeLLM(
        classifications={
            "https://n/1": _cls(CATEGORY_VULNERABILITY, "a:b:rce"),
            "https://n/2": _cls(CATEGORY_RED_TEAM, "sliver:c2:beacon"),
        }
    )
    config = _config(tmp_path)
    db = Database(config.database)
    stats = pipeline.run(config, db, llm, dry_run=True)
    assert stats.in_window == 2
    assert stats.new_items == 2
    db.close()
