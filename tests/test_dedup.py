"""Dedup layers, including the CVE-independent path that matters for zero-days."""

from __future__ import annotations

from cybersecnews.db import Database
from cybersecnews.dedup import DedupEngine
from conftest import FakeLLM, make_vuln


def _engine(tmp_path, llm=None, use_semantic=False):
    db = Database(tmp_path / "seen.db")
    return db, DedupEngine(db=db, llm=llm or FakeLLM(), use_semantic=use_semantic)


def test_new_item_is_not_duplicate(tmp_path):
    db, engine = _engine(tmp_path)
    result = engine.check(make_vuln(url="https://x/1", canonical_key="acme:w:rce"))
    assert result.is_duplicate is False


def test_layer1_cve_match(tmp_path):
    db, engine = _engine(tmp_path)
    db.insert(make_vuln(url="https://x/1", canonical_key="k1", cve_ids=["CVE-2024-1"]))
    # Different URL and different canonical_key, same CVE -> duplicate.
    dup = make_vuln(url="https://x/2", canonical_key="k2", cve_ids=["CVE-2024-1"])
    result = engine.check(dup)
    assert result.is_duplicate
    assert result.reason.startswith("layer1:cve")


def test_layer2_canonical_key_matches_cveless_zeroday(tmp_path):
    """A zero-day with no CVE must still dedup across articles via canonical_key."""
    db, engine = _engine(tmp_path)
    db.insert(
        make_vuln(url="https://x/1", canonical_key="ivanti:cs:auth-bypass", cve_ids=[])
    )
    dup = make_vuln(
        url="https://x/2", canonical_key="ivanti:cs:auth-bypass", cve_ids=[]
    )
    result = engine.check(dup)
    assert result.is_duplicate
    assert result.reason.startswith("layer2")


def test_layer3_semantic_match(tmp_path):
    db = Database(tmp_path / "seen.db")
    # Paraphrased key for the same product: layer 2 misses, layer 3 catches it.
    seen = db.insert(
        make_vuln(url="https://x/1", canonical_key="ivanti:connect-secure:rce", cve_ids=[])
    )
    candidate = make_vuln(
        url="https://x/2", canonical_key="ivanti:ics:code-execution", cve_ids=[]
    )
    llm = FakeLLM(semantic_matches={"https://x/2": seen})
    engine = DedupEngine(db=db, llm=llm, use_semantic=True)

    result = engine.check(candidate)
    assert result.is_duplicate
    assert result.reason.startswith("layer3")
    assert result.matched_record_id == seen


def test_within_run_dedup_via_pending(tmp_path):
    db, engine = _engine(tmp_path)
    first = make_vuln(url="https://x/1", canonical_key="dup:key", cve_ids=[])
    assert engine.check(first).is_duplicate is False
    engine.remember(first)  # accepted this run, not yet persisted
    second = make_vuln(url="https://x/2", canonical_key="dup:key", cve_ids=[])
    assert engine.check(second).is_duplicate


def test_cve_backfill(tmp_path):
    db = Database(tmp_path / "seen.db")
    rid = db.insert(make_vuln(url="https://x/1", canonical_key="k", cve_ids=[]))
    db.add_cves(rid, ["CVE-2025-42"])
    assert db.find_by_cve(["CVE-2025-42"]).id == rid


def test_layer3_rejects_unrelated_product(tmp_path):
    """An LLM match between two different products must not swallow the item."""
    db = Database(tmp_path / "seen.db")
    seen = db.insert(
        make_vuln(
            url="https://x/1",
            canonical_key="tensorlake:tensorlake-npm:supply-chain-attack",
            cve_ids=[],
        )
    )
    candidate = make_vuln(
        url="https://x/2", canonical_key="litellm:litellm:supply-chain-attack", cve_ids=[]
    )
    llm = FakeLLM(semantic_matches={"https://x/2": seen})
    engine = DedupEngine(db=db, llm=llm, use_semantic=True)
    assert engine.check(candidate).is_duplicate is False


def test_layer3_rejects_unknown_match_id(tmp_path):
    db = Database(tmp_path / "seen.db")
    db.insert(make_vuln(url="https://x/1", canonical_key="acme:widget:rce", cve_ids=[]))
    candidate = make_vuln(url="https://x/2", canonical_key="acme:widget:sqli", cve_ids=[])
    llm = FakeLLM(semantic_matches={"https://x/2": 9999})  # not a candidate
    engine = DedupEngine(db=db, llm=llm, use_semantic=True)
    assert engine.check(candidate).is_duplicate is False


def test_layer3_fails_open_without_identity(tmp_path):
    """Vague keys (no usable vendor/product) leave the decision to the LLM."""
    db = Database(tmp_path / "seen.db")
    seen = db.insert(make_vuln(url="https://x/1", canonical_key="acme:widget:rce", cve_ids=[]))
    candidate = make_vuln(url="https://x/2", canonical_key="multiple:unknown:rce", cve_ids=[])
    llm = FakeLLM(semantic_matches={"https://x/2": seen})
    engine = DedupEngine(db=db, llm=llm, use_semantic=True)
    assert engine.check(candidate).is_duplicate
