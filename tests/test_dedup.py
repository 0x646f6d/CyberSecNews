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
    seen = db.insert(make_vuln(url="https://x/1", canonical_key="k-old", cve_ids=[]))
    candidate = make_vuln(url="https://x/2", canonical_key="k-new", cve_ids=[])
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
