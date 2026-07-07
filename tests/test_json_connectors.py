"""CISA KEV and GitHub Advisories JSON connectors (offline; http_get monkeypatched)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import cybersecnews.connectors.cisa_kev as kevmod
import cybersecnews.connectors.github_advisories as ghmod
from cybersecnews.connectors import build_connectors
from cybersecnews.connectors.cisa_kev import CisaKevConnector
from cybersecnews.connectors.github_advisories import GitHubAdvisoriesConnector
from cybersecnews.config import ConnectorConfig

NOW = datetime.now(timezone.utc)


# --- CISA KEV -----------------------------------------------------------------


def test_kev_maps_and_filters_by_date(monkeypatch):
    payload = {
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1111",
                "vendorProject": "Acme",
                "product": "Gateway",
                "vulnerabilityName": "Acme Gateway RCE",
                "dateAdded": NOW.strftime("%Y-%m-%d"),
                "shortDescription": "Unauthenticated RCE in the gateway.",
                "requiredAction": "Patch now.",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2000-0001",
                "vendorProject": "Old",
                "product": "Thing",
                "vulnerabilityName": "Ancient bug",
                "dateAdded": "2000-01-01",
                "shortDescription": "old",
                "requiredAction": "n/a",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ],
    }
    monkeypatch.setattr(
        kevmod, "http_get", lambda url, timeout, headers=None: (json.dumps(payload).encode(), {})
    )

    conn = CisaKevConnector("cisa-kev", "https://x/kev.json", timeout=5)
    arts = conn.fetch(since=NOW - timedelta(hours=6))

    assert len(arts) == 1
    a = arts[0]
    assert "CVE-2026-1111" in a.title
    assert a.url == "https://nvd.nist.gov/vuln/detail/CVE-2026-1111"
    assert "actively exploited" in a.summary
    assert "CVE-2026-1111" in a.summary  # so classify extracts it / dedup layer 1
    assert "ransomware" in a.summary.lower()
    assert a.source == "cisa-kev"


def test_kev_fetch_error_returns_empty(monkeypatch):
    def boom(url, timeout, headers=None):
        raise TimeoutError("timed out")

    monkeypatch.setattr(kevmod, "http_get", boom)
    conn = CisaKevConnector("cisa-kev", "https://x/kev.json", timeout=5)
    assert conn.fetch(since=NOW - timedelta(hours=6)) == []


# --- GitHub Advisories --------------------------------------------------------


def _adv(ghsa, cve, severity, when, summary="A vuln"):
    return {
        "ghsa_id": ghsa,
        "cve_id": cve,
        "summary": summary,
        "description": "Details.",
        "severity": severity,
        "html_url": f"https://github.com/advisories/{ghsa}",
        "published_at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "vulnerabilities": [
            {"package": {"ecosystem": "composer", "name": "acme/pkg"}}
        ],
    }


def test_ghsa_filters_severity_and_stops_on_old(monkeypatch):
    page = [
        _adv("GHSA-aaaa", "CVE-2026-2222", "critical", NOW - timedelta(hours=1)),
        _adv("GHSA-bbbb", "CVE-2026-3333", "high", NOW - timedelta(hours=2)),  # dropped
        _adv("GHSA-cccc", "CVE-2000-0001", "critical", NOW - timedelta(days=99)),  # old -> stop
    ]
    calls = {"n": 0}

    def fake_get(url, timeout, headers=None):
        calls["n"] += 1
        return json.dumps(page).encode(), {"Link": '<https://api.github.com/next>; rel="next"'}

    monkeypatch.setattr(ghmod, "http_get", fake_get)

    conn = GitHubAdvisoriesConnector(
        "gh", "https://api.github.com/advisories", timeout=5,
        options={"severities": ["critical"], "max_pages": 3},
    )
    arts = conn.fetch(since=NOW - timedelta(hours=6))

    assert [a.url for a in arts] == ["https://github.com/advisories/GHSA-aaaa"]
    assert "CVE-2026-2222" in arts[0].title
    assert "Severity: critical" in arts[0].summary
    assert "composer/acme/pkg" in arts[0].summary
    assert calls["n"] == 1  # stopped after the old entry, did not follow next link


def test_ghsa_paginates_up_to_max_pages(monkeypatch):
    page1 = [_adv("GHSA-p1", "CVE-2026-0001", "critical", NOW - timedelta(hours=1))]
    page2 = [_adv("GHSA-p2", "CVE-2026-0002", "critical", NOW - timedelta(hours=2))]
    pages = [
        (json.dumps(page1).encode(), {"Link": '<https://api.github.com/p2>; rel="next"'}),
        (json.dumps(page2).encode(), {}),  # no next link -> stop
    ]
    it = iter(pages)
    captured = {}

    def fake_get(url, timeout, headers=None):
        captured["headers"] = headers
        return next(it)

    monkeypatch.setattr(ghmod, "http_get", fake_get)
    monkeypatch.setenv("GITHUB_TOKEN", "secret-tok")

    conn = GitHubAdvisoriesConnector(
        "gh", "https://api.github.com/advisories", timeout=5,
        options={"severities": ["critical"], "max_pages": 3},
    )
    arts = conn.fetch(since=NOW - timedelta(hours=6))

    assert {a.url for a in arts} == {
        "https://github.com/advisories/GHSA-p1",
        "https://github.com/advisories/GHSA-p2",
    }
    assert captured["headers"]["Authorization"] == "Bearer secret-tok"


def test_ghsa_fetch_error_returns_empty(monkeypatch):
    def boom(url, timeout, headers=None):
        raise ConnectionError("nope")

    monkeypatch.setattr(ghmod, "http_get", boom)
    conn = GitHubAdvisoriesConnector("gh", "https://api.github.com/advisories", timeout=5)
    assert conn.fetch(since=NOW - timedelta(hours=6)) == []


# --- registry -----------------------------------------------------------------


def test_registry_builds_json_connectors():
    cfgs = [
        ConnectorConfig(name="cisa-kev", type="cisa_kev", url="https://x/kev.json"),
        ConnectorConfig(
            name="gh", type="github_advisories", url="https://api.github.com/advisories",
            options={"severities": ["critical"]},
        ),
    ]
    conns = build_connectors(cfgs, timeout=9)
    assert isinstance(conns[0], CisaKevConnector)
    assert isinstance(conns[1], GitHubAdvisoriesConnector)
    assert conns[0].timeout == 9
    assert conns[1].severities == {"critical"}
