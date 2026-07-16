"""Anthropic Claude backend (Claude Haiku).

One classify+extract call per prefiltered article, an optional semantic-match
call for dedup, and a summarize call per new item. All calls request strict JSON
(or a bare token) and parse defensively.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from ..config import LLMConfig
from ..logging_setup import get_logger
from ..models import (
    CATEGORY_OTHER,
    CATEGORY_RED_TEAM,
    CATEGORY_VULNERABILITY,
    Article,
    Classification,
    SeenRecord,
)
from .base import LLMClient

log = get_logger(__name__)

_VALID_CATEGORIES = {CATEGORY_VULNERABILITY, CATEGORY_RED_TEAM, CATEGORY_OTHER}

CLASSIFY_SYSTEM = """You are a precise cybersecurity news triage assistant.
You are given a single news article (title + summary). Decide whether it belongs
to one of these categories of interest, and extract structured fields.

Categories:
- "vulnerability": a specific software/hardware security vulnerability, especially
  zero-day or n-day (newly disclosed / actively exploited) flaws. Product bugs,
  CVEs, exploits, patches for specific flaws.
- "red_team": offensive security / red-team tradecraft: C2 frameworks and
  infrastructure, lateral movement, EDR/AV evasion, post-exploitation tooling,
  new offensive techniques and TTPs.
- "other": anything else (policy, breaches without a specific vuln, funding,
  arrests, general commentary, product marketing). These are discarded.

Respond with ONLY a JSON object, no prose, with exactly these keys:
{
  "category": "vulnerability" | "red_team" | "other",
  "is_zero_or_nday": true/false,   // true if a zero-day or freshly disclosed/exploited flaw
  "vendor": string|null,           // e.g. "Ivanti"; for red_team, the tool vendor if any
  "product": string|null,          // e.g. "Connect Secure"; for red_team, the tool/framework
  "vuln_class": string|null,       // e.g. "auth-bypass","rce","sqli"; for red_team a technique like "lateral-movement","c2","edr-evasion"
  "affected_component": string|null,
  "cve_ids": [string],             // e.g. ["CVE-2024-1234"], empty if none (common for zero-days)
  "severity": string|null,         // e.g. "critical","high","CVSS 9.8", or null
  "relevance": integer,            // 1..5, how relevant this item is to a security engineer (see scale below)
  "canonical_key": string,         // lowercase stable identity slug "vendor:product:vuln_class" e.g. "ivanti:connect-secure:auth-bypass". Use best-effort tokens; no spaces.
  "one_line": string               // <= 140 char neutral one-line description
}

Relevance scale (independent of raw CVSS severity — it measures how much a
defender/red-teamer should care, driven mainly by how widely the affected thing
is deployed and how exposed/exploited it is):
- 5: ubiquitous or perimeter/critical infrastructure, or actively exploited in the
     wild. Windows, Linux kernel, major browsers, hypervisors (VMware/ESXi),
     Active Directory, Exchange, and internet-facing enterprise gear — VPNs,
     firewalls, gateways (Ivanti, Fortinet, Palo Alto, Citrix, Cisco). Also any
     flaw with confirmed in-the-wild exploitation.
- 4: widely deployed software / popular frameworks / common server software with a
     large install base (e.g. WordPress/Drupal core, OpenSSL, popular libraries,
     mainstream databases).
- 3: moderately used products; notable but not everywhere.
- 2: niche or less-common products; limited install base.
- 1: obscure / no-name products, or minor third-party plugins/extensions/themes
     with a tiny install base (e.g. an unknown WordPress plugin).
For red_team items, rate how novel/impactful the tradecraft is (default 3 if
unclear). Bump the score up when a flaw is remotely and unauthenticated
exploitable, or exploited in the wild. If genuinely unsure, use 3.

Do not invent CVE numbers. If unsure, prefer "other"."""

MATCH_SYSTEM = """You decide whether a NEW security item describes the SAME
underlying vulnerability or offensive technique as one already reported. Two
articles about the same flaw/technique (even with different wording, or one with
a CVE and one without) are the SAME. Different flaws in the same product are
DIFFERENT.

You are given the new item and a numbered list of already-reported items.
Respond with ONLY a JSON object: {"match_id": <id or null>}
where <id> is the id of the matching already-reported item, or null if the new
item is genuinely new."""

SUMMARIZE_SYSTEM = """You are a cybersecurity analyst writing a terse English
briefing entry for a security engineer. Given one article, write 2-4 sentences
covering: affected software/technique, what the vulnerability or technique is,
severity and whether it is exploited in the wild, and the recommended action
(patch/mitigation) if applicable. No preamble, no markdown headers, plain text."""


class AnthropicClient(LLMClient):
    def __init__(self, config: LLMConfig) -> None:
        if not config.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set; cannot use the Anthropic LLM backend."
            )
        # Imported lazily so the package can be imported without the SDK present
        # (e.g. for --dry-run with a stub, or in tests).
        from anthropic import Anthropic

        self._client = Anthropic(api_key=config.api_key)
        self._model = config.model
        self._max_tokens = config.max_tokens

    # -- public API ------------------------------------------------------------

    def classify(self, article: Article) -> Classification:
        user = f"Title: {article.title}\n\nSummary: {article.summary}"
        data = self._json_call(CLASSIFY_SYSTEM, user)
        if data is None:
            # On failure, keep the item (fail open) but mark other so it is
            # dropped only if nothing else matches — safer is to drop; we drop.
            log.warning("[llm] classify failed for %s; dropping", article.url)
            return Classification(
                category=CATEGORY_OTHER, canonical_key="", one_line=article.title
            )
        return _parse_classification(data, article)

    def match_existing(
        self,
        article: Article,
        classification: Classification,
        candidates: list[SeenRecord],
    ) -> Optional[int]:
        if not candidates:
            return None
        lines = []
        for rec in candidates:
            cves = ",".join(rec.cve_ids) if rec.cve_ids else "none"
            lines.append(
                f"[{rec.id}] key={rec.canonical_key} cves={cves} :: {rec.title} — {rec.description}"
            )
        candidate_block = "\n".join(lines)
        user = (
            f"NEW ITEM:\n"
            f"key={classification.canonical_key} "
            f"cves={','.join(classification.cve_ids) or 'none'}\n"
            f"title: {article.title}\n"
            f"summary: {article.summary}\n\n"
            f"ALREADY-REPORTED ITEMS:\n{candidate_block}"
        )
        data = self._json_call(MATCH_SYSTEM, user)
        if not data:
            return None
        match_id = data.get("match_id")
        if isinstance(match_id, bool):  # guard against true/false
            return None
        if isinstance(match_id, int):
            return match_id
        if isinstance(match_id, str) and match_id.strip().isdigit():
            return int(match_id.strip())
        return None

    def summarize(self, article: Article, classification: Classification) -> str:
        user = f"Title: {article.title}\n\nSummary: {article.summary}"
        text = self._text_call(SUMMARIZE_SYSTEM, user)
        return text.strip() if text else classification.one_line

    # -- low-level helpers -----------------------------------------------------

    def _text_call(self, system: str, user: str) -> Optional[str]:
        try:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as exc:
            log.error("[llm] API call failed: %s", exc)
            return None
        parts = [b.text for b in resp.content if getattr(b, "type", None) == "text"]
        return "".join(parts)

    def _json_call(self, system: str, user: str) -> Optional[dict[str, Any]]:
        text = self._text_call(system, user)
        if not text:
            return None
        return _extract_json(text)


def _extract_json(text: str) -> Optional[dict[str, Any]]:
    """Parse a JSON object out of an LLM response, tolerating stray prose/fences."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Strip markdown code fences if present.
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass
    # Fall back to the first balanced-looking object.
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _parse_classification(data: dict[str, Any], article: Article) -> Classification:
    category = str(data.get("category", CATEGORY_OTHER)).strip().lower()
    if category not in _VALID_CATEGORIES:
        category = CATEGORY_OTHER

    cve_ids = data.get("cve_ids") or []
    if not isinstance(cve_ids, list):
        cve_ids = [cve_ids]
    cve_ids = [_normalize_cve(str(c)) for c in cve_ids if c]
    cve_ids = [c for c in cve_ids if c]

    canonical_key = str(data.get("canonical_key") or "").strip().lower()
    if not canonical_key:
        canonical_key = _fallback_key(data, article)

    return Classification(
        category=category,
        canonical_key=canonical_key,
        one_line=str(data.get("one_line") or article.title)[:200],
        is_zero_or_nday=bool(data.get("is_zero_or_nday", False)),
        vendor=_opt_str(data.get("vendor")),
        product=_opt_str(data.get("product")),
        vuln_class=_opt_str(data.get("vuln_class")),
        affected_component=_opt_str(data.get("affected_component")),
        cve_ids=cve_ids,
        severity=_opt_str(data.get("severity")),
        relevance=_opt_relevance(data.get("relevance")),
    )


def _opt_relevance(value: Any) -> Optional[int]:
    """Parse the 1..5 relevance score, clamping to range; None if unparseable."""
    if value is None:
        return None
    try:
        score = int(value)
    except (TypeError, ValueError):
        return None
    return max(1, min(5, score))


def _normalize_cve(value: str) -> str:
    m = re.search(r"CVE-\d{4}-\d{4,}", value, re.IGNORECASE)
    return m.group(0).upper() if m else ""


def _opt_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _fallback_key(data: dict[str, Any], article: Article) -> str:
    """Build a slug when the model omitted canonical_key."""
    parts = [
        _slug(data.get("vendor")),
        _slug(data.get("product")),
        _slug(data.get("vuln_class")),
    ]
    parts = [p for p in parts if p]
    if parts:
        return ":".join(parts)
    return _slug(article.title) or "unknown"


def _slug(value: Any) -> str:
    if not value:
        return ""
    text = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return text
