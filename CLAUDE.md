# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository. Read this first
when starting a fresh session — it captures what the project is, how it's built,
and the non-obvious decisions and environment gotchas that aren't visible from a
quick skim.

## What this is

**CyberSecNews** is a Python service that aggregates cybersecurity news on a short
interval (**every 8h** via the workflow), keeps **only two categories** of
interest, deduplicates against everything
it has already reported, summarizes each new item with a small LLM, and sends one
structured English report via **[ntfy.sh](https://ntfy.sh)**.

The two categories (everything else — politics, breaches without a specific flaw,
marketing — is discarded):
1. **Zero-/n-day vulnerabilities** (the primary interest).
2. **Red-team / offensive tradecraft**: C2 infrastructure, lateral movement,
   EDR/AV evasion, offensive tooling & TTPs.

Design intent lives in `README.md` (user-facing) and the plan file referenced in
commit history; this file is the developer/agent orientation.

## Pipeline

```
fetch (RSS connectors) → 24h window filter → cheap keyword prefilter
→ LLM classify+extract (category + identity fields)
→ 3-layer dedup against DB → LLM summarize (new items only)
→ store in DB → build report → send via ntfy → (workflow) commit DB back
```

Orchestrated by `src/cybersecnews/pipeline.py::run()`.

## Module map (`src/cybersecnews/`)

| File | Responsibility |
|------|----------------|
| `cli.py` | Entry point. Arg parsing (`--dry-run`, `--since`, `--config`, `--verbose`), builds config/LLM/DB, calls `pipeline.run`, prints (dry-run) or sends the report. |
| `__main__.py` | Enables `python -m cybersecnews`. |
| `config.py` | Loads YAML (`config.yaml` → falls back to `config.example.yaml`) + env secrets; validates. Dataclasses `Config`, `ConnectorConfig`, `LLMConfig`, `NtfyConfig`, `FeedConfig`. |
| `models.py` | Core dataclasses: `Article`, `Classification`, `Vulnerability`, `SeenRecord`, and the `CATEGORY_*` constants. |
| `logging_setup.py` | stdout logging, grep-friendly per-stage lines. `configure(verbose)`. |
| `connectors/base.py` | `Connector` ABC: `fetch(since) -> list[Article]`. |
| `connectors/rss.py` | Generic `feedparser` RSS connector (drives all feed sources via config). Browser User-Agent to dodge 403s; per-feed timeout; resilient to parse/network errors. |
| `connectors/http.py` | Shared `http_get()` (urllib + UA + timeout + optional bearer) for the JSON-API connectors. |
| `connectors/cisa_kev.py` | CISA KEV JSON connector (`cisa_kev` type). Actively-exploited CVEs → `Article` (CVE kept in text for dedup layer 1). |
| `connectors/github_advisories.py` | GitHub Security Advisories connector (`github_advisories` type). Paginated, severity-filtered (default critical), optional `GITHUB_TOKEN`. |
| `connectors/__init__.py` | Type registry (`rss`, `cisa_kev`, `github_advisories`) + `build_connectors()`. |
| `llm/base.py` | `LLMClient` protocol: `classify`, `match_existing`, `summarize`. |
| `llm/anthropic_client.py` | Claude Haiku impl. Prompts + defensive JSON extraction. |
| `llm/stub.py` | `HeuristicLLM` — offline keyword-based stub for `--dry-run`/tests. **Approximate, not a substitute for the real model.** |
| `llm/__init__.py` | `build_llm(config)` factory. |
| `db.py` | SQLite store (`Database`): the `seen` table, lookups, `insert`, `add_cves` (backfill). |
| `dedup.py` | `DedupEngine` — the 3-layer decision + within-run `_pending` tracking. |
| `report.py` | `build_report()` → a `Report` of one `Message` **per item** (empty run → one heartbeat message). Per-item keeps each ntfy notification short enough to display fully on the Android app, which crops long bodies. |
| `notify.py` | `send_report()` → POSTs each `Report.message` to ntfy as its own notification (Title/Priority/Markdown/per-category Tags). No `Click` header — a tap opens the message in the ntfy app, not an article's website. |
| `feed.py` | `build_atom_feed()` / `write_atom_feed()` → render the persisted store (`db.latest`) as a static Atom 1.0 `atom.xml`. A read/unread-capable reading surface (any feed reader tracks read/unread per entry) alongside the ntfy ping. Stable per-item `<id>` (`urn:cybersecnews:item:{db_id}`) preserves reader state across regenerations. Gated by `config.feed.enabled`; written from `cli.py` after a real run, published by the workflow. |
| `pipeline.py` | Wires it all together; emits `RunStats`. |

Tests in `tests/` (see Testing below).

## Key design decisions — preserve these

- **Vulnerability identity is CVE-independent.** Zero-days frequently have *no CVE
  yet*, so identity is a semantic `canonical_key` (`vendor:product:vuln_class`
  slug from the classify call). CVE is an *optional* signal, never the primary
  key. Do not "simplify" dedup down to CVE matching — that breaks the primary use
  case. See `dedup.py` + `models.Classification.canonical_key`.
- **3-layer dedup** (`dedup.py::DedupEngine.check`), cheapest first, stop at first
  match:
  1. URL already seen, or any extracted CVE already stored (no LLM);
  2. `canonical_key` matches an existing row (no LLM) — carries CVE-less zero-days;
  3. one bounded LLM `match_existing` call vs the recent window
     (`dedup_window_days`, default 45) — paraphrase/re-mention catch.
- **CVE backfill:** when a later article about a known zero-day finally carries a
  CVE, `db.add_cves` merges it onto the stored record so Layer 1 catches it next
  time. Triggered from `pipeline.run` on a duplicate with `matched_record_id`.
- **Within-run dedup:** `DedupEngine._pending` holds items accepted earlier in the
  same run (negative ids) so two articles about the same fresh vuln collapse to
  one report entry.
- **Two-stage filtering:** cheap keyword prefilter (`pipeline._passes_prefilter`,
  terms from `config.prefilter`) gates the LLM to keep token cost low; the LLM
  makes the *final* category decision. Empty prefilter = everything passes.
  Connectors with `bypass_prefilter: true` skip the keyword gate entirely and go
  straight to the LLM — used for curated, low-volume, high-signal feeds (fast vuln
  advisories + red-team research blogs) whose posts rarely contain the keywords
  verbatim (e.g. "Abusing AD CS ESC13"). High-volume general news outlets keep the
  prefilter.
- **Concurrent fetching:** connectors are fetched in parallel
  (`ThreadPoolExecutor`, `fetch_workers`), each with a per-feed network timeout
  (`fetch_timeout`), so one slow/hanging source can't stall the run. Each
  connector still swallows its own errors and returns `[]`.
- **Store-after-report ordering:** new items are persisted only after the report is
  built (and never on `--dry-run`), so a crash mid-run doesn't silently swallow an
  unreported item.
- **Relevance scoring.** The classify call also returns a `relevance` score
  (`Classification.relevance`, 1..5) — how much a defender should care, driven by
  deployment breadth + exposure/exploitation (Windows/perimeter/actively-exploited
  = 5; obscure no-name web-CMS plugin = 1). It is *independent* of raw CVSS
  `severity`. The pipeline drops items below `config.min_relevance` (default 1 =
  keep everything) *after* classify but *before* dedup/report; `relevance=None`
  (unscored — older records / stub) fails open. The report shows `relevance N/5`
  and orders items most-relevant-first within each category. Not persisted to the
  DB (send-path only).
- **Persistence = `data/seen.db` committed back by the workflow.** This SQLite file
  is the "already reported" memory and is **intentionally NOT git-ignored**
  (see `.gitignore` note). The daily workflow commits it after each run so state
  survives ephemeral runners.
- **Pluggable by design:**
  - New source → subclass `Connector`, register its `type` in
    `connectors/__init__.py`, add a `config.yaml` entry. Nothing else changes.
  - New LLM backend (e.g. Ollama) → implement the `LLMClient` protocol, wire into
    `llm/build_llm`. The pipeline depends only on the protocol.

## Commands

```bash
# Install (editable, with dev extras). NOTE the sgmllib3k workaround below.
pip install -e ".[dev]"

# Full run: classify with Claude, dedup, store, send to ntfy.
export ANTHROPIC_API_KEY=sk-ant-...   # required for a real run
export NTFY_TOPIC=your-topic          # required to send
python -m cybersecnews

# Dry run: fetch + classify + build report, print it, persist/send nothing.
# Works offline (heuristic stub LLM) when ANTHROPIC_API_KEY is unset.
python -m cybersecnews --dry-run --verbose

# Look back further than the default 24h:
python -m cybersecnews --since 48 --dry-run

# Tests (no network / API key needed — LLM is faked, HTTP is mocked).
python -m pytest -q
```

## Configuration & secrets

- Non-secret settings live in `config.yaml` (falls back to `config.example.yaml`).
  Key knobs: `connectors[]` (feeds; `enabled: false` to disable,
  `bypass_prefilter: true` to skip the keyword gate), `prefilter` (vuln + red-team
  keyword lists), `categories`, `llm.model`, `llm.semantic_dedup` (toggle layer 3),
  `dedup_window_days`, `min_relevance` (1..5 gate; 1 = report everything),
  `since_hours`, `fetch_timeout`, `fetch_workers`, `ntfy.quiet_heartbeat`. Sources are two-track: high-volume general news outlets
  (prefilter-gated) plus curated fast vuln feeds + red-team blogs (bypass; the
  red-team set is derived from Bad Sector Labs' `blogs.txt`). Two of the fast
  sources are **JSON APIs, not RSS** — `cisa_kev` (actively-exploited CVEs) and
  `github_advisories` (critical GHSA) — each its own connector type; per-connector
  `options:` carries their params (GHSA `severities`/`max_pages`/`token_env`).
- Secrets come from the environment (never commit them). `config.yaml` is
  git-ignored; `config.example.yaml` is the committed template.

| Env var | Required | Purpose |
|---------|----------|---------|
| `ANTHROPIC_API_KEY` | yes (not for `--dry-run`) | Claude Haiku access |
| `NTFY_TOPIC` | yes (to send) | ntfy.sh topic to publish to |
| `NTFY_TOKEN` | no | Bearer token for access-protected topics |
| `GITHUB_TOKEN` | no | Raises GitHub Advisories API limit 60→5000/h. Auto-provided in Actions. |

## Deployment

Hosting is **GitHub Actions** — no server; **deploy = `git push`**.

- `.github/workflows/daily.yml`: cron `0 */8 * * *` (every 8h; frequency is the
  main zero-/n-day latency lever) + `workflow_dispatch`. Installs, runs
  `python -m cybersecnews`, then commits `data/seen.db` back (`[skip ci]`).
  Needs `permissions: contents: write` (already set). Secrets are repo Actions
  secrets: `ANTHROPIC_API_KEY`, `NTFY_TOPIC`, optional `NTFY_TOKEN`.
- `.github/workflows/ci.yml`: runs `pytest` on push / PR.
- First-time setup: add the secrets, then trigger `daily.yml` manually from the
  Actions tab to confirm a report arrives and the DB commit lands.

## LLM / model

- The model is **Claude Haiku `claude-haiku-4-5-20251001`** (`llm/anthropic_client.py`,
  default in `config.py`). It's cheap at this volume and needs no host.
- **When touching any LLM/prompt/model code, load the `claude-api` skill first**
  (model ids, params, tool use, token/cost). Don't hand-edit model ids from memory.
- Prompts live as module constants in `anthropic_client.py`
  (`CLASSIFY_SYSTEM`, `MATCH_SYSTEM`, `SUMMARIZE_SYSTEM`). The classify prompt is
  what enforces the "only these two categories" precision — edit it carefully and
  re-check against `tests/` expectations.

## Conventions

- Python **3.10+**, `src/` layout (`pyproject.toml`, packages under `src/`).
- Plain **dataclasses** for models; no pydantic.
- **stdlib `logging`** only, to stdout. Keep the per-stage, one-line-per-source
  style (`[source] fetched N / in-window M`, `[dedup] duplicate (...)`, `[new] ...`)
  — it's the primary debugging tool for "why did no news come in?".
- **Connectors and LLM calls must be defensive**: a single source or API error
  logs and returns empty/partial rather than crashing the whole run.
- Prefer extending config/registries over hardcoding new sources or providers.

## Testing

`python -m pytest -q` — 20 tests, all offline:

| File | Covers |
|------|--------|
| `tests/conftest.py` | `FakeLLM`, `make_article`/`make_vuln` builders. |
| `tests/test_rss.py` | RSS parse, 24h window filter, HTML cleaning, bad-feed resilience. |
| `tests/test_dedup.py` | All 3 layers incl. **CVE-less zero-day via canonical_key**, semantic match, within-run pending, CVE backfill. |
| `tests/test_report.py` | Two sections, counts, per-item source links, zero-day tag, empty case, multi-source. |
| `tests/test_pipeline.py` | End-to-end: only interesting/new items reported, second-run dedup, dry-run non-persistence, prefilter gating. |
| `tests/test_notify.py` | ntfy POST headers + error handling (mocked HTTP via `responses`). |

Run `pytest` before committing. Tests need no network or API key.

## Environment gotchas

- **`sgmllib3k` build failure** (a `feedparser` dependency). In some sandboxed/
  Debian-patched environments its legacy `setup.py` fails with
  `AttributeError: install_layout`. Workaround:
  ```bash
  SETUPTOOLS_USE_DISTUTILS=stdlib pip install sgmllib3k --use-pep517
  ```
  then re-run `pip install -e ".[dev]"`. Standard GitHub `ubuntu-latest` runners
  build it fine, so the workflow needs no special handling.
- **Feeds are blocked in this sandbox.** The agent proxy returns
  `403 Forbidden` on the CONNECT tunnel for heise/golem/etc., so a live
  `--dry-run` here fetches 0 articles (handled + logged, not a code bug). The
  feeds work on real GitHub runners; verify live behavior via `workflow_dispatch`.
- **Offline dry-run** uses `HeuristicLLM` (keyword heuristics) — good enough to
  exercise fetch→prefilter→classify→dedup→report plumbing, but its
  classifications are crude (it may miscategorize; the real Haiku model is
  accurate). Don't judge classification quality from the stub.

## Working agreement

- Develop on branch **`claude/cybersecurity-news-aggregator-2ujobm`**.
- Never commit secrets or a real `config.yaml`.
- Run `pytest` before committing; keep it green.
- `data/seen.db` is committed state — don't delete it or add it to `.gitignore`.

## Roadmap / out of scope (v1)

- **X/Twitter connector** — no free feed; the `Connector` interface is ready.
- **Local Ollama LLM backend** — the `LLMClient` protocol is ready.
- **Self-hosted systemd deployment** — GitHub Actions is the chosen path.
