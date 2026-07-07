# CyberSecNews

A cybersecurity news aggregator that runs on a short interval (every 4h). It pulls
from a broad set of fast, high-signal sources — authoritative vulnerability/advisory
feeds (CISA KEV, GitHub critical advisories, ZDI, Project Zero, watchTowr, SANS ISC,
vendor research …) plus curated red-team / offensive-tradecraft blogs (derived from
Bad Sector Labs' reading list) —
and keeps **only** the two things you care about —

1. **Zero-/n-day vulnerabilities**, and
2. **Red-team / offensive tradecraft** (C2 infrastructure, lateral movement,
   EDR/AV evasion, offensive tooling & TTPs)

— drops everything else (politics, breaches without a specific flaw, marketing),
removes anything it has already reported before, summarizes each new item with a
small LLM, and sends a single structured English report to your phone via
[ntfy.sh](https://ntfy.sh).

## How it works

```
fetch (RSS connectors, concurrent) → look-back window → cheap keyword prefilter
→ LLM classify+extract (category + identity fields)
→ 3-layer dedup against the DB → LLM summarize (new items only)
→ store → build report → send via ntfy → commit DB back
```

- **Two-stage filtering.** A cheap keyword prefilter drops obvious off-topic
  articles before any LLM call; the LLM then makes the final classification and
  extracts structured fields. Keeps token cost low. Curated high-signal feeds set
  `bypass_prefilter: true` to skip the keyword gate (their posts rarely contain the
  keywords verbatim) and go straight to the LLM.
- **CVE-independent dedup.** Zero-days often have *no CVE yet*, so identity is a
  semantic fingerprint (`vendor:product:vuln_class`), not a CVE. Three layers,
  cheapest first:
  1. URL already seen, or any extracted CVE already stored;
  2. `canonical_key` matches an existing item (this carries CVE-less zero-days);
  3. one bounded LLM call comparing against the recent window (handles
     paraphrasing and re-mentions weeks later).
  When a later article about a known zero-day finally carries a CVE, it is
  back-filled onto the stored record.
- **Traceable logging.** Every stage logs one line per source
  (`fetched → in-window → prefiltered → classified → new → duplicate`), so when
  news *doesn't* come in you can see exactly where it dropped out.

## Setup

Requires Python 3.10+.

```bash
pip install -e ".[dev]"      # dev extras add pytest + responses
cp config.example.yaml config.yaml   # then edit to taste (optional)
```

### Secrets (environment variables)

| Variable            | Required | Purpose                                            |
| ------------------- | -------- | -------------------------------------------------- |
| `ANTHROPIC_API_KEY` | yes\*    | Claude Haiku access for classify/summarize/dedup   |
| `NTFY_TOPIC`        | yes      | The ntfy.sh topic to publish the report to         |
| `NTFY_TOKEN`        | no       | Bearer token if your ntfy topic is access-protected |

\* Not needed for `--dry-run`, which falls back to an offline heuristic stub.

Pick an unguessable topic name (anyone who knows it can read your reports), e.g.
`csn-a8f3k29xqz`, and subscribe to it in the ntfy app or at
`https://ntfy.sh/<topic>`.

## Usage

```bash
# Full run: classify with Claude, dedup, store, and send to ntfy.
export ANTHROPIC_API_KEY=sk-ant-...
export NTFY_TOPIC=csn-a8f3k29xqz
python -m cybersecnews

# Dry run: fetch + classify + build the report, print it, persist/send nothing.
# Works offline (heuristic stub) if ANTHROPIC_API_KEY is unset.
python -m cybersecnews --dry-run --verbose

# Look back further than the default window (e.g. for a first backfill-free test):
python -m cybersecnews --since 48 --dry-run
```

Flags: `--config PATH`, `--since HOURS`, `--dry-run`, `--verbose/-v`.

## Configuration

Everything non-secret lives in `config.yaml` (falls back to
`config.example.yaml`). Notable knobs:

- `connectors` — the RSS sources; disable one with `enabled: false`, or set
  `bypass_prefilter: true` to send its articles straight to the LLM (used for the
  curated advisory + red-team feeds).
- `prefilter` — keyword lists (vuln + red-team) for the cheap gate.
- `categories` — which classified categories to keep.
- `since_hours` — look-back window per run (default 6, overlaps the 4h cron).
- `fetch_timeout` / `fetch_workers` — per-feed timeout and concurrency for fetching.
- `llm.model` — defaults to `claude-haiku-4-5-20251001`.
- `llm.semantic_dedup` — toggle the layer-3 LLM dedup call.
- `dedup_window_days` — how far back layer 3 compares (default 45).
- `ntfy.quiet_heartbeat` — send a "nothing new" message on empty runs, or stay
  silent (default: silent, still logged).

## Adding a new source

Sources are pluggable. For another RSS feed, just add an entry under
`connectors:` in `config.yaml`. For a non-RSS source (e.g. X/Twitter later):

1. Implement a `Connector` subclass with `fetch(since) -> list[Article]`
   (see `src/cybersecnews/connectors/base.py`).
2. Register its `type` in `src/cybersecnews/connectors/__init__.py`.
3. Add a config entry.

Nothing else in the pipeline changes. The LLM backend is similarly pluggable via
the `LLMClient` protocol (`src/cybersecnews/llm/base.py`), so a local Ollama
backend can be dropped in later.

## Deployment (GitHub Actions)

The intended hosting is a scheduled GitHub Actions workflow — no server needed,
and **deploy = `git push`**.

1. Add repository **Secrets** (Settings → Secrets and variables → Actions):
   `ANTHROPIC_API_KEY`, `NTFY_TOPIC`, and optionally `NTFY_TOKEN`.
2. `.github/workflows/daily.yml` runs every 4h (UTC) and on manual dispatch.
   After each run it commits the updated `data/seen.db` back to the repo, so the
   "already reported" memory survives between ephemeral runners.
3. Trigger it manually the first time from the **Actions** tab
   (**Run workflow**) to confirm a report arrives and the DB commit lands.

The dedup database `data/seen.db` is intentionally **not** git-ignored — it *is*
the persisted state.

> Note: the workflow needs `contents: write` permission (already set) so it can
> push the DB commit. The commit is marked `[skip ci]` so it doesn't trigger CI.

## Development

```bash
python -m pytest -q     # 20 tests: rss parsing, dedup layers, report, pipeline, notify
```

Tests use fakes for the LLM and mocked HTTP for ntfy — no network or API key
required.

## Out of scope (for now)

- X/Twitter connector (no free feed; the interface is ready).
- Local Ollama LLM backend (the protocol is ready).
- Self-hosted systemd deployment (GitHub Actions is the chosen path).
