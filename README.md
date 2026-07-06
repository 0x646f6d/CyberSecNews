# CyberSecNews

A daily cybersecurity news aggregator. It reads a handful of security news
sources once a day and sends you one tidy report via [ntfy.sh](https://ntfy.sh).

## What it does

- Keeps **only** two things: **zero-/n-day vulnerabilities** and **red-team /
  offensive tradecraft** (C2, lateral movement, EDR evasion, tooling). Everything
  else is dropped.
- **Deduplicates** — each vulnerability is reported once, even if it resurfaces
  days later (and even when it has no CVE yet).
- **Summarizes** each new item with a small LLM (Claude Haiku).
- Sends a single **structured English report** to your phone via ntfy.

## Quick start

```bash
# 1. Install (the sgmllib3k line is only needed if the normal install fails)
SETUPTOOLS_USE_DISTUTILS=stdlib pip install sgmllib3k --use-pep517
pip install -e ".[dev]"

# 2. Set your secrets
export ANTHROPIC_API_KEY=sk-ant-...
export NTFY_TOPIC=your-secret-topic     # subscribe to it in the ntfy app

# 3. Run
python -m cybersecnews
```

Try it offline first (fetches feeds, prints the report, sends nothing):

```bash
python -m cybersecnews --dry-run --verbose
```

## Deployment

Runs on **GitHub Actions** — no server needed, and **deploy = `git push`**. Add
`ANTHROPIC_API_KEY` and `NTFY_TOPIC` as repository Actions secrets; the daily
workflow (`.github/workflows/daily.yml`) then runs once a day and commits its
dedup database back to the repo.

## More

See [`CLAUDE.md`](CLAUDE.md) for architecture, configuration, adding sources, and
development notes. Run the tests with `python -m pytest -q`.
