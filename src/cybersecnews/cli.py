"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from . import __version__
from .config import Config, ConfigError, load_config
from .db import Database
from .llm.base import LLMClient
from .logging_setup import configure, get_logger
from .notify import NtfyError, send_report
from .pipeline import run

log = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybersecnews",
        description="Daily cybersecurity news aggregator (zero/n-day vulns + red-team).",
    )
    parser.add_argument("--config", help="Path to config YAML.", default=None)
    parser.add_argument(
        "--since",
        type=int,
        default=None,
        help="Override look-back window in hours (default: config value).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch, classify and build the report but do not persist or send. "
        "Prints the report to stdout. Works offline with a heuristic stub if no "
        "ANTHROPIC_API_KEY is set.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable DEBUG logging."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _build_llm(config: Config, dry_run: bool) -> LLMClient:
    """Pick the LLM backend. Falls back to the heuristic stub for offline dry runs."""
    if config.llm.api_key:
        from .llm import build_llm

        return build_llm(config.llm)
    if dry_run:
        log.warning(
            "ANTHROPIC_API_KEY not set — using heuristic stub LLM for dry run "
            "(classifications are approximate)."
        )
        from .llm.stub import HeuristicLLM

        return HeuristicLLM()
    raise ConfigError(
        "ANTHROPIC_API_KEY is not set. Set it in the environment, or use --dry-run "
        "to test offline with the heuristic stub."
    )


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    configure(verbose=args.verbose)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        return 2

    if args.since is not None:
        config.since_hours = args.since

    try:
        llm = _build_llm(config, args.dry_run)
    except ConfigError as exc:
        log.error("%s", exc)
        return 2

    db = Database(config.database)
    try:
        stats = run(config, db, llm, dry_run=args.dry_run)
    finally:
        db.close()

    report = stats.report
    if report is None:  # defensive; run always sets it
        return 1

    if args.dry_run:
        print("\n" + "=" * 70)
        print(f"TITLE: {report.title}")
        if report.click_url:
            print(f"CLICK: {report.click_url}")
        print("=" * 70)
        print(report.body)
        print("=" * 70)
        return 0

    if report.is_empty and not config.ntfy.quiet_heartbeat:
        log.info("no new items and quiet_heartbeat disabled — sending nothing")
        return 0

    try:
        send_report(report, config.ntfy)
    except NtfyError as exc:
        log.error("failed to send report: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
