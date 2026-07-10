"""SQLite persistence for the dedup store.

Holds one row per already-reported item. Kept small and queryable; the daily
GitHub Actions workflow commits the file back so state survives between runs.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .logging_setup import get_logger
from .models import SeenRecord, Vulnerability

log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS seen (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    category      TEXT NOT NULL,
    vendor        TEXT,
    product       TEXT,
    vuln_class    TEXT,
    canonical_key TEXT NOT NULL,
    cve_ids       TEXT NOT NULL DEFAULT '[]',
    description   TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT '',
    url           TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_seen_key ON seen(canonical_key);
CREATE INDEX IF NOT EXISTS idx_seen_url ON seen(url);
CREATE INDEX IF NOT EXISTS idx_seen_time ON seen(first_seen_at);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- lookups ---------------------------------------------------------------

    def url_seen(self, url: str) -> bool:
        cur = self._conn.execute("SELECT 1 FROM seen WHERE url = ? LIMIT 1", (url,))
        return cur.fetchone() is not None

    def find_by_cve(self, cve_ids: list[str]) -> Optional[SeenRecord]:
        for cve in cve_ids:
            for row in self._conn.execute("SELECT * FROM seen"):
                if cve.upper() in _load_cves(row["cve_ids"]):
                    return _row_to_record(row)
        return None

    def find_by_canonical_key(self, key: str) -> Optional[SeenRecord]:
        if not key:
            return None
        cur = self._conn.execute(
            "SELECT * FROM seen WHERE canonical_key = ? LIMIT 1", (key,)
        )
        row = cur.fetchone()
        return _row_to_record(row) if row else None

    def recent_records(self, window_days: int) -> list[SeenRecord]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()
        cur = self._conn.execute(
            "SELECT * FROM seen WHERE first_seen_at >= ? ORDER BY first_seen_at DESC",
            (cutoff,),
        )
        return [_row_to_record(r) for r in cur.fetchall()]

    def latest(self, limit: int = 100) -> list[SeenRecord]:
        """The most recently reported records, newest first (for the Atom feed)."""
        cur = self._conn.execute(
            "SELECT * FROM seen ORDER BY first_seen_at DESC, id DESC LIMIT ?",
            (limit,),
        )
        return [_row_to_record(r) for r in cur.fetchall()]

    def get(self, record_id: int) -> Optional[SeenRecord]:
        cur = self._conn.execute("SELECT * FROM seen WHERE id = ?", (record_id,))
        row = cur.fetchone()
        return _row_to_record(row) if row else None

    # -- mutations -------------------------------------------------------------

    def insert(self, vuln: Vulnerability) -> int:
        c = vuln.classification
        cur = self._conn.execute(
            """
            INSERT INTO seen (category, vendor, product, vuln_class, canonical_key,
                              cve_ids, description, title, source, url, first_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                c.category,
                c.vendor,
                c.product,
                c.vuln_class,
                c.canonical_key,
                json.dumps([x.upper() for x in c.cve_ids]),
                vuln.summary or c.one_line,
                vuln.article.title,
                vuln.article.source,
                vuln.primary_url,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def add_cves(self, record_id: int, cve_ids: list[str]) -> None:
        """Backfill CVEs onto an existing record (a zero-day that got a CVE)."""
        if not cve_ids:
            return
        row = self._conn.execute(
            "SELECT cve_ids FROM seen WHERE id = ?", (record_id,)
        ).fetchone()
        if row is None:
            return
        existing = _load_cves(row["cve_ids"])
        merged = sorted(existing | {c.upper() for c in cve_ids})
        if merged != sorted(existing):
            self._conn.execute(
                "UPDATE seen SET cve_ids = ? WHERE id = ?",
                (json.dumps(merged), record_id),
            )
            self._conn.commit()
            log.info("[dedup] backfilled CVEs %s onto record #%d", cve_ids, record_id)


def _load_cves(raw: str) -> set[str]:
    try:
        return {str(x).upper() for x in json.loads(raw)}
    except (json.JSONDecodeError, TypeError):
        return set()


def _row_to_record(row: sqlite3.Row) -> SeenRecord:
    return SeenRecord(
        id=row["id"],
        category=row["category"],
        vendor=row["vendor"],
        product=row["product"],
        vuln_class=row["vuln_class"],
        canonical_key=row["canonical_key"],
        cve_ids=sorted(_load_cves(row["cve_ids"])),
        description=row["description"],
        title=row["title"],
        source=row["source"],
        url=row["url"],
        first_seen_at=datetime.fromisoformat(row["first_seen_at"]),
    )
