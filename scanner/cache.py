"""SQLite-backed cache for EPSS and KEV feeds."""

from __future__ import annotations

import csv
import gzip
import io
import json
import sqlite3
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass(slots=True)
class EpssRecord:
    """EPSS data for a CVE."""

    cve_id: str
    score: float
    percentile: float


@dataclass(slots=True)
class KevRecord:
    """KEV data for a CVE."""

    cve_id: str
    vendor_project: str
    product: str
    due_date: str


class FeedCache:
    """Persistent cache for threat intelligence feeds."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS epss (
                    cve_id TEXT PRIMARY KEY,
                    score REAL NOT NULL,
                    percentile REAL NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS kev (
                    cve_id TEXT PRIMARY KEY,
                    vendor_project TEXT NOT NULL,
                    product TEXT NOT NULL,
                    due_date TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    def refresh(self, epss_url: str = EPSS_URL, kev_url: str = KEV_URL) -> None:
        """Refresh local cache from upstream feeds."""
        epss_records = _download_epss(epss_url)
        kev_records = _download_kev(kev_url)
        now = datetime.now(UTC).isoformat()

        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO epss(cve_id, score, percentile, updated_at)
                VALUES(?, ?, ?, ?)
                """,
                [(row.cve_id, row.score, row.percentile, now) for row in epss_records],
            )
            conn.executemany(
                """
                INSERT OR REPLACE INTO kev(cve_id, vendor_project, product, due_date, updated_at)
                VALUES(?, ?, ?, ?, ?)
                """,
                [
                    (row.cve_id, row.vendor_project, row.product, row.due_date, now)
                    for row in kev_records
                ],
            )

    def lookup_epss(self, cve_id: str) -> float | None:
        """Return EPSS score for a CVE if present."""
        with self._connect() as conn:
            row = conn.execute("SELECT score FROM epss WHERE cve_id = ?", (cve_id,)).fetchone()
        if row is None:
            return None
        return float(row[0])

    def is_kev(self, cve_id: str) -> bool:
        """Return True if CVE is in KEV catalog."""
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
        return row is not None


def _download_epss(url: str) -> list[EpssRecord]:
    with urllib.request.urlopen(url, timeout=30) as response:
        compressed = response.read()
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as gz_file:
        content = gz_file.read().decode("utf-8")

    records: list[EpssRecord] = []
    reader = csv.DictReader(content.splitlines())
    for row in reader:
        cve_id = row.get("cve")
        epss = row.get("epss")
        percentile = row.get("percentile")
        if cve_id is None or epss is None or percentile is None:
            continue
        records.append(EpssRecord(cve_id=cve_id, score=float(epss), percentile=float(percentile)))
    return records


def _download_kev(url: str) -> list[KevRecord]:
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read().decode("utf-8")
    payload = json.loads(raw)

    records: list[KevRecord] = []
    for item in payload.get("vulnerabilities", []):
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        records.append(
            KevRecord(
                cve_id=str(cve_id),
                vendor_project=str(item.get("vendorProject", "")),
                product=str(item.get("product", "")),
                due_date=str(item.get("dueDate", "")),
            )
        )
    return records
