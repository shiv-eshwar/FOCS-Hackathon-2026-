"""Tests for cache and enrichment behavior."""

from pathlib import Path

from scanner.cache import FeedCache
from scanner.enrich import enrich_findings
from scanner.models import Finding


def test_cache_lookup_and_enrich() -> None:
    cache = FeedCache(Path("tests/tmp_cache.sqlite"))
    with cache._connect() as conn:  # noqa: SLF001 - test-only direct setup
        conn.execute(
            "INSERT OR REPLACE INTO epss(cve_id, score, percentile, updated_at) VALUES(?, ?, ?, ?)",
            ("CVE-2023-0001", 0.91, 0.98, "now"),
        )
        conn.execute(
            (
                "INSERT OR REPLACE INTO kev("
                "cve_id, vendor_project, product, due_date, updated_at"
                ") VALUES(?, ?, ?, ?, ?)"
            ),
            ("CVE-2023-0001", "Vendor", "Product", "2026-12-31", "now"),
        )

    findings = [
        Finding(
            package="openssl",
            installed_version="1.1.1",
            cve_id="CVE-2023-0001",
            severity="Critical",
            cvss_score=9.8,
        )
    ]

    enrich_findings(findings, cache)

    assert findings[0].epss == 0.91
    assert findings[0].kev is True

    Path("tests/tmp_cache.sqlite").unlink(missing_ok=True)
