"""Tests for risk scorer."""

from datetime import date

from scanner.models import Finding
from scanner.scorer import score_findings


def test_score_findings_builds_summary() -> None:
    findings = [
        Finding(
            package="openssl",
            installed_version="1.1.1",
            cve_id="CVE-2023-0001",
            severity="Critical",
            cvss_score=9.8,
            fixed_version="1.1.1u",
            epss=0.9,
            kev=True,
            published_date=date(2023, 2, 12),
        )
    ]

    summary = score_findings("nginx:1.14", findings, reference_date=date(2026, 5, 23))

    assert summary.critical_count == 1
    assert summary.ci_block is True
    assert summary.total_score > 0
    assert findings[0].score > 0
