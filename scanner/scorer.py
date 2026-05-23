"""Risk scoring utilities for vulnerability findings."""

from __future__ import annotations

import math
from datetime import UTC, date, datetime

from scanner.models import Finding, ScanSummary

SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "negligible": 0,
}


def score_findings(
    image: str, findings: list[Finding], reference_date: date | None = None
) -> ScanSummary:
    """Calculate score for all findings and return summary."""
    if reference_date is None:
        reference_date = datetime.now(UTC).date()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}
    kev_count = 0
    total_score = 0.0

    for finding in findings:
        severity_key = finding.severity.lower()
        if severity_key not in counts:
            severity_key = "low"
        counts[severity_key] += 1
        if finding.kev:
            kev_count += 1

        severity_weight = float(SEVERITY_WEIGHT.get(severity_key, 1))
        epss_factor = 1.0 + min(finding.epss or 0.0, 1.0)
        kev_factor = 2.0 if finding.kev else 1.0
        fix_factor = 1.2 if finding.fixed_version else 1.0
        age_factor = _age_factor(finding.published_date, reference_date)

        finding.score = severity_weight * epss_factor * kev_factor * fix_factor * age_factor
        total_score += finding.score

    summary = ScanSummary(
        image=image,
        total_score=round(total_score, 2),
        risk_grade=_risk_grade(total_score),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        negligible_count=counts["negligible"],
        kev_count=kev_count,
        total_count=len(findings),
        ci_block=counts["critical"] > 0,
    )
    return summary


def _risk_grade(score: float) -> str:
    if score <= 10:
        return "A"
    if score <= 30:
        return "B"
    if score <= 60:
        return "C"
    if score <= 100:
        return "D"
    return "F"


def _age_factor(published_date: date | None, reference_date: date) -> float:
    if published_date is None:
        return 1.0
    age_days = max((reference_date - published_date).days, 1)
    scaled = 1.0 + math.log10(age_days / 30.0)
    return min(max(scaled, 1.0), 1.5)
