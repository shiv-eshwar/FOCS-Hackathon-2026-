"""Tests for CLI helper behavior."""

from main import _should_fail
from scanner.models import PolicyOutcome, ScanReport, ScanSummary


def _report(critical: int, high: int, action: str) -> ScanReport:
    summary = ScanSummary(
        image="img",
        total_score=0,
        risk_grade="A",
        critical_count=critical,
        high_count=high,
        medium_count=0,
        low_count=0,
        negligible_count=0,
        kev_count=0,
        total_count=critical + high,
        ci_block=critical > 0,
    )
    return ScanReport(
        summary=summary,
        findings=[],
        policy=PolicyOutcome(action=action),
        metadata={},
    )


def test_should_fail_threshold_and_policy() -> None:
    assert _should_fail("critical", _report(1, 0, "pass")) is True
    assert _should_fail("high", _report(0, 1, "pass")) is True
    assert _should_fail("critical", _report(0, 0, "block")) is True
    assert _should_fail("critical", _report(0, 0, "pass")) is False
