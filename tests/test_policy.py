"""Tests for policy rules."""

from datetime import date
from pathlib import Path

from scanner.models import Finding
from scanner.policy import evaluate_policy, load_policy


def test_policy_blocks_critical_findings() -> None:
    rules = load_policy(Path("policies/default.yaml"))
    findings = [
        Finding(
            package="openssl",
            installed_version="1.1.1",
            cve_id="CVE-2023-0001",
            severity="Critical",
            cvss_score=9.8,
            epss=0.91,
            kev=False,
            published_date=date(2023, 1, 1),
        )
    ]

    result = evaluate_policy(findings, rules)

    assert result.action == "block"
    assert any("block-critical" in reason for reason in result.reasons)
