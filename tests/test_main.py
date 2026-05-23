"""Tests for CLI helper behavior."""

import argparse
from pathlib import Path

import pytest

import main
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


def test_should_fail_honors_non_blocking_policy_rules() -> None:
    report = _report(critical=5, high=10, action="warn")
    report.metadata["policy_rule_count"] = 2
    assert _should_fail("critical", report) is False


def test_render_outputs_both_writes_json_and_html(tmp_path: Path) -> None:
    args = argparse.Namespace(
        output="both",
        report_file=None,
        reports_dir=tmp_path / "reports",
    )
    report = _report(0, 0, "pass")
    main._render_outputs(args, report)

    assert (args.reports_dir / "report.json").exists()
    assert (args.reports_dir / "report.html").exists()


def test_run_pipeline_includes_metadata_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    args = argparse.Namespace(
        image="vaultshield-app:test",
        cache_db=tmp_path / "feeds.sqlite",
        refresh=False,
        live=False,
        policy=tmp_path / "missing-policy.yaml",
        baseline=None,
        project="VaultShield Demo App",
        branch="vulnerable",
    )

    monkeypatch.setattr(
        main,
        "run_syft",
        lambda _image, _sbom_path: {
            "components": [
                {"name": "pkg-a", "version": "1"},
                {"name": "pkg-b", "version": "1"},
                {"name": "pkg-c", "version": "1"},
            ]
        },
    )
    monkeypatch.setattr(main, "run_grype", lambda _sbom_path, _vuln_path: {"matches": []})
    monkeypatch.setattr(main, "extract_findings", lambda _vuln_data: [])
    monkeypatch.setattr(main, "enrich_findings", lambda findings, _cache: findings)

    report = main._run_pipeline(args)

    assert report.metadata["project"] == "VaultShield Demo App"
    assert report.metadata["branch"] == "vulnerable"
    assert report.metadata["total_packages_scanned"] == 3
    assert report.metadata["scan_duration_seconds"] >= 0
    assert isinstance(report.metadata["commit_sha"], str)
