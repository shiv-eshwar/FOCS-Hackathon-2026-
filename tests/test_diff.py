"""Tests for report diffing."""

import json
from pathlib import Path

from scanner.diff import compare_reports


def test_compare_reports_detects_added_removed_changed() -> None:
    baseline = json.loads(Path("tests/fixtures/baseline_report.json").read_text(encoding="utf-8"))
    current = json.loads(Path("tests/fixtures/current_report.json").read_text(encoding="utf-8"))

    diff = compare_reports(baseline, current)

    assert diff["summary"]["added_count"] == 1
    assert diff["summary"]["changed_count"] == 1
    assert diff["summary"]["removed_count"] == 0
