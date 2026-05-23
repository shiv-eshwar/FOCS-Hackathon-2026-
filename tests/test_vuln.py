"""Tests for vulnerability parsing."""

import json
from pathlib import Path

from scanner.vuln import extract_findings


def test_extract_findings_parses_grype_matches() -> None:
    fixture = Path("tests/fixtures/sample_vulns.json")
    payload = json.loads(fixture.read_text(encoding="utf-8"))

    findings = extract_findings(payload)

    assert len(findings) == 2
    assert findings[0].cve_id == "CVE-2023-0001"
    assert findings[0].cvss_score == 9.8
    assert findings[1].fixed_version == "2.32"
