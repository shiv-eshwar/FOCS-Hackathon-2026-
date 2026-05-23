"""Tests for SBOM helpers."""

import json
from pathlib import Path

from scanner.sbom import extract_packages


def test_extract_packages_reads_components() -> None:
    fixture = Path("tests/fixtures/sample_sbom.json")
    payload = json.loads(fixture.read_text(encoding="utf-8"))

    packages = extract_packages(payload)

    assert len(packages) == 2
    assert packages[0]["name"] == "openssl"
    assert packages[1]["version"] == "2.31"
