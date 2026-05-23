"""Grype wrapper for vulnerability detection."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import date
from pathlib import Path
from typing import Any, cast

from scanner.errors import ToolExecutionError, ToolNotInstalledError
from scanner.models import Finding


def run_grype(sbom_path: Path, vuln_path: Path, timeout_seconds: int = 600) -> dict[str, Any]:
    """Run grype against an SBOM file and return parsed JSON results."""
    if shutil.which("grype") is None:
        raise ToolNotInstalledError("grype is not installed. Install grype to continue.")

    command = ["grype", f"sbom:{sbom_path}", "-o", "json", "--file", str(vuln_path)]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ToolExecutionError(
            f"grype timed out after {timeout_seconds}s for SBOM '{sbom_path}'"
        ) from error
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown grype error"
        raise ToolExecutionError(f"grype failed for '{sbom_path}': {message}")

    if not vuln_path.exists():
        raise ToolExecutionError(f"grype completed but output not found at {vuln_path}")

    return cast(dict[str, Any], json.loads(vuln_path.read_text(encoding="utf-8")))


def extract_findings(vuln_data: dict[str, Any]) -> list[Finding]:
    """Convert grype JSON matches to Finding objects."""
    findings: list[Finding] = []
    for match in vuln_data.get("matches", []):
        artifact = match.get("artifact", {})
        vulnerability = match.get("vulnerability", {})

        package = str(artifact.get("name", "unknown"))
        installed_version = str(artifact.get("version", "unknown"))
        cve_id = str(vulnerability.get("id", "UNKNOWN"))
        severity = str(vulnerability.get("severity", "Unknown"))
        cvss_score = _cvss_score(vulnerability)
        fixed_version = _fixed_version(vulnerability)
        description = str(vulnerability.get("description", ""))
        namespace = str(vulnerability.get("namespace", ""))
        published_date = _parse_published_date(vulnerability)

        findings.append(
            Finding(
                package=package,
                installed_version=installed_version,
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                fixed_version=fixed_version,
                description=description,
                namespace=namespace,
                published_date=published_date,
            )
        )

    return findings


def _cvss_score(vulnerability: dict[str, Any]) -> float:
    """Extract CVSS score from vulnerability payload."""
    cvss_entries = vulnerability.get("cvss", [])
    for cvss in cvss_entries:
        score = cvss.get("metrics", {}).get("baseScore")
        if score is not None:
            return float(score)
    return 0.0


def _fixed_version(vulnerability: dict[str, Any]) -> str | None:
    """Extract fixed version if available."""
    fixed_versions = vulnerability.get("fix", {}).get("versions", [])
    if not fixed_versions:
        return None
    return str(fixed_versions[0])


def _parse_published_date(vulnerability: dict[str, Any]) -> date | None:
    """Extract publication date from vulnerability metadata if available."""
    published_raw = vulnerability.get("publishedDate")
    if not isinstance(published_raw, str) or not published_raw:
        return None
    # Accept RFC3339 date-time style prefixes.
    try:
        return date.fromisoformat(published_raw[:10])
    except ValueError:
        return None


def grype_version() -> str:
    """Return grype version string if available."""
    if shutil.which("grype") is None:
        return "unavailable"

    result = subprocess.run(
        ["grype", "version", "-o", "json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        return "unknown"

    try:
        payload = cast(dict[str, Any], json.loads(result.stdout))
    except json.JSONDecodeError:
        return "unknown"

    return str(payload.get("version", "unknown"))
