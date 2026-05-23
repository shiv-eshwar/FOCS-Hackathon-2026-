"""Report formatting for terminal, JSON, and HTML outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.models import ScanReport

SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "orange3",
    "medium": "yellow",
    "low": "cyan",
    "negligible": "white",
}


def render_terminal(report: ScanReport) -> None:
    """Display report in rich terminal output."""
    console = Console()
    summary = report.summary

    banner_color = "red" if summary.ci_block or report.policy.action == "block" else "green"
    banner_text = "PIPELINE BLOCKED" if banner_color == "red" else "PIPELINE CLEAR"
    console.print(Panel.fit(banner_text, style=f"bold {banner_color}"))

    summary_table = Table(title="Scan Summary")
    summary_table.add_column("Metric")
    summary_table.add_column("Value", justify="right")
    summary_table.add_row("Image", summary.image)
    summary_table.add_row("Risk Grade", summary.risk_grade)
    summary_table.add_row("Total Score", f"{summary.total_score:.2f}")
    summary_table.add_row("Critical", str(summary.critical_count))
    summary_table.add_row("High", str(summary.high_count))
    summary_table.add_row("Medium", str(summary.medium_count))
    summary_table.add_row("Low", str(summary.low_count))
    summary_table.add_row("KEV", str(summary.kev_count))
    summary_table.add_row("Policy Action", report.policy.action.upper())
    console.print(summary_table)

    findings_table = Table(title="Vulnerabilities")
    findings_table.add_column("CVE")
    findings_table.add_column("Package")
    findings_table.add_column("Version")
    findings_table.add_column("Severity")
    findings_table.add_column("EPSS")
    findings_table.add_column("KEV")
    findings_table.add_column("Score")

    sorted_findings = sorted(report.findings, key=lambda item: item.score, reverse=True)
    for finding in sorted_findings:
        sev = finding.severity.lower()
        style = SEVERITY_COLOR.get(sev, "white")
        findings_table.add_row(
            finding.cve_id,
            finding.package,
            finding.installed_version,
            f"[{style}]{finding.severity}[/{style}]",
            _format_epss(finding.epss),
            "yes" if finding.kev else "no",
            f"{finding.score:.2f}",
        )
    console.print(findings_table)


def write_json(report: ScanReport, output_path: Path) -> None:
    """Write report as JSON."""
    payload = report.to_dict()
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_html(report: ScanReport, template_dir: Path, output_path: Path) -> None:
    """Render report to standalone HTML."""
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("report.html")

    severity_counts = {
        "critical": report.summary.critical_count,
        "high": report.summary.high_count,
        "medium": report.summary.medium_count,
        "low": report.summary.low_count,
    }
    top_packages = _top_packages(report.to_dict())

    html = template.render(
        report=report.to_dict(),
        severity_counts=severity_counts,
        top_packages=top_packages,
        bypasses=[
            "Static stripped binaries can hide vulnerable components.",
            "Runtime-injected libraries are outside static image SBOM visibility.",
            "Configuration weaknesses require complementary IaC/runtime scanning.",
        ],
    )
    output_path.write_text(html, encoding="utf-8")


def _top_packages(report_payload: dict[str, Any]) -> list[dict[str, Any]]:
    package_counts: dict[str, int] = {}
    for finding in report_payload.get("findings", []):
        package = str(finding.get("package", "unknown"))
        package_counts[package] = package_counts.get(package, 0) + 1

    ranked = sorted(package_counts.items(), key=lambda item: item[1], reverse=True)
    return [{"package": package, "count": count} for package, count in ranked[:10]]


def _format_epss(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.3f}"
