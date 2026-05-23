"""CLI entrypoint for the PS-15 vulnerability scanner."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from scanner.cache import FeedCache
from scanner.diff import compare_reports
from scanner.enrich import enrich_findings
from scanner.errors import ScannerError
from scanner.models import PolicyOutcome, ScanReport
from scanner.policy import evaluate_policy, load_policy
from scanner.report import render_terminal, write_both, write_html, write_json
from scanner.sbom import extract_packages, run_syft, syft_version
from scanner.scorer import score_findings
from scanner.vuln import extract_findings, grype_version, run_grype


def parse_args() -> argparse.Namespace:
    """Create and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="FOCS PS-15 container vulnerability scanner"
    )
    parser.add_argument(
        "--image",
        required=True,
        help="Container image reference (example: nginx:1.14)",
    )
    parser.add_argument(
        "--output",
        default="terminal",
        choices=["json", "html", "terminal", "both"],
        help="Output format",
    )
    parser.add_argument(
        "--fail-on",
        default="critical",
        choices=["critical", "high"],
        help="Fail threshold for non-zero exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate arguments without scanning",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Baseline report JSON for diff",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("policies/default.yaml"),
        help="Policy YAML",
    )
    parser.add_argument(
        "--cache-db",
        type=Path,
        default=Path("data/feeds.sqlite"),
        help="SQLite cache path",
    )
    parser.add_argument("--refresh", action="store_true", help="Refresh threat feeds from internet")
    parser.add_argument("--live", action="store_true", help="Alias for --refresh")
    parser.add_argument("--report-file", type=Path, default=None, help="Output file path override")
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path("reports"),
        help="Reports output directory",
    )
    parser.add_argument("--project", default="", help="Project name for report context")
    parser.add_argument("--branch", default="", help="Git branch for report context")
    return parser.parse_args()


def main() -> int:
    """Run scan pipeline and return process exit code."""
    args = parse_args()

    if args.dry_run:
        print(f"Dry run complete: image={args.image} output={args.output}")
        return 0

    try:
        report = _run_pipeline(args)
    except ScannerError as error:
        print(f"Scan failed: {error}")
        return 2

    _render_outputs(args, report)

    if _should_fail(args.fail_on, report):
        return 1
    return 0


def _run_pipeline(args: argparse.Namespace) -> ScanReport:
    """Execute full scanner pipeline and build final report object."""
    start_time = time.perf_counter()
    cache = FeedCache(args.cache_db)
    if args.refresh or args.live:
        cache.refresh()

    package_count = 0
    with tempfile.TemporaryDirectory(prefix="focs-scan-") as temp_dir:
        temp_path = Path(temp_dir)
        sbom_path = temp_path / "sbom.json"
        vuln_path = temp_path / "vulns.json"

        sbom_data = run_syft(args.image, sbom_path)
        package_count = len(extract_packages(sbom_data))
        vuln_data = run_grype(sbom_path, vuln_path)

    findings = extract_findings(vuln_data)
    enrich_findings(findings, cache)
    summary = score_findings(args.image, findings)

    rules = load_policy(args.policy) if args.policy.exists() else []
    policy = evaluate_policy(findings, rules) if rules else PolicyOutcome(action="pass", reasons=[])

    metadata = {
        "generated_at": datetime.now(UTC).isoformat(),
        "image": args.image,
        "policy_path": str(args.policy),
        "cache_db": str(args.cache_db),
        "project": args.project or "VaultShield Demo App",
        "branch": args.branch or _determine_branch(),
        "commit_sha": _determine_commit_sha(),
        "scan_duration_seconds": round(time.perf_counter() - start_time, 2),
        "total_packages_scanned": package_count,
        "tool_versions": {
            "syft": syft_version(),
            "grype": grype_version(),
        },
        "policy_rule_count": len(rules),
    }

    report = ScanReport(summary=summary, findings=findings, policy=policy, metadata=metadata)

    if args.baseline is not None and args.baseline.exists():
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        report.diff = compare_reports(baseline, report.to_dict())

    return report


def _should_fail(fail_on: str, report: ScanReport) -> bool:
    """Evaluate process failure criteria."""
    if report.policy.action == "block":
        return True

    policy_rule_count = int(report.metadata.get("policy_rule_count", 0))
    if policy_rule_count > 0:
        return False

    if fail_on == "critical":
        return report.summary.critical_count > 0
    if fail_on == "high":
        return report.summary.high_count > 0 or report.summary.critical_count > 0
    return False


def _render_outputs(args: argparse.Namespace, report: ScanReport) -> None:
    """Render requested report output format(s)."""
    if args.output == "terminal":
        render_terminal(report)
        return

    if args.output == "json":
        output_file = args.report_file or Path("report.json")
        write_json(report, output_file)
        print(f"JSON report written: {output_file}")
        return

    if args.output == "html":
        output_file = args.report_file or Path("report.html")
        write_html(report, Path("templates"), output_file)
        print(f"HTML report written: {output_file}")
        return

    output_dir = args.reports_dir
    write_both(report, Path("templates"), output_dir)
    print(f"Reports written to: {output_dir}")


def _determine_commit_sha() -> str:
    """Resolve commit SHA from CI environment or local git."""
    env_sha = os.getenv("GITHUB_SHA")
    if env_sha:
        return env_sha

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except OSError:
        return "unknown"

    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return "unknown"


def _determine_branch() -> str:
    """Resolve current branch from CI environment or local git."""
    env_branch = os.getenv("GITHUB_REF_NAME")
    if env_branch:
        return env_branch

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except OSError:
        return "unknown"

    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
