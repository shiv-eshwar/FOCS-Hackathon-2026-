"""CLI entrypoint for the PS-15 vulnerability scanner."""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from scanner.cache import FeedCache
from scanner.diff import compare_reports
from scanner.enrich import enrich_findings
from scanner.errors import ScannerError
from scanner.models import PolicyOutcome, ScanReport
from scanner.policy import evaluate_policy, load_policy
from scanner.report import render_terminal, write_html, write_json
from scanner.sbom import extract_packages, run_syft
from scanner.scorer import score_findings
from scanner.vuln import extract_findings, run_grype


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
        choices=["json", "html", "terminal"],
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

    if args.output == "terminal":
        render_terminal(report)
    elif args.output == "json":
        output_file = args.report_file or Path("report.json")
        write_json(report, output_file)
        print(f"JSON report written: {output_file}")
    elif args.output == "html":
        output_file = args.report_file or Path("report.html")
        write_html(report, Path("templates"), output_file)
        print(f"HTML report written: {output_file}")

    if _should_fail(args.fail_on, report):
        return 1
    return 0


def _run_pipeline(args: argparse.Namespace) -> ScanReport:
    """Execute full scanner pipeline and build final report object."""
    cache = FeedCache(args.cache_db)
    if args.refresh or args.live:
        cache.refresh()

    with tempfile.TemporaryDirectory(prefix="focs-scan-") as temp_dir:
        temp_path = Path(temp_dir)
        sbom_path = temp_path / "sbom.json"
        vuln_path = temp_path / "vulns.json"

        sbom_data = run_syft(args.image, sbom_path)
        _ = extract_packages(sbom_data)
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

    if fail_on == "critical":
        return report.summary.critical_count > 0
    if fail_on == "high":
        return report.summary.high_count > 0 or report.summary.critical_count > 0
    return False


if __name__ == "__main__":
    raise SystemExit(main())
