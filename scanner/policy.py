"""Policy as code evaluation for scanner output."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from scanner.models import Finding, PolicyOutcome


@dataclass(slots=True)
class PolicyRule:
    """A single policy rule."""

    rule_id: str
    action: str
    match: dict[str, Any]
    justification: str
    expires: date | None


def load_policy(policy_path: Path) -> list[PolicyRule]:
    """Load policy YAML file into structured rules."""
    payload = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    rules_raw = payload.get("rules", [])

    rules: list[PolicyRule] = []
    for raw in rules_raw:
        expires = _parse_date(raw.get("expires"))
        rules.append(
            PolicyRule(
                rule_id=str(raw.get("id", "unnamed-rule")),
                action=str(raw.get("action", "warn")).lower(),
                match=dict(raw.get("match", {})),
                justification=str(raw.get("justification", "")),
                expires=expires,
            )
        )
    return rules


def evaluate_policy(findings: list[Finding], rules: list[PolicyRule]) -> PolicyOutcome:
    """Evaluate findings against policy rules and return strongest action."""
    strongest = "pass"
    reasons: list[str] = []
    now = datetime.now(UTC).date()

    for finding in findings:
        for rule in rules:
            if rule.expires and now > rule.expires:
                reasons.append(f"Rule {rule.rule_id} expired on {rule.expires.isoformat()}")
                continue
            if not _matches(rule.match, finding):
                continue

            reasons.append(_format_reason(rule, finding))
            strongest = _stronger_action(strongest, rule.action)

    return PolicyOutcome(action=strongest, reasons=reasons)


def _matches(match: dict[str, Any], finding: Finding) -> bool:
    severity = match.get("severity")
    if severity is not None and str(severity).lower() != finding.severity.lower():
        return False

    cve_id = match.get("cve")
    if cve_id is not None and str(cve_id).upper() != finding.cve_id.upper():
        return False

    package = match.get("package")
    if package is not None and str(package).lower() != finding.package.lower():
        return False

    kev = match.get("kev")
    if kev is not None and bool(kev) != finding.kev:
        return False

    epss = match.get("epss_gte")
    if epss is not None and (finding.epss or 0.0) < float(epss):
        return False

    return True


def _parse_date(raw: Any) -> date | None:
    if raw is None:
        return None
    try:
        return date.fromisoformat(str(raw))
    except ValueError:
        return None


def _stronger_action(current: str, proposed: str) -> str:
    order = {"pass": 0, "ignore": 0, "warn": 1, "block": 2}
    return proposed if order.get(proposed, 0) > order.get(current, 0) else current


def _format_reason(rule: PolicyRule, finding: Finding) -> str:
    text = (
        f"{rule.rule_id} matched {finding.cve_id} "
        f"({finding.package}@{finding.installed_version})"
    )
    if rule.justification:
        return f"{text}: {rule.justification}"
    return text
