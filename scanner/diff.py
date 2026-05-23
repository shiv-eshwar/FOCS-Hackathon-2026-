"""Report differencing utilities."""

from __future__ import annotations

from typing import Any


def compare_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare baseline and current report finding sets."""
    base_findings = {_finding_key(item): item for item in baseline.get("findings", [])}
    curr_findings = {_finding_key(item): item for item in current.get("findings", [])}

    added_keys = sorted(set(curr_findings) - set(base_findings))
    removed_keys = sorted(set(base_findings) - set(curr_findings))
    shared_keys = set(base_findings).intersection(curr_findings)

    changed: list[dict[str, Any]] = []
    for key in sorted(shared_keys):
        before = base_findings[key]
        after = curr_findings[key]
        if (
            before.get("severity") != after.get("severity")
            or before.get("score") != after.get("score")
        ):
            changed.append({"key": key, "before": before, "after": after})

    return {
        "added": [curr_findings[key] for key in added_keys],
        "removed": [base_findings[key] for key in removed_keys],
        "changed": changed,
        "summary": {
            "added_count": len(added_keys),
            "removed_count": len(removed_keys),
            "changed_count": len(changed),
        },
    }


def _finding_key(finding: dict[str, Any]) -> str:
    return "|".join(
        [
            str(finding.get("cve_id", "")),
            str(finding.get("package", "")),
            str(finding.get("installed_version", "")),
        ]
    )
