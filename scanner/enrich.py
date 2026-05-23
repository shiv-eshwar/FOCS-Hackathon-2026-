"""Finding enrichment using cached threat intelligence feeds."""

from __future__ import annotations

from scanner.cache import FeedCache
from scanner.models import Finding


def enrich_findings(findings: list[Finding], cache: FeedCache) -> list[Finding]:
    """Add EPSS and KEV flags to findings in-place."""
    for finding in findings:
        finding.epss = cache.lookup_epss(finding.cve_id)
        finding.kev = cache.is_kev(finding.cve_id)
    return findings
