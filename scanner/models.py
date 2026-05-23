"""Shared data models for scan pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date
from typing import Any


@dataclass(slots=True)
class Finding:
    """Represents one vulnerability finding."""

    package: str
    installed_version: str
    cve_id: str
    severity: str
    cvss_score: float
    fixed_version: str | None = None
    description: str = ""
    namespace: str = ""
    epss: float | None = None
    kev: bool = False
    published_date: date | None = None
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to dictionary."""
        output = asdict(self)
        output["published_date"] = self.published_date.isoformat() if self.published_date else None
        return output


@dataclass(slots=True)
class ScanSummary:
    """Summary values for vulnerability report."""

    image: str
    total_score: float
    risk_grade: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    negligible_count: int
    kev_count: int
    total_count: int
    ci_block: bool


@dataclass(slots=True)
class PolicyOutcome:
    """Policy evaluation result."""

    action: str
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanReport:
    """Final report model for outputs."""

    summary: ScanSummary
    findings: list[Finding]
    policy: PolicyOutcome
    metadata: dict[str, Any]
    diff: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to dictionary."""
        return {
            "summary": asdict(self.summary),
            "findings": [item.to_dict() for item in self.findings],
            "policy": asdict(self.policy),
            "metadata": self.metadata,
            "diff": self.diff,
        }
