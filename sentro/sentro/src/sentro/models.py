"""Core data models shared across all modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    DANGER = "DANGER"


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    DANGER = "DANGER"


@dataclass
class Finding:
    """A single security issue identified by a scanner."""

    scanner: str
    severity: Severity
    title: str
    detail: str
    score: int  # 0–100 contribution to total risk score
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None


@dataclass
class PackageFiles:
    """Files extracted from a downloaded package, ready for scanning."""

    name: str
    version: str
    source_dir: Path
    python_files: list[Path] = field(default_factory=list)
    setup_py: Optional[Path] = None
    pyproject_toml: Optional[Path] = None
    pypi_metadata: dict = field(default_factory=dict)
    download_stats: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    """Final result of scanning a package."""

    package_name: str
    package_version: str
    pypi_verified: bool
    findings: list[Finding] = field(default_factory=list)
    trust_factor: float = 1.0
    age_days: Optional[int] = None
    download_stats: dict = field(default_factory=dict)

    @property
    def risk_score(self) -> int:
        raw = min(100, sum(f.score for f in self.findings))
        # If every finding is WARNING or below, cap at 65 so that accumulating
        # many low-confidence signals never auto-promotes a package to DANGER.
        # A DANGER-severity finding (e.g. a decode-exec chain) lifts the cap.
        has_danger_finding = any(f.severity == Severity.DANGER for f in self.findings)
        if not has_danger_finding:
            raw = int(raw * self.trust_factor)
        return raw if has_danger_finding else min(raw, 65)

    def risk_level(self, thresholds: dict) -> RiskLevel:
        score = self.risk_score
        if score >= thresholds.get("danger", 70):
            return RiskLevel.DANGER
        if score >= thresholds.get("warning", 30):
            return RiskLevel.WARNING
        return RiskLevel.SAFE

    @property
    def scanner_summary(self) -> dict[str, dict[str, int]]:
        summary: dict[str, dict[str, int]] = {}
        for f in self.findings:
            summary.setdefault(f.scanner, {"INFO": 0, "WARNING": 0, "DANGER": 0})
            summary[f.scanner][f.severity.value] += 1
        return summary
