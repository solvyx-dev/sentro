"""Tests for models.py."""

from sentro.models import Finding, RiskLevel, ScanReport, Severity


def test_risk_score_capped_at_100():
    findings = [
        Finding(scanner="x", severity=Severity.DANGER, title="A", detail="d", score=60),
        Finding(scanner="x", severity=Severity.DANGER, title="B", detail="d", score=60),
    ]
    report = ScanReport("pkg", "1.0", True, findings)
    assert report.risk_score == 100


def test_risk_level_safe():
    report = ScanReport("pkg", "1.0", True, [])
    assert report.risk_level({"warning": 30, "danger": 70}) == RiskLevel.SAFE


def test_risk_level_warning():
    findings = [Finding(scanner="x", severity=Severity.WARNING, title="W", detail="d", score=35)]
    report = ScanReport("pkg", "1.0", True, findings)
    assert report.risk_level({"warning": 30, "danger": 70}) == RiskLevel.WARNING


def test_risk_level_danger():
    findings = [Finding(scanner="x", severity=Severity.DANGER, title="D", detail="d", score=75)]
    report = ScanReport("pkg", "1.0", True, findings)
    assert report.risk_level({"warning": 30, "danger": 70}) == RiskLevel.DANGER


def test_empty_findings_score_zero():
    report = ScanReport("pkg", "1.0", True, [])
    assert report.risk_score == 0


def test_warning_only_findings_capped_at_65():
    """Multiple WARNING findings must not compound into DANGER."""
    findings = [Finding(scanner="x", severity=Severity.WARNING, title="W", detail="d", score=20)] * 4
    report = ScanReport("pkg", "1.0", True, findings)
    assert report.risk_score == 65  # raw=80, capped at 65
    assert report.risk_level({"warning": 30, "danger": 70}) == RiskLevel.WARNING


def test_danger_finding_lifts_warning_cap():
    """One DANGER finding uncaps the score so the full sum is returned."""
    findings = (
        [Finding(scanner="x", severity=Severity.WARNING, title="W", detail="d", score=20)] * 4
        + [Finding(scanner="x", severity=Severity.DANGER, title="D", detail="d", score=10)]
    )
    report = ScanReport("pkg", "1.0", True, findings)
    assert report.risk_score == 90  # 80+10, no cap
    assert report.risk_level({"warning": 30, "danger": 70}) == RiskLevel.DANGER
