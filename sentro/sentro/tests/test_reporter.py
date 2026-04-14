"""Tests for reporters."""

from __future__ import annotations

import json

from rich.console import Console
import io

from sentro.config import load_config
from sentro.models import Finding, RiskLevel, ScanReport, Severity
from sentro.reporting.json_reporter import render_json_report
from sentro.reporting.text_reporter import render_text_report


def _safe_report():
    return ScanReport("mypkg", "1.0.0", True, [])


def _danger_report():
    return ScanReport(
        "evil", "0.1.0", False,
        [Finding(
            scanner="malicious_code",
            severity=Severity.DANGER,
            title="exec() detected",
            detail="exec() is bad",
            score=75,
            file_path="evil/__init__.py",
            line_number=3,
            code_snippet="exec(payload)",
        )],
    )


def test_json_safe_report():
    cfg = load_config()
    output = render_json_report(_safe_report(), cfg.thresholds)
    data = json.loads(output)
    assert data["risk_level"] == "SAFE"
    assert data["risk_score"] == 0
    assert data["pypi_verified"] is True
    assert data["findings"] == []


def test_json_danger_report():
    cfg = load_config()
    output = render_json_report(_danger_report(), cfg.thresholds)
    data = json.loads(output)
    assert data["risk_level"] == "DANGER"
    assert data["risk_score"] == 75
    assert data["pypi_verified"] is False
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "DANGER"


def test_json_output_is_valid_json():
    cfg = load_config()
    output = render_json_report(_danger_report(), cfg.thresholds)
    parsed = json.loads(output)
    assert "sentro_version" in parsed
    assert "package" in parsed


def test_text_safe_report_no_crash():
    cfg = load_config()
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_text_report(_safe_report(), cfg.thresholds, console=console)
    text = buf.getvalue()
    assert "SAFE" in text


def test_text_danger_report_shows_finding():
    cfg = load_config()
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_text_report(_danger_report(), cfg.thresholds, console=console)
    text = buf.getvalue()
    assert "DANGER" in text


def test_text_no_findings_message():
    cfg = load_config()
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_text_report(_safe_report(), cfg.thresholds, console=console)
    assert "No issues found" in buf.getvalue()


def test_json_verbose_includes_metadata():
    cfg = load_config()
    report = ScanReport(
        "pkg", "1.0", True, [],
        trust_factor=0.5, age_days=100,
        download_stats={"last_month": 5000},
    )
    output = render_json_report(report, cfg.thresholds, verbose=True)
    data = json.loads(output)
    assert "metadata" in data
    assert data["metadata"]["age_days"] == 100
    assert data["scanner_summary"] == {}


def test_text_verbose_shows_detail_and_summary():
    cfg = load_config()
    report = _danger_report()
    buf = io.StringIO()
    # Use a wide console so the Detail column isn't truncated
    console = Console(file=buf, highlight=False, width=200)
    render_text_report(report, cfg.thresholds, console=console, verbose=True)
    text = buf.getvalue()
    assert "exec() is bad" in text  # detail shown
    assert "malicious_code" in text  # scanner summary shown
