"""Machine-readable JSON reporter."""

from __future__ import annotations

import json
from dataclasses import asdict

from .._version import __version__
from ..models import RiskLevel, ScanReport


def render_json_report(report: ScanReport, thresholds: dict, verbose: bool = False) -> str:
    level = report.risk_level(thresholds)
    findings = []
    for f in report.findings:
        d = {
            "scanner": f.scanner,
            "severity": f.severity.value,
            "title": f.title,
            "detail": f.detail,
            "score": f.score,
        }
        if f.file_path:
            d["file_path"] = f.file_path
        if f.line_number is not None:
            d["line_number"] = f.line_number
        if f.code_snippet:
            d["code_snippet"] = f.code_snippet
        findings.append(d)

    output: dict = {
        "sentro_version": __version__,
        "package": report.package_name,
        "version": report.package_version,
        "pypi_verified": report.pypi_verified,
        "risk_level": level.value,
        "risk_score": report.risk_score,
        "findings_count": len(report.findings),
        "findings": findings,
    }

    if verbose:
        output["metadata"] = {
            "age_days": report.age_days,
            "download_stats": report.download_stats,
            "reputation_discount": report.reputation_discount,
        }
        output["scanner_summary"] = report.scanner_summary

    return json.dumps(output, indent=2)
