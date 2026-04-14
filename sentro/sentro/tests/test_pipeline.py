"""Tests for the scanner pipeline."""

from __future__ import annotations

from pathlib import Path

from sentro.config import load_config
from sentro.models import Finding, PackageFiles, Severity
from sentro.orchestrator import ScannerPipeline
from sentro.scanners.base import BaseScanner


class _AlwaysFindScanner(BaseScanner):
    name = "always_find"
    description = "Always returns one finding"

    def scan(self, package):
        return [Finding(
            scanner=self.name,
            severity=Severity.WARNING,
            title="Test finding",
            detail="Always present",
            score=20,
        )]


class _NeverFindScanner(BaseScanner):
    name = "never_find"
    description = "Never returns findings"

    def scan(self, package):
        return []


def _empty_pkg(tmp_path):
    return PackageFiles(name="pkg", version="0.1", source_dir=tmp_path, python_files=[])


def test_pipeline_runs_all_scanners(tmp_path):
    pipeline = ScannerPipeline([_AlwaysFindScanner(), _NeverFindScanner()])
    findings = pipeline.run(_empty_pkg(tmp_path), load_config())
    assert len(findings) == 1


def test_pipeline_disabled_scanner_skipped(tmp_path):
    cfg = load_config(cli_overrides={"scanners_disabled": ["always_find"]})
    pipeline = ScannerPipeline([_AlwaysFindScanner(), _NeverFindScanner()])
    findings = pipeline.run(_empty_pkg(tmp_path), cfg)
    assert findings == []


def test_pipeline_only_enabled_scanner_runs(tmp_path):
    cfg = load_config(cli_overrides={"scanners_enabled": ["never_find"]})
    pipeline = ScannerPipeline([_AlwaysFindScanner(), _NeverFindScanner()])
    findings = pipeline.run(_empty_pkg(tmp_path), cfg)
    assert findings == []


def test_pipeline_empty_no_crash(tmp_path):
    pipeline = ScannerPipeline([])
    assert pipeline.run(_empty_pkg(tmp_path), load_config()) == []
