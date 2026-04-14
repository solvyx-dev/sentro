"""Tests for the metadata scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentro.models import PackageFiles, Severity
from sentro.scanners.metadata import MetadataScanner

scanner = MetadataScanner()


def _pkg(pypi_metadata: dict, download_stats: dict | None = None) -> PackageFiles:
    return PackageFiles(
        name="testpkg",
        version="0.1.0",
        source_dir=Path("/tmp"),
        python_files=[],
        pypi_metadata=pypi_metadata,
        download_stats=download_stats or {},
    )


def test_no_metadata_no_findings():
    pkg = PackageFiles(name="x", version="0.1", source_dir=Path("/tmp"), python_files=[])
    assert scanner.scan(pkg) == []


def test_package_2_days_old_danger():
    metadata = {
        "info": {"author": "test", "home_page": "https://x.com", "summary": "s"},
        "releases": {
            "0.0.1": [{
                "upload_time_iso_8601": "2026-04-10T12:00:00.000000Z",
            }]
        },
    }
    findings = scanner.scan(_pkg(metadata))
    assert any(f.severity == Severity.DANGER for f in findings)


def test_package_15_days_old_warning():
    metadata = {
        "info": {"author": "test", "home_page": "https://x.com", "summary": "s"},
        "releases": {
            "0.0.1": [{
                "upload_time_iso_8601": "2026-03-28T12:00:00.000000Z",
            }]
        },
    }
    findings = scanner.scan(_pkg(metadata))
    assert any(f.severity == Severity.WARNING for f in findings)


def test_old_package_no_age_finding():
    metadata = {
        "info": {"author": "test", "home_page": "https://x.com", "summary": "s"},
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00.000000Z"}],
            "2.0.0": [{"upload_time_iso_8601": "2022-06-01T00:00:00.000000Z"}],
        },
    }
    findings = scanner.scan(_pkg(metadata))
    age_findings = [f for f in findings if "old" in f.title.lower() or "day" in f.title.lower()]
    assert age_findings == []


def test_low_downloads_warning():
    metadata = {
        "info": {"author": "test", "home_page": "https://x.com", "summary": "s"},
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00.000000Z"}],
            "2.0.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00.000000Z"}],
        },
    }
    findings = scanner.scan(_pkg(metadata, download_stats={"last_month": 5}))
    assert any("download" in f.title.lower() for f in findings)


def test_high_downloads_no_finding():
    metadata = {
        "info": {"author": "test", "home_page": "https://x.com", "summary": "s"},
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00.000000Z"}],
            "2.0.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00.000000Z"}],
        },
    }
    findings = scanner.scan(_pkg(metadata, download_stats={"last_month": 500000}))
    download_findings = [f for f in findings if "download" in f.title.lower()]
    assert download_findings == []


def test_single_release_warning():
    metadata = {
        "info": {"author": "test", "home_page": "https://x.com", "summary": "s"},
        "releases": {
            "0.0.1": [{"upload_time_iso_8601": "2020-01-01T00:00:00.000000Z"}],
        },
    }
    findings = scanner.scan(_pkg(metadata))
    assert any("one release" in f.title.lower() or "single" in f.title.lower() for f in findings)


def test_missing_all_metadata_warning():
    metadata = {
        "info": {"author": "", "home_page": "", "summary": "", "project_urls": None},
        "releases": {
            "0.0.1": [{"upload_time_iso_8601": "2020-01-01T00:00:00.000000Z"}],
            "0.0.2": [{"upload_time_iso_8601": "2021-01-01T00:00:00.000000Z"}],
        },
    }
    findings = scanner.scan(_pkg(metadata))
    assert any("author" in f.title.lower() or "description" in f.title.lower() for f in findings)
