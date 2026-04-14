"""Tests for the dependency_confusion scanner."""

from __future__ import annotations

from pathlib import Path

from sentro.models import PackageFiles, Severity
from sentro.scanners.dependency_confusion import DependencyConfusionScanner

scanner = DependencyConfusionScanner()


def _pkg(name: str, has_metadata: bool = True) -> PackageFiles:
    return PackageFiles(
        name=name,
        version="0.1.0",
        source_dir=Path("/tmp"),
        python_files=[],
        pypi_metadata={"info": {}} if has_metadata else {},
    )


def test_stdlib_json_danger():
    findings = scanner.scan(_pkg("json"))
    assert any(f.severity == Severity.DANGER for f in findings)
    assert any("stdlib" in f.title.lower() or "shadows" in f.title.lower() for f in findings)


def test_stdlib_os_danger():
    findings = scanner.scan(_pkg("os"))
    assert any(f.severity == Severity.DANGER for f in findings)


def test_stdlib_urllib_danger():
    findings = scanner.scan(_pkg("urllib"))
    # urllib is in stdlib
    assert any(f.severity == Severity.DANGER for f in findings)


def test_requests_not_stdlib():
    findings = scanner.scan(_pkg("requests"))
    stdlib = [f for f in findings if "stdlib" in f.title.lower()]
    assert stdlib == []


def test_not_on_pypi_danger():
    findings = scanner.scan(_pkg("requests", has_metadata=False))
    assert any(f.severity == Severity.DANGER for f in findings)
    assert any("not found on pypi" in f.title.lower() for f in findings)


def test_known_package_no_pypi_absence_finding():
    findings = scanner.scan(_pkg("requests", has_metadata=True))
    pypi_findings = [f for f in findings if "not found" in f.title.lower()]
    assert pypi_findings == []
