"""Integration tests (require network). Run with: pytest -m integration"""

from __future__ import annotations

import pytest

from sentro.config import load_config
from sentro.models import RiskLevel
from sentro.orchestrator import ScanOrchestrator


@pytest.mark.integration
def test_scan_cowsay_safe():
    """cowsay is a trivial safe package."""
    cfg = load_config()
    orch = ScanOrchestrator(config=cfg)
    report = orch.scan_package("cowsay")
    assert report.pypi_verified is True
    # Should not be DANGER
    assert report.risk_level(cfg.thresholds) != RiskLevel.DANGER


@pytest.mark.integration
def test_scan_requests_safe():
    cfg = load_config()
    orch = ScanOrchestrator(config=cfg)
    report = orch.scan_package("requests")
    assert report.pypi_verified is True
    assert report.risk_level(cfg.thresholds) == RiskLevel.SAFE


# Golden-package regression tests: these widely-used packages should never
# score DANGER (and most should be SAFE) after accuracy improvements.
_GOLDEN_SAFE_PACKAGES = [
    "pandas",
    "numpy",
    "flask",
    "pillow",
    "matplotlib",
    "click",
    "pytest",
]


@pytest.mark.integration
@pytest.mark.parametrize("pkg_name", _GOLDEN_SAFE_PACKAGES)
def test_scan_golden_packages_are_safe(pkg_name):
    """Top-tier packages with millions of downloads must not be flagged as DANGER."""
    cfg = load_config()
    orch = ScanOrchestrator(config=cfg)
    report = orch.scan_package(pkg_name)
    assert report.pypi_verified is True
    assert report.risk_level(cfg.thresholds) != RiskLevel.DANGER


@pytest.mark.integration
def test_scan_django_not_danger():
    """django uses subprocess(shell=True) for git log — should be WARNING at most."""
    cfg = load_config()
    orch = ScanOrchestrator(config=cfg)
    report = orch.scan_package("django")
    assert report.pypi_verified is True
    assert report.risk_level(cfg.thresholds) != RiskLevel.DANGER


@pytest.mark.integration
def test_scan_nonexistent_package():
    from sentro.models import RiskLevel
    cfg = load_config()
    orch = ScanOrchestrator(config=cfg)
    report = orch.scan_package("this-package-definitely-does-not-exist-xyzzy-99999")
    assert report.pypi_verified is False
    # Should flag as DANGER (not on PyPI = dependency confusion risk)
    assert report.risk_level(cfg.thresholds) in (RiskLevel.WARNING, RiskLevel.DANGER)
