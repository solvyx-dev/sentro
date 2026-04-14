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


@pytest.mark.integration
def test_scan_nonexistent_package():
    from sentro.models import RiskLevel
    cfg = load_config()
    orch = ScanOrchestrator(config=cfg)
    report = orch.scan_package("this-package-definitely-does-not-exist-xyzzy-99999")
    assert report.pypi_verified is False
    # Should flag as DANGER (not on PyPI = dependency confusion risk)
    assert report.risk_level(cfg.thresholds) in (RiskLevel.WARNING, RiskLevel.DANGER)
