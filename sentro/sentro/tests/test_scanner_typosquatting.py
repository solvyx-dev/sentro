"""Tests for the typosquatting scanner."""

from __future__ import annotations

from sentro.models import PackageFiles, Severity
from sentro.scanners.typosquatting import TyposquattingScanner

scanner = TyposquattingScanner()


def _pkg(name: str) -> PackageFiles:
    from pathlib import Path
    return PackageFiles(name=name, version="0.1.0", source_dir=Path("/tmp"))


def test_exact_popular_name_not_flagged():
    """requests itself should not be flagged."""
    findings = scanner.scan(_pkg("requests"))
    assert not any("requests" in f.title for f in findings)


def test_typosquat_reqeusts_flagged():
    findings = scanner.scan(_pkg("reqeusts"))
    assert any("requests" in f.title.lower() for f in findings)


def test_homoglyph_attack_danger():
    # Replace 'a' with Cyrillic 'а' (U+0430)
    fake = "n\u0443mpy"  # Cyrillic у instead of u
    findings = scanner.scan(_pkg(fake))
    assert any(f.severity == Severity.DANGER for f in findings)
    assert any("non-ascii" in f.title.lower() or "homoglyph" in f.title.lower() for f in findings)


def test_suffix_pattern_numpy_dev():
    findings = scanner.scan(_pkg("numpy-dev"))
    assert any("numpy" in f.title.lower() for f in findings)


def test_unrelated_name_no_findings():
    findings = scanner.scan(_pkg("myprivateinternalpackagexyz"))
    assert findings == []


def test_numpy_itself_not_flagged():
    findings = scanner.scan(_pkg("numpy"))
    # numpy is popular; should not flag itself
    fuzzy = [f for f in findings if "numpy" in f.title.lower() and "suffix" not in f.title.lower() and "non-ascii" not in f.title.lower()]
    assert fuzzy == []
