"""Scanner: detect typosquatting via fuzzy name matching and homoglyphs."""

from __future__ import annotations

import difflib
import re
from importlib import resources
from pathlib import Path

from ..models import Finding, PackageFiles, Severity
from .base import BaseScanner

_TYPOSQUAT_SUFFIXES = (
    "-dev", "-test", "-staging", "-fork", "-fix", "-patch",
    "-backup", "-old", "-new", "-copy", "-clone", "-fake",
    "2", "3", "4",
)
_ASCII_RE = re.compile(r'^[\x00-\x7F]+$')
_FUZZY_CUTOFF = 0.85


class TyposquattingScanner(BaseScanner):
    name = "typosquatting"
    description = "Detects package names that closely resemble popular packages"

    def __init__(self) -> None:
        self._popular = self._load_popular_packages()

    def _load_popular_packages(self) -> list[str]:
        data_path = Path(__file__).parent.parent / "data" / "popular_packages.txt"
        if data_path.exists():
            text = data_path.read_text(encoding="utf-8")
            return [line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#")]
        return []

    def scan(self, package: PackageFiles) -> list[Finding]:
        name = package.name
        findings: list[Finding] = []
        findings.extend(self._check_homoglyphs(name))
        findings.extend(self._check_fuzzy_match(name))
        findings.extend(self._check_suffix_patterns(name))
        return findings

    def _normalize(self, name: str) -> str:
        return re.sub(r"[-_.]", "", name).lower()

    def _check_homoglyphs(self, name: str) -> list[Finding]:
        if not _ASCII_RE.match(name):
            non_ascii = [c for c in name if ord(c) > 127]
            return [Finding(
                scanner=self.name,
                severity=Severity.DANGER,
                title="Non-ASCII characters in package name",
                detail=(
                    f"Package name contains non-ASCII characters: {non_ascii!r}. "
                    "This is a homoglyph attack — characters that look like ASCII letters "
                    "but are Unicode lookalikes (Cyrillic, Greek, etc.)."
                ),
                score=70,
            )]
        return []

    def _check_fuzzy_match(self, name: str) -> list[Finding]:
        if not self._popular:
            return []
        norm = self._normalize(name)
        # Skip if this package IS in the popular list
        if norm in {self._normalize(p) for p in self._popular}:
            return []

        matches = difflib.get_close_matches(
            norm,
            [self._normalize(p) for p in self._popular],
            n=3,
            cutoff=_FUZZY_CUTOFF,
        )
        if not matches:
            return []

        # Map normalized matches back to original names
        norm_to_orig = {self._normalize(p): p for p in self._popular}
        orig_matches = [norm_to_orig.get(m, m) for m in matches]

        return [Finding(
            scanner=self.name,
            severity=Severity.WARNING,
            title=f"Package name resembles popular package(s): {', '.join(orig_matches)}",
            detail=(
                f"'{name}' is very similar to {orig_matches}. "
                "This may be a typosquatting attempt targeting developers who mistype package names."
            ),
            score=35,
        )]

    def _check_suffix_patterns(self, name: str) -> list[Finding]:
        lower = name.lower()
        norm_popular = {self._normalize(p) for p in self._popular}
        for suffix in _TYPOSQUAT_SUFFIXES:
            if lower.endswith(suffix):
                base = lower[: -len(suffix)]
                if self._normalize(base) in norm_popular:
                    return [Finding(
                        scanner=self.name,
                        severity=Severity.WARNING,
                        title=f"Package name is a common typosquat suffix pattern: '{base}' + '{suffix}'",
                        detail=(
                            f"'{name}' looks like a variant of the popular package '{base}' "
                            f"with a '{suffix}' suffix. This pattern is commonly used in typosquatting."
                        ),
                        score=30,
                    )]
        return []
