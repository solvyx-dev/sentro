"""Scanner: detect dependency confusion and stdlib name shadowing."""

from __future__ import annotations

import sys

from ..models import Finding, PackageFiles, Severity
from .base import BaseScanner

# stdlib_module_names is available in Python 3.10+
_STDLIB_NAMES: frozenset[str] = frozenset(
    getattr(sys, "stdlib_module_names", frozenset())
)


class DependencyConfusionScanner(BaseScanner):
    name = "dependency_confusion"
    description = "Detects stdlib name shadowing and packages absent from PyPI"

    def scan(self, package: PackageFiles) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_stdlib_shadowing(package.name))
        findings.extend(self._check_pypi_absence(package))
        return findings

    def _check_stdlib_shadowing(self, name: str) -> list[Finding]:
        normalized = name.replace("-", "_").lower()
        if normalized in {n.lower() for n in _STDLIB_NAMES}:
            return [Finding(
                scanner=self.name,
                severity=Severity.DANGER,
                title=f"Package name '{name}' shadows a Python stdlib module",
                detail=(
                    f"'{name}' is the same as a Python standard library module. "
                    "Installing this would shadow the stdlib module for all code in this environment, "
                    "which is a known supply-chain attack vector."
                ),
                score=80,
            )]
        return []

    def _check_pypi_absence(self, package: PackageFiles) -> list[Finding]:
        if not package.pypi_metadata:
            return [Finding(
                scanner=self.name,
                severity=Severity.DANGER,
                title="Package not found on PyPI",
                detail=(
                    f"'{package.name}' does not exist on PyPI. "
                    "This could be a dependency confusion attack: "
                    "an attacker publishes a public package matching an internal package name "
                    "to get it installed instead of the intended private package."
                ),
                score=60,
            )]
        return []
