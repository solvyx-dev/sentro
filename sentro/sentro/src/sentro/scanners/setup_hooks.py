"""Scanner: detect malicious install hooks in setup.py."""

from __future__ import annotations

import ast
from pathlib import Path

from ..models import Finding, PackageFiles, Severity
from .base import BaseScanner

_DANGEROUS_CALLS = frozenset({"system", "popen", "run", "call", "Popen", "check_output"})
_DANGEROUS_MODULES = frozenset({"os", "subprocess", "commands"})


class SetupHooksScanner(BaseScanner):
    name = "setup_hooks"
    description = "Detects malicious install hooks and dangerous code in setup.py"

    def scan(self, package: PackageFiles) -> list[Finding]:
        if package.setup_py is None:
            return []

        try:
            source = package.setup_py.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename="setup.py")
        except (OSError, SyntaxError):
            return [Finding(
                scanner=self.name,
                severity=Severity.WARNING,
                title="setup.py cannot be parsed",
                detail="setup.py contains a syntax error, which may be intentional to prevent analysis.",
                score=20,
                file_path="setup.py",
            )]

        findings: list[Finding] = []
        findings.extend(self._check_toplevel_dangerous_calls(tree, source))
        findings.extend(self._check_cmdclass_override(tree, source))
        findings.extend(self._check_dynamic_install_requires(tree, source))
        return findings

    def _check_toplevel_dangerous_calls(self, tree: ast.AST, source: str) -> list[Finding]:
        """Flag dangerous calls that are NOT inside any function/class (run at install time)."""
        findings: list[Finding] = []
        visitor = _ToplevelCallVisitor()
        visitor.visit(tree)
        for node in visitor.dangerous_calls:
            if _has_nosec(source, node.lineno):
                continue
            severity = Severity.DANGER
            score = 50
            findings.append(Finding(
                scanner=self.name,
                severity=severity,
                title="Dangerous module-level call in setup.py",
                detail=(
                    "This call executes at package install time (when pip runs setup.py). "
                    "Legitimate setup.py files do not need to run shell commands at the top level."
                ),
                score=score,
                file_path="setup.py",
                line_number=node.lineno,
            ))
        return findings

    def _check_cmdclass_override(self, tree: ast.AST, source: str) -> list[Finding]:
        """Flag setup(cmdclass={...}) — legitimate but worth noting."""
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_setup = (isinstance(func, ast.Name) and func.id == "setup") or (
                isinstance(func, ast.Attribute) and func.attr == "setup"
            )
            if not is_setup:
                continue
            for kw in node.keywords:
                if kw.arg == "cmdclass":
                    if _has_nosec(source, node.lineno):
                        continue
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.WARNING,
                        title="setup.py overrides install command (cmdclass)",
                        detail=(
                            "cmdclass overrides allow custom code to run during pip install. "
                            "This is legitimate for some packages but is also a common malware technique."
                        ),
                        score=20,
                        file_path="setup.py",
                        line_number=node.lineno,
                    ))
        return findings

    def _check_dynamic_install_requires(self, tree: ast.AST, source: str) -> list[Finding]:
        """Flag install_requires computed by subprocess or open()."""
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.keyword):
                continue
            if node.arg != "install_requires":
                continue
            val = node.value
            line_no = getattr(val, "lineno", None)
            if _has_nosec(source, line_no):
                continue
            # If it's a plain list literal, that's fine
            if isinstance(val, ast.List):
                continue
            # Anything else (function call, name, etc.) is suspicious
            findings.append(Finding(
                scanner=self.name,
                severity=Severity.WARNING,
                title="install_requires is computed dynamically",
                detail=(
                    "install_requires should be a static list. "
                    "Dynamic computation can hide malicious dependency injection."
                ),
                score=25,
                file_path="setup.py",
                line_number=line_no,
            ))
        return findings


class _ToplevelCallVisitor(ast.NodeVisitor):
    """Collects dangerous calls at module scope (depth 0)."""

    def __init__(self) -> None:
        self.dangerous_calls: list[ast.Call] = []
        self._depth = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._depth += 1
        self.generic_visit(node)
        self._depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._depth += 1
        self.generic_visit(node)
        self._depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if self._depth == 0 and _is_dangerous_call(node):
            self.dangerous_calls.append(node)
        self.generic_visit(node)


def _is_dangerous_call(node: ast.Call) -> bool:
    func = node.func
    # os.system(...), subprocess.run(...), etc.
    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id in _DANGEROUS_MODULES
        and func.attr in _DANGEROUS_CALLS
    ):
        return True
    # exec(...) / eval(...)
    if isinstance(func, ast.Name) and func.id in {"exec", "eval"}:
        return True
    return False


def _has_nosec(source: str, line_number: int | None) -> bool:
    """Return True if the line contains a # nosec comment."""
    if line_number is None:
        return False
    lines = source.splitlines()
    if not (1 <= line_number <= len(lines)):
        return False
    return "# nosec" in lines[line_number - 1]
