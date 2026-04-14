"""Scanner: detect malicious code patterns via AST walking and regex."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional

from ..models import Finding, PackageFiles, Severity
from .base import BaseScanner

# Regex patterns used as fallback when AST parsing fails
_RE_EVAL_EXEC = re.compile(r'\b(eval|exec)\s*\(', re.MULTILINE)
_RE_OS_SYSTEM = re.compile(r'\bos\s*\.\s*system\s*\(', re.MULTILINE)
_RE_SUBPROCESS_SHELL = re.compile(
    r'\bsubprocess\s*\.\s*(run|call|Popen|check_output|check_call)\s*\(.*?shell\s*=\s*True',
    re.MULTILINE | re.DOTALL,
)
_RE_SOCKET_IP = re.compile(
    r'socket\s*\.\s*connect\s*\(\s*\(\s*["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["\']',
    re.MULTILINE,
)

_DANGEROUS_BUILTINS = frozenset({"eval", "exec", "compile", "__import__"})
_DECODE_ATTRS = frozenset({"b64decode", "decodebytes", "decompress", "loads"})
_SHELL_MODULES = frozenset({"subprocess", "os", "commands"})
_CLI_MODULES = frozenset({"argparse", "click", "typer", "optparse"})


class MaliciousCodeScanner(BaseScanner):
    name = "malicious_code"
    description = "Detects eval/exec, shell invocations, and socket connections"

    def scan(self, package: PackageFiles) -> list[Finding]:
        findings: list[Finding] = []
        targets = list(package.python_files)
        if package.setup_py:
            targets.append(package.setup_py)

        for path in targets:
            findings.extend(self._scan_file(path, package.source_dir))
        return findings

    def _scan_file(self, path: Path, root: Path) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        rel = str(path.relative_to(root))
        is_test = _is_test_file(path)

        try:
            tree = ast.parse(source, filename=str(path))
            has_cli = _has_cli_framework_import(tree)
            return self._check_ast(tree, source, rel, is_test=is_test, has_cli_import=has_cli)
        except SyntaxError:
            if is_test:
                return []  # syntax errors in test files are not suspicious
            findings = self._check_regex(source, rel)
            findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.WARNING,
                    title="Syntax error in Python file",
                    detail=(
                        "This file cannot be parsed as valid Python. "
                        "This may indicate intentional obfuscation to defeat static analysis."
                    ),
                    score=15,
                    file_path=rel,
                )
            )
            return findings

    def _check_ast(
        self,
        tree: ast.AST,
        source: str,
        rel_path: str,
        is_test: bool = False,
        has_cli_import: bool = False,
    ) -> list[Finding]:
        visitor = _SecurityVisitor(rel_path, self.name, is_test=is_test, has_cli_import=has_cli_import)
        visitor.visit(tree)
        return visitor.findings

    def _check_regex(self, source: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for m in _RE_EVAL_EXEC.finditer(source):
            findings.append(Finding(
                scanner=self.name,
                severity=Severity.DANGER,
                title=f"Dynamic code execution: {m.group(1)}()",
                detail="eval()/exec() can execute arbitrary code at runtime.",
                score=40,
                file_path=rel_path,
                line_number=source[:m.start()].count("\n") + 1,
                code_snippet=_extract_line(source, m.start()),
            ))

        for m in _RE_OS_SYSTEM.finditer(source):
            findings.append(Finding(
                scanner=self.name,
                severity=Severity.DANGER,
                title="Shell command via os.system()",
                detail="os.system() executes shell commands and is commonly used in malware.",
                score=35,
                file_path=rel_path,
                line_number=source[:m.start()].count("\n") + 1,
                code_snippet=_extract_line(source, m.start()),
            ))

        for m in _RE_SUBPROCESS_SHELL.finditer(source):
            findings.append(Finding(
                scanner=self.name,
                severity=Severity.DANGER,
                title="subprocess with shell=True",
                detail="subprocess(..., shell=True) passes commands through the shell, enabling injection.",
                score=35,
                file_path=rel_path,
                line_number=source[:m.start()].count("\n") + 1,
                code_snippet=_extract_line(source, m.start()),
            ))

        for m in _RE_SOCKET_IP.finditer(source):
            findings.append(Finding(
                scanner=self.name,
                severity=Severity.DANGER,
                title=f"Outbound socket connection to IP {m.group(1)}",
                detail="Hardcoded IP address in socket.connect() is a red flag for C2/exfiltration.",
                score=50,
                file_path=rel_path,
                line_number=source[:m.start()].count("\n") + 1,
                code_snippet=_extract_line(source, m.start()),
            ))

        return findings


class _SecurityVisitor(ast.NodeVisitor):
    def __init__(
        self,
        rel_path: str,
        scanner_name: str,
        is_test: bool = False,
        has_cli_import: bool = False,
    ) -> None:
        self.rel_path = rel_path
        self.scanner_name = scanner_name
        self._is_test = is_test
        self._has_cli_import = has_cli_import
        self.findings: list[Finding] = []
        self._depth = 0  # function/class nesting depth

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
        self._check_call(node)
        self.generic_visit(node)

    def _check_call(self, node: ast.Call) -> None:
        func = node.func

        # eval() / exec() / compile() / __import__() as bare names
        if isinstance(func, ast.Name) and func.id in _DANGEROUS_BUILTINS:
            at_module_level = self._depth == 0
            is_import = func.id == "__import__"

            # __import__ inside a function is a common legitimate pattern
            # (plugin loaders, optional deps, importlib fallbacks). Skip it.
            if is_import and not at_module_level:
                return

            # decode chain: always DANGER regardless of depth or test context
            if node.args and _is_decode_chain(node.args[0]):
                severity = Severity.DANGER
                score = 65
                detail = (
                    f"{func.id}() is called with a decoded/decompressed payload — "
                    "a classic obfuscation technique to hide malicious code."
                )
            elif self._is_test:
                # In test files, eval/exec/etc are common for testing dynamic behaviour.
                # Only the decode-chain case above is kept; everything else is skipped.
                return
            elif at_module_level and not is_import:
                # eval/exec at module level runs unconditionally on import
                severity = Severity.DANGER
                score = 40
                detail = (
                    f"{func.id}() at module level executes arbitrary code unconditionally "
                    "when the package is imported. Legitimate packages do not need this."
                )
            elif is_import:
                # __import__ at module level: unusual but sometimes legitimate
                severity = Severity.WARNING
                score = 15
                detail = (
                    "__import__() at module level is unusual. "
                    "It may be legitimate (conditional import) but is worth reviewing."
                )
            else:
                # eval/exec inside a function: often legitimate (REPLs, template engines)
                severity = Severity.WARNING
                score = 20
                detail = (
                    f"{func.id}() inside a function can execute arbitrary code. "
                    "This is sometimes legitimate (e.g. a REPL or template engine) "
                    "but should be reviewed."
                )

            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=severity,
                title=f"Dynamic code execution: {func.id}()",
                detail=detail,
                score=score,
                file_path=self.rel_path,
                line_number=node.lineno,
                code_snippet=None,
            ))

        # os.system(...)
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "system"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
            and not self._is_test
        ):
            # CLI tools legitimately call os.system(); lower the severity in that context.
            if self._has_cli_import:
                severity = Severity.INFO
                score = 10
                detail = (
                    "os.system() in a file that imports a CLI framework. "
                    "Likely legitimate — review to confirm the command is not user-controlled."
                )
            else:
                severity = Severity.DANGER
                score = 35
                detail = "os.system() executes shell commands and is frequently used in malware."
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=severity,
                title="Shell command via os.system()",
                detail=detail,
                score=score,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))

        # subprocess.*(shell=True) — always dangerous, even in CLI tools
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
            and _has_shell_true(node)
            and not self._is_test
        ):
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=Severity.DANGER,
                title="subprocess call with shell=True",
                detail="shell=True passes commands through /bin/sh, enabling command injection.",
                score=35,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))

        # socket.connect(("x.x.x.x", port))
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "connect"
            and node.args
            and _is_ip_tuple(node.args[0])
            and not self._is_test
        ):
            ip = _extract_ip(node.args[0])
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=Severity.DANGER,
                title=f"Outbound socket connection to IP {ip}",
                detail="Hardcoded IP address in socket.connect() is a strong indicator of C2/exfiltration.",
                score=50,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))

        # urllib/requests to IP addresses
        elif _is_network_call_to_ip(func, node) and not self._is_test:
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=Severity.WARNING,
                title="Network request to hardcoded IP address",
                detail="Making HTTP requests to hardcoded IPs is suspicious and may indicate exfiltration.",
                score=30,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))


def _is_decode_chain(node: ast.expr) -> bool:
    """Return True if node looks like base64.b64decode(...) or zlib.decompress(...)."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _DECODE_ATTRS:
        return True
    return False


def _has_shell_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def _is_ip_tuple(node: ast.expr) -> bool:
    if not isinstance(node, ast.Tuple) or len(node.elts) < 1:
        return False
    first = node.elts[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return bool(_IP_RE.match(first.value))
    return False


def _extract_ip(node: ast.expr) -> str:
    if isinstance(node, ast.Tuple) and node.elts:
        first = node.elts[0]
        if isinstance(first, ast.Constant):
            return str(first.value)
    return "unknown"


def _is_network_call_to_ip(func: ast.expr, node: ast.Call) -> bool:
    """Detect urllib.request.urlopen("http://1.2.3.4/...")."""
    if not isinstance(func, ast.Attribute):
        return False
    if not node.args:
        return False
    first_arg = node.args[0]
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        if _IP_RE.search(first_arg.value.split("/")[2] if "//" in first_arg.value else ""):
            return True
    return False


def _is_test_file(path: Path) -> bool:
    """Return True if the file is part of a test suite."""
    return (
        path.name.startswith("test_")
        or path.name.endswith("_test.py")
        or "tests" in path.parts
        or "test" in path.parts
    )


def _has_cli_framework_import(tree: ast.AST) -> bool:
    """Return True if the file imports a CLI framework (argparse, click, typer, optparse)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _CLI_MODULES:
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in _CLI_MODULES:
                return True
    return False


def _extract_line(source: str, offset: int) -> Optional[str]:
    line_start = source.rfind("\n", 0, offset) + 1
    line_end = source.find("\n", offset)
    if line_end == -1:
        line_end = len(source)
    return source[line_start:line_end].strip()
