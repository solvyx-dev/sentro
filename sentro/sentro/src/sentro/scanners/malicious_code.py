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
_SUSPICIOUS_EVAL_KEYWORDS = frozenset({
    "import", "os", "subprocess", "socket", "sys", "shutil", "pathlib",
    "__builtins__", "__import__", "eval", "exec", "compile", "open",
})
_DECODE_ATTRS = frozenset({"b64decode", "decodebytes", "decompress", "loads"})
_SHELL_MODULES = frozenset({"subprocess", "os", "commands"})
_CLI_MODULES = frozenset({"argparse", "click", "typer", "optparse"})

# Well-known public DNS/resolver IPs commonly used for local-IP detection
_SAFE_PUBLIC_IPS = frozenset({
    "8.8.8.8", "8.8.4.4",      # Google DNS
    "1.1.1.1", "1.0.0.1",      # Cloudflare DNS
    "208.67.222.222",           # OpenDNS
    "9.9.9.9",                  # Quad9
    "127.0.0.1", "0.0.0.0",     # localhost / bind-all
})

# Known-safe hardcoded shell commands (e.g. git log, xdg-open, clear)
_SAFE_SHELL_COMMANDS_RE = re.compile(
    r'^\s*(git\s+(log|describe|status|rev-parse|diff|show)|'
    r'xdg-open|open|start|explorer|'
    r'make|cmd\s+/c\s+start|clear|cls|'
    r'[A-Za-z0-9_\\.\-]+\s+--version)\b',
    re.IGNORECASE,
)

# Path fragments that suggest a display/viewer/launch/editor/terminal/REPL utility
_SAFE_PATH_FRAGMENTS = frozenset({
    "show", "display", "viewer", "launch", "imageshow",
    "termui", "edit", "editor", "open",
    "terminal", "magics", "hooks", "page", "pager",
    "interactive", "repl", "shell",
})

# Path patterns where dynamic code execution (eval/exec/compile) is a known,
# well-documented legitimate pattern (e.g. code generators, test frameworks).
_SAFE_DYNAMIC_CODE_PATTERNS = (
    r"/f2py/",
    r"/sphinxext/",
    r"/assertion/rewrite",
    r"/distutils/",
    r"/testing/_private/",
    r"/pylab\.py$",
    r"/_pytest/",
)

# Sensitive paths that indicate persistence or credential theft
_SENSITIVE_PATH_RE = re.compile(
    r'('  # noqa: E501
    r'\.bashrc|\.zshrc|\.profile|\.bash_profile|\.bash_login|'
    r'authorized_keys|known_hosts|id_rsa|id_ed25519|id_dsa|'
    r'\.ssh[/\\]|\.gnupg|'
    r'cron\.d|crontab|cron\.(daily|hourly|weekly|monthly)|'
    r'/var/spool/cron|/etc/cron|'
    r'startup|Start Menu[/\\]Programs[/\\]Startup|'
    r'regsvr32|HKEY_|SOFTWARE\\Microsoft\\Windows|'
    r'\.npmrc|\.pypirc|netrc|\.git-credentials|'
    r'aws/credentials|azure/config|gcloud'
    r')',
    re.IGNORECASE,
)

# Suspicious domain patterns commonly used for C2 / staging
_SUSPICIOUS_DOMAIN_RE = re.compile(
    r'('  # noqa: E501
    r'pastebin\.(com|pl|co)|ghostbin|termbin|'
    r'discord(app)?\.com/api/webhooks|'
    r'api\.telegram\.org|'
    r'transfer\.sh|file\.io|0x0\.st|'
    r'raw\.githubusercontent\.com'
    r')',
    re.IGNORECASE,
)

# Max findings with the *same title* per file before collapsing
_MAX_FINDINGS_PER_TITLE = 3


class MaliciousCodeScanner(BaseScanner):
    name = "malicious_code"
    description = "Detects eval/exec, shell invocations, socket connections, file writes, and more"

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
        shadowed = _find_shadowed_builtins(tree)
        visitor = _SecurityVisitor(
            rel_path, self.name, source=source, is_test=is_test,
            has_cli_import=has_cli_import, shadowed=shadowed,
        )
        visitor.visit(tree)
        return _collapse_findings(visitor.findings, rel_path)

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
            ip = m.group(1)
            if ip in _SAFE_PUBLIC_IPS:
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.INFO,
                    title=f"Socket connection to well-known public IP {ip}",
                    detail=(
                        f"{ip} is a well-known public DNS/resolver. "
                        "This pattern is commonly used for local-IP detection and is usually harmless."
                    ),
                    score=0,
                    file_path=rel_path,
                    line_number=source[:m.start()].count("\n") + 1,
                    code_snippet=_extract_line(source, m.start()),
                ))
            else:
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.DANGER,
                    title=f"Outbound socket connection to IP {ip}",
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
        source: str,
        is_test: bool = False,
        has_cli_import: bool = False,
        shadowed: Optional[set[str]] = None,
    ) -> None:
        self.rel_path = rel_path
        self.scanner_name = scanner_name
        self._source = source
        self._is_test = is_test
        self._has_cli_import = has_cli_import
        self._shadowed = shadowed or set()
        self.findings: list[Finding] = []
        self._depth = 0  # function/class nesting depth
        self._try_depth = 0
        self._has_os_environ_access = False
        self._has_network_call = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._depth += 1
        self.generic_visit(node)
        self._depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._depth += 1
        self.generic_visit(node)
        self._depth -= 1

    def visit_Try(self, node: ast.Try) -> None:
        self._try_depth += 1
        self.generic_visit(node)
        self._try_depth -= 1

    visit_TryStar = visit_Try

    def visit_Call(self, node: ast.Call) -> None:
        self._check_call(node)
        self.generic_visit(node)

    def _check_call(self, node: ast.Call) -> None:
        func = node.func

        # eval() / exec() / compile() / __import__() as bare names
        if isinstance(func, ast.Name) and func.id in _DANGEROUS_BUILTINS:
            if func.id in self._shadowed:
                return

            if _has_nosec(self._source, node.lineno):
                return

            at_module_level = self._depth == 0
            is_import = func.id == "__import__"

            # __import__ inside a function is a common legitimate pattern
            # (plugin loaders, optional deps, importlib fallbacks). Skip it.
            if is_import and not at_module_level:
                return

            # eval(compile(..., "exec")) or exec(compile(..., "exec")) is the standard
            # pattern for loading a Python file into a namespace — very common and
            # usually legitimate (Flask config, Django shell, etc.).
            if func.id in ("eval", "exec") and node.args:
                if _is_compile_exec_pattern(node.args[0]):
                    self.findings.append(Finding(
                        scanner=self.scanner_name,
                        severity=Severity.INFO,
                        title=f"Dynamic code execution: {func.id}(compile(...))",
                        detail=(
                            f"{func.id}() is used with compile(..., 'exec') — a common pattern "
                            "for loading configuration or startup files. Usually legitimate."
                        ),
                        score=5,
                        file_path=self.rel_path,
                        line_number=node.lineno,
                    ))
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
            elif _is_known_legitimate_dynamic_code_path(self.rel_path):
                # Known legitimate patterns (f2py, sphinxext, assertion rewriting, etc.)
                return
            elif is_import:
                # __import__ at module level is extremely common for lazy loading and
                # optional dependency checks. Emit an INFO note with zero score so it
                # does not push reputable packages into false-positive WARNING territory.
                severity = Severity.INFO
                score = 0
                detail = (
                    "__import__() at module level is common for lazy loading or optional dependencies. "
                    "Usually legitimate."
                )
            elif func.id == "compile" and not at_module_level:
                # compile() inside a function by itself is harmless unless combined with
                # obfuscation or decode chains (handled above).
                return
            elif at_module_level and not is_import:
                # compile(..., "exec") by itself does not execute code; it's the standard
                # file-loading pattern. Downgrade to INFO unless it's part of a decode chain.
                if func.id == "compile" and _is_compile_exec_pattern(node):
                    severity = Severity.INFO
                    score = 5
                    detail = (
                        "compile(..., 'exec') at module level prepares a code object. "
                        "Usually harmless unless combined with obfuscation."
                    )
                else:
                    # eval/exec at module level runs unconditionally on import
                    severity = Severity.DANGER
                    score = 40
                    detail = (
                        f"{func.id}() at module level executes arbitrary code unconditionally "
                        "when the package is imported. Legitimate packages do not need this."
                    )
            else:
                # Benign constant-string eval inside functions (e.g. simple math expressions
                # in parsers). At module level we still treat it as suspicious because it
                # runs unconditionally on import.
                if func.id in ("eval", "exec") and node.args and _is_benign_eval_argument(node.args[0]):
                    self.findings.append(Finding(
                        scanner=self.scanner_name,
                        severity=Severity.INFO,
                        title=f"Dynamic code execution: {func.id}()",
                        detail=(
                            f"{func.id}() is called with a short, hardcoded string that "
                            "appears to be a benign expression. Common in template engines and parsers."
                        ),
                        score=0,
                        file_path=self.rel_path,
                        line_number=node.lineno,
                    ))
                    return
                # eval/exec inside a function: often legitimate (REPLs, template engines)
                severity = Severity.INFO
                score = 5
                detail = (
                    f"{func.id}() inside a function can execute arbitrary code. "
                    "This is sometimes legitimate (e.g. a REPL or template engine)."
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
            if _has_nosec(self._source, node.lineno):
                return

            is_safe_context = self._has_safe_shell_context(node)
            if self._has_cli_import or is_safe_context:
                severity = Severity.INFO
                score = 5
                detail = (
                    "os.system() in a file that imports a CLI framework or appears to be a "
                    "display/viewer utility. Likely legitimate — review to confirm the command is not user-controlled."
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

        # subprocess.*(shell=True)
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
            and _has_shell_true(node)
            and not self._is_test
        ):
            if _has_nosec(self._source, node.lineno):
                return

            severity = Severity.DANGER
            score = 35
            detail = "shell=True passes commands through /bin/sh, enabling command injection."

            # Downgrade if the command looks like a known-safe hardcoded string
            # or if the file path suggests a viewer/launcher/editor utility
            if node.args and _is_safe_shell_command(node.args[0]):
                severity = Severity.WARNING
                score = 15
                detail = (
                    "subprocess(..., shell=True) with a known-safe command (e.g. git log, xdg-open). "
                    "Often legitimate in development utilities."
                )
            elif self._has_safe_subprocess_context(node):
                severity = Severity.WARNING
                score = 15
                detail = (
                    "subprocess(..., shell=True) in a file that appears to be a display, "
                    "launch, or editor utility. Likely legitimate."
                )
            elif _is_pip_install_call(node):
                # Installing packages programmatically via shell=True is highly suspicious
                severity = Severity.DANGER
                score = 55
                detail = (
                    "subprocess(..., shell=True) is used to install Python packages. "
                    "This is a common technique for dependency confusion and chain-loading malware."
                )

            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=severity,
                title="subprocess call with shell=True",
                detail=detail,
                score=score,
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
            if _has_nosec(self._source, node.lineno):
                return
            ip = _extract_ip(node.args[0])
            if ip in _SAFE_PUBLIC_IPS:
                self.findings.append(Finding(
                    scanner=self.scanner_name,
                    severity=Severity.INFO,
                    title=f"Socket connection to well-known public IP {ip}",
                    detail=(
                        f"{ip} is a well-known public DNS/resolver. "
                        "This pattern is commonly used for local-IP detection and is usually harmless."
                    ),
                    score=0,
                    file_path=self.rel_path,
                    line_number=node.lineno,
                ))
                return
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
            if _has_nosec(self._source, node.lineno):
                return
            self._has_network_call = True
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=Severity.WARNING,
                title="Network request to hardcoded IP address",
                detail="Making HTTP requests to hardcoded IPs is suspicious and may indicate exfiltration.",
                score=30,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))

        # urllib/requests to suspicious domains
        elif _is_network_call_to_suspicious_url(func, node) and not self._is_test:
            if _has_nosec(self._source, node.lineno):
                return
            self._has_network_call = True
            url = _extract_url(node.args[0])
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=Severity.WARNING,
                title="Network request to suspicious URL",
                detail=(
                    f"Hardcoded URL '{url}' points to a service frequently abused for "
                    "C2 staging (pastebin, Discord webhooks, Telegram, raw GitHub, etc.)."
                ),
                score=40,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))

        # ctypes.CDLL / ctypes.windll / ctypes.cdll / ctypes.WinDLL
        elif _is_ctypes_load(func) and not self._is_test:
            if _has_nosec(self._source, node.lineno):
                return
            lib = _extract_ctypes_lib(node.args[0])
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=Severity.WARNING,
                title="Native library loading via ctypes",
                detail=(
                    f"Loading native library '{lib}' via ctypes can execute arbitrary machine code. "
                    "Malware often hides payloads in bundled .so/.dll files."
                ),
                score=30,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))

        # pip.main([...]) or pip.main(...)
        elif _is_pip_main_call(func, node) and not self._is_test:
            if _has_nosec(self._source, node.lineno):
                return
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=Severity.DANGER,
                title="Programmatic pip installation detected",
                detail=(
                    "Calling pip.main() or pip._internal.cli.main() to install packages at runtime "
                    "is a known malware technique for dependency confusion and payload delivery."
                ),
                score=55,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))

        # subprocess pip install (without shell=True)
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
            and not self._is_test
            and _is_subprocess_pip_install(node)
        ):
            if _has_nosec(self._source, node.lineno):
                return
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=Severity.DANGER,
                title="Programmatic pip installation via subprocess",
                detail=(
                    "Using subprocess to invoke pip install is a common supply-chain attack pattern "
                    "used to pull down secondary malicious payloads."
                ),
                score=50,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))

        # open(path, 'w') / open(path, 'a') to sensitive paths
        elif (
            isinstance(func, ast.Name)
            and func.id == "open"
            and not self._is_test
        ):
            if _has_nosec(self._source, node.lineno):
                return
            sensitive = _is_sensitive_file_open(node)
            if sensitive:
                self.findings.append(Finding(
                    scanner=self.scanner_name,
                    severity=Severity.DANGER,
                    title="Write to sensitive system file",
                    detail=(
                        f"Opening '{sensitive}' for writing is a strong indicator of persistence "
                        "(e.g. backdooring .bashrc, injecting SSH keys, or installing a cron job)."
                    ),
                    score=60,
                    file_path=self.rel_path,
                    line_number=node.lineno,
                ))

        # getattr(__builtins__, 'eval') or similar reflection
        elif _is_getattr_builtins_evasion(func, node) and not self._is_test:
            if _has_nosec(self._source, node.lineno):
                return
            attr = _extract_getattr_name(node.args[1])
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=Severity.DANGER,
                title=f"Reflection evasion: getattr(..., '{attr}')",
                detail=(
                    f"Using getattr() to retrieve '{attr}' is a known obfuscation technique "
                    "to evade simple static analysis tools."
                ),
                score=50,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))

        # importlib.import_module with non-constant or suspicious args
        elif _is_importlib_dynamic_load(func, node) and not self._is_test:
            if _has_nosec(self._source, node.lineno):
                return
            # importlib inside try/except is overwhelmingly a compatibility shim
            # (e.g. requests trying chardet vs charset_normalizer).
            if self._try_depth > 0:
                return
            self.findings.append(Finding(
                scanner=self.scanner_name,
                severity=Severity.WARNING,
                title="Dynamic module loading via importlib",
                detail=(
                    "importlib.import_module() with a non-literal or computed argument is "
                    "sometimes used by malware to hide imports until runtime."
                ),
                score=25,
                file_path=self.rel_path,
                line_number=node.lineno,
            ))

        # os.environ / os.getenv access
        elif _is_os_environ_access(func) and not self._is_test:
            self._has_os_environ_access = True

        if self._has_os_environ_access and self._has_network_call:
            # Already handled by co-occurrence; nothing to do per-call
            pass

    def _has_safe_shell_context(self, node: ast.Call) -> bool:
        """True if os.system() is in a file whose path suggests a viewer/launcher."""
        lower_path = self.rel_path.lower()
        if any(fragment in lower_path for fragment in _SAFE_PATH_FRAGMENTS):
            return True
        # os.system(self.get_command(...)) is typical of image viewers
        if node.args and isinstance(node.args[0], ast.Call):
            return True
        return False

    def _has_safe_subprocess_context(self, node: ast.Call) -> bool:
        """True if subprocess(..., shell=True) is in a file whose path suggests a viewer/launcher/editor."""
        lower_path = self.rel_path.lower()
        if any(fragment in lower_path for fragment in _SAFE_PATH_FRAGMENTS):
            return True
        # subprocess.Popen(self.get_command(...), shell=True) is typical of image viewers
        if node.args and isinstance(node.args[0], ast.Call):
            return True
        return False


def _is_benign_eval_argument(node: ast.expr) -> bool:
    """True if eval()/exec() is called with a short, hardcoded, non-suspicious string."""
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    text = node.value
    if len(text) > 120:
        return False
    lower = text.lower()
    if any(kw in lower for kw in _SUSPICIOUS_EVAL_KEYWORDS):
        return False
    # Heuristic: benign eval strings are usually simple expressions
    # (math, attribute access, dict/list literals) without statement syntax.
    if ";" in text or "\n" in text:
        return False
    return True


def _has_nosec(source: str, line_number: int | None) -> bool:
    """Return True if the line contains a # nosec comment."""
    if line_number is None:
        return False
    lines = source.splitlines()
    if not (1 <= line_number <= len(lines)):
        return False
    return "# nosec" in lines[line_number - 1]


def _find_shadowed_builtins(tree: ast.AST) -> set[str]:
    """Find names in the module that shadow eval/exec/compile/__import__."""
    shadowed: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[-1]
                if name in _DANGEROUS_BUILTINS:
                    shadowed.add(name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname or alias.name
                if name in _DANGEROUS_BUILTINS:
                    shadowed.add(name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in _DANGEROUS_BUILTINS:
                    shadowed.add(target.id)
    return shadowed


def _is_compile_exec_pattern(node: ast.expr) -> bool:
    """True for compile(..., 'exec') — the standard file-loading pattern."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not (isinstance(func, ast.Name) and func.id == "compile"):
        return False
    # compile(source, filename, mode) — check mode == "exec"
    if len(node.args) >= 3:
        mode_arg = node.args[2]
        if isinstance(mode_arg, ast.Constant) and mode_arg.value == "exec":
            return True
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and kw.value.value == "exec":
            return True
    return False


def _collapse_findings(findings: list[Finding], rel_path: str) -> list[Finding]:
    """Cap the number of identical-title findings per file to avoid noise."""
    if not findings:
        return findings

    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.title, []).append(f)

    collapsed: list[Finding] = []
    for title, items in groups.items():
        if len(items) <= _MAX_FINDINGS_PER_TITLE:
            collapsed.extend(items)
        else:
            collapsed.extend(items[:_MAX_FINDINGS_PER_TITLE])
            extra = len(items) - _MAX_FINDINGS_PER_TITLE
            collapsed.append(Finding(
                scanner=items[0].scanner,
                severity=Severity.INFO,
                title=f"{title} (additional occurrences)",
                detail=f"{extra} more occurrence(s) of the same pattern were found in this file.",
                score=0,
                file_path=rel_path,
            ))
    return collapsed


def _is_safe_shell_command(node: ast.expr) -> bool:
    """Check if the command argument is a hardcoded known-safe string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(_SAFE_SHELL_COMMANDS_RE.match(node.value))
    return False


def _is_pip_install_call(node: ast.Call) -> bool:
    """True for subprocess calls that contain both 'pip' and 'install' as string literals."""
    return _args_contain_all(node, ("pip", "install"))


def _is_pip_main_call(func: ast.expr, node: ast.Call) -> bool:
    """Detect pip.main([...]) or pip._internal.cli.main([...])."""
    if isinstance(func, ast.Attribute) and func.attr == "main":
        if isinstance(func.value, ast.Name) and func.value.id == "pip":
            return True
        if (
            isinstance(func.value, ast.Attribute)
            and func.value.attr == "main"
            and isinstance(func.value.value, ast.Attribute)
            and func.value.value.attr == "cli"
        ):
            return True
    return False


def _is_subprocess_pip_install(node: ast.Call) -> bool:
    """True for subprocess calls installing via pip (without shell=True, checked separately)."""
    return _args_contain_all(node, ("pip", "install")) or _args_contain_all(node, ("-m", "pip", "install"))


def _args_contain_all(node: ast.Call, needles: tuple[str, ...]) -> bool:
    """Check if any argument (list/tuple of strings or joined string) contains all needles."""
    all_args = node.args + [kw.value for kw in node.keywords if kw.arg != "shell"]
    for arg in all_args:
        if isinstance(arg, (ast.List, ast.Tuple)):
            values = []
            for elt in arg.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    values.append(elt.value)
            if all(n in values for n in needles):
                return True
        elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if all(n in arg.value for n in needles):
                return True
    return False


def _is_sensitive_file_open(node: ast.Call) -> Optional[str]:
    """Return the path string if open() targets a sensitive file for writing/appending."""
    if not node.args:
        return None
    path_node = node.args[0]
    path: Optional[str] = None
    if isinstance(path_node, ast.Constant) and isinstance(path_node.value, str):
        path = path_node.value
    elif isinstance(path_node, ast.JoinedStr):
        # Simple f-string heuristic: extract literal parts
        parts = []
        for v in path_node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
        path = "".join(parts) if parts else None

    if not path:
        return None

    mode = None
    if len(node.args) >= 2:
        mode_node = node.args[1]
        if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
            mode = mode_node.value
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = kw.value.value

    if mode and ("w" in mode or "a" in mode or "x" in mode) and _SENSITIVE_PATH_RE.search(path):
        return path
    return None


def _is_ctypes_load(func: ast.expr) -> bool:
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr in {"CDLL", "WinDLL", "OleDLL", "PyDLL", "windll", "cdll", "oledll", "pydll"}:
        if isinstance(func.value, ast.Name) and func.value.id == "ctypes":
            return True
        if isinstance(func.value, ast.Attribute) and func.value.attr in {"windll", "cdll", "oledll", "pydll"}:
            if isinstance(func.value.value, ast.Name) and func.value.value.id == "ctypes":
                return True
    return False


def _extract_ctypes_lib(node: ast.expr) -> str:
    if isinstance(node, ast.Constant):
        return str(node.value)
    return "<dynamic>"


def _is_getattr_builtins_evasion(func: ast.expr, node: ast.Call) -> bool:
    """Detect getattr(__builtins__, 'eval') and similar evasion patterns."""
    if not isinstance(func, ast.Name) or func.id != "getattr":
        return False
    if len(node.args) < 2:
        return False
    target = node.args[0]
    attr = node.args[1]
    if not _is_builtins_reference(target):
        return False
    if isinstance(attr, ast.Constant) and attr.value in _DANGEROUS_BUILTINS:
        return True
    return False


def _is_builtins_reference(node: ast.expr) -> bool:
    """True for __builtins__, __builtins__.__dict__, builtins, etc."""
    if isinstance(node, ast.Name) and node.id in {"__builtins__", "builtins", "__builtins__"}:
        return True
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "__builtins__"
    ):
        return True
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "builtins"
    ):
        return True
    return False


def _extract_getattr_name(node: ast.expr) -> str:
    if isinstance(node, ast.Constant):
        return str(node.value)
    return "unknown"


def _is_importlib_dynamic_load(func: ast.expr, node: ast.Call) -> bool:
    """Detect importlib.import_module(decoded_string) or other dynamic args."""
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in {"import_module", "find_loader", "find_spec"}:
        return False
    if not isinstance(func.value, ast.Name) or func.value.id != "importlib":
        return False
    if not node.args:
        return False
    first = node.args[0]
    # If it's a simple constant string, it's usually legitimate
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return False
    # Anything else (call, name, f-string, etc.) is worth flagging
    return True


def _is_os_environ_access(func: ast.expr) -> bool:
    """Detect os.environ or os.getenv access."""
    if isinstance(func, ast.Attribute) and func.attr == "environ":
        if isinstance(func.value, ast.Name) and func.value.id == "os":
            return True
    if isinstance(func, ast.Attribute) and func.attr == "getenv":
        if isinstance(func.value, ast.Name) and func.value.id == "os":
            return True
    return False


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


def _is_network_call_to_suspicious_url(func: ast.expr, node: ast.Call) -> bool:
    """Detect requests.get('https://pastebin.com/raw/...') and similar."""
    if not isinstance(func, ast.Attribute):
        return False
    if not node.args:
        return False
    first_arg = node.args[0]
    url = ""
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        url = first_arg.value
    elif isinstance(first_arg, ast.JoinedStr):
        parts = [v.value for v in first_arg.values if isinstance(v, ast.Constant)]
        url = "".join(parts)
    if url and _SUSPICIOUS_DOMAIN_RE.search(url):
        return True
    return False


def _extract_url(node: ast.expr) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = [v.value for v in node.values if isinstance(v, ast.Constant)]
        return "".join(parts)
    return "<dynamic>"


def _is_test_file(path: Path) -> bool:
    """Return True if the file is part of a test suite."""
    return (
        path.name.startswith("test_")
        or path.name.endswith("_test.py")
        or any(part in ("tests", "test") for part in path.parts)
    )


def _is_known_legitimate_dynamic_code_path(rel_path: str) -> bool:
    # Prepend a slash so patterns like /f2py/ match both 'pkg/f2py/x.py' and 'f2py/x.py'
    normalized = "/" + rel_path.lower()
    return any(re.search(p, normalized) for p in _SAFE_DYNAMIC_CODE_PATTERNS)


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
