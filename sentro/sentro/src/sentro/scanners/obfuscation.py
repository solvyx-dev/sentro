"""Scanner: detect code obfuscation (base64/marshal chains, high entropy)."""

from __future__ import annotations

import ast
import math
import re
from pathlib import Path

from ..models import Finding, PackageFiles, Severity
from .base import BaseScanner

_DECODE_ATTRS = frozenset({"b64decode", "decodebytes", "decompress", "loads"})
_EXEC_NAMES = frozenset({"exec", "eval", "compile"})
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/\n]+=*$')
_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
_MIN_ENCODED_LEN = 500

# Variable names that indicate legitimate embedded data (skip encoded-constant check)
_SAFE_VAR_RE = re.compile(
    r'(font|image|icon|logo|schema|grammar|test|fixture|vector|cert|certificate|'
    r'digest|checksum|hash|sample|example|stub|mock|banner|template|svg|png|jpg)',
    re.IGNORECASE,
)

# Entropy threshold raised from 5.5 to 6.2 — only genuinely random/encrypted data
# exceeds this (most crypto test vectors, compressed resources stay below it).
_ENTROPY_THRESHOLD = 6.2


class ObfuscationScanner(BaseScanner):
    name = "obfuscation"
    description = "Detects base64/marshal exec chains, encoded payloads, and high-entropy strings"

    def scan(self, package: PackageFiles) -> list[Finding]:
        findings: list[Finding] = []
        targets = list(package.python_files)
        if package.setup_py:
            targets.append(package.setup_py)

        for path in targets:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            try:
                tree = ast.parse(source)
            except SyntaxError:
                # If it won't parse, malicious_code scanner handles that
                continue

            rel = str(path.relative_to(package.source_dir))
            is_test = _is_test_file(path)

            # Decode-exec chains: always check — no legitimate code has this pattern
            chain_findings = self._check_decode_exec_chain(tree, rel)
            findings.extend(chain_findings)

            if is_test:
                # Test files legitimately contain encoded fixtures, test vectors,
                # high-entropy key material, etc. Only keep the decode-chain check.
                continue

            # Encoded constants: only flag when in suspicious context
            encoded_findings = self._check_long_encoded_constants(tree, rel)
            findings.extend(encoded_findings)

            # High-entropy strings: only flag when there are already other suspicious
            # findings in this file. Avoids false positives from crypto test vectors,
            # embedded fonts, compressed resources in large legitimate libraries.
            if chain_findings or encoded_findings:
                findings.extend(self._check_high_entropy_strings(tree, rel))

        return findings

    def _check_decode_exec_chain(self, tree: ast.AST, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Name) and func.id in _EXEC_NAMES):
                continue
            # Check if the argument is itself a decode call
            if node.args and _is_decode_call(node.args[0]):
                depth = _decode_depth(node.args[0])
                score = min(80, 50 + depth * 10)
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.DANGER,
                    title=f"{func.id}(decode(...)) obfuscation chain detected",
                    detail=(
                        f"The code uses {func.id}() with a nested decode/decompress call "
                        f"(depth {depth}). This is the canonical obfuscation pattern used "
                        "by malicious packages to hide their payload."
                    ),
                    score=score,
                    file_path=rel_path,
                    line_number=node.lineno,
                ))
        return findings

    def _check_long_encoded_constants(self, tree: ast.AST, rel_path: str) -> list[Finding]:
        """Flag large base64/hex string constants assigned to variables.

        Only checks assignment targets so we have variable-name context.
        Constants assigned to names that look like legitimate embedded data
        (fonts, icons, schemas, test vectors) are skipped.
        """
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            val_node = node.value
            if not isinstance(val_node, ast.Constant):
                continue
            val = val_node.value
            if not isinstance(val, (str, bytes)):
                continue
            text = val if isinstance(val, str) else val.decode("latin-1")
            if len(text) < _MIN_ENCODED_LEN:
                continue

            # Skip if the variable name looks like legitimate embedded data
            var_name = ""
            if node.targets and isinstance(node.targets[0], ast.Name):
                var_name = node.targets[0].id
            if var_name and _SAFE_VAR_RE.search(var_name):
                continue

            clean = text.replace("\n", "").replace(" ", "")
            if _BASE64_RE.match(clean) and len(clean) > _MIN_ENCODED_LEN:
                purity = sum(
                    c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                    for c in clean
                ) / len(clean)
                if purity > 0.92:
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.WARNING,
                        title="Large base64-encoded string constant",
                        detail=(
                            f"A string of {len(text)} characters appears to be base64 encoded "
                            f"({purity:.0%} purity). This may be an encoded payload."
                        ),
                        score=25,
                        file_path=rel_path,
                        line_number=getattr(val_node, "lineno", None),
                    ))
            elif _HEX_RE.match(clean) and len(clean) > _MIN_ENCODED_LEN:
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.WARNING,
                    title="Large hex-encoded string constant",
                    detail=(
                        f"A string of {len(text)} characters appears to be hex encoded. "
                        "This may be an encoded payload."
                    ),
                    score=20,
                    file_path=rel_path,
                    line_number=getattr(val_node, "lineno", None),
                ))
        return findings

    def _check_high_entropy_strings(self, tree: ast.AST, rel_path: str) -> list[Finding]:
        """Flag string constants with Shannon entropy above the threshold.

        Only called when other suspicious findings already exist in the same file,
        so a high-entropy string alone never triggers a finding.
        """
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant):
                continue
            val = node.value
            if not isinstance(val, str) or len(val) < 64:
                continue
            entropy = _shannon_entropy(val)
            if entropy > _ENTROPY_THRESHOLD:
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.WARNING,
                    title="High-entropy string constant",
                    detail=(
                        f"String of length {len(val)} has Shannon entropy {entropy:.2f} bits/char "
                        f"(>{_ENTROPY_THRESHOLD}). This is typical of encrypted or randomly "
                        "generated data embedded in source code."
                    ),
                    score=20,
                    file_path=rel_path,
                    line_number=getattr(node, "lineno", None),
                ))
        return findings


def _is_test_file(path: Path) -> bool:
    """Return True if the file is part of a test suite."""
    return (
        path.name.startswith("test_")
        or path.name.endswith("_test.py")
        or "tests" in path.parts
        or "test" in path.parts
    )


def _is_decode_call(node: ast.expr) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _DECODE_ATTRS:
        return True
    return False


def _decode_depth(node: ast.expr, depth: int = 1) -> int:
    """Count how many nested decode calls are chained."""
    if not isinstance(node, ast.Call) or not node.args:
        return depth
    inner = node.args[0]
    if _is_decode_call(inner):
        return _decode_depth(inner, depth + 1)
    return depth


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())
