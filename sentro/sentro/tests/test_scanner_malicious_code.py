"""Tests for the malicious_code scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentro.models import PackageFiles, Severity
from sentro.scanners.malicious_code import MaliciousCodeScanner


def _make_package(tmp_path: Path, code: str) -> PackageFiles:
    f = tmp_path / "pkg" / "__init__.py"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(code)
    return PackageFiles(
        name="testpkg", version="0.1.0",
        source_dir=tmp_path, python_files=[f],
    )


scanner = MaliciousCodeScanner()


def test_clean_file_no_findings(tmp_path):
    pkg = _make_package(tmp_path, "def add(a, b):\n    return a + b\n")
    findings = scanner.scan(pkg)
    assert findings == []


def test_eval_at_module_level(tmp_path):
    pkg = _make_package(tmp_path, "eval('1+1')\n")
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.DANGER for f in findings)
    assert any("eval" in f.title.lower() for f in findings)


def test_exec_at_module_level(tmp_path):
    pkg = _make_package(tmp_path, "exec('import os')\n")
    findings = scanner.scan(pkg)
    assert any("exec" in f.title.lower() for f in findings)


def test_exec_with_base64_decode(tmp_path):
    code = "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    danger = [f for f in findings if f.severity == Severity.DANGER]
    assert danger
    # Should have higher score for obfuscation chain
    assert any(f.score >= 50 for f in danger)


def test_os_system(tmp_path):
    pkg = _make_package(tmp_path, "import os\nos.system('id')\n")
    findings = scanner.scan(pkg)
    assert any("os.system" in f.title.lower() or "shell" in f.title.lower() for f in findings)


def test_subprocess_shell_true(tmp_path):
    code = "import subprocess\nsubprocess.run(['ls'], shell=True)\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.DANGER for f in findings)


def test_socket_ip_connect(tmp_path):
    code = "import socket\ns = socket.socket()\ns.connect(('192.168.1.1', 4444))\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any("socket" in f.title.lower() or "192.168.1.1" in f.title for f in findings)


def test_syntax_error_flagged(tmp_path):
    pkg = _make_package(tmp_path, "def broken(\n    pass\n")
    findings = scanner.scan(pkg)
    assert any("syntax" in f.title.lower() for f in findings)


def test_no_findings_for_safe_code_with_imports(tmp_path):
    code = "import os\nimport sys\n\ndef get_path():\n    return os.path.join('a', 'b')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    # os.path.join is safe; no dangerous calls
    assert all(f.severity != Severity.DANGER for f in findings)


def test_eval_inside_function_is_warning_not_danger(tmp_path):
    code = "def safe_eval(expr):\n    return eval(expr)\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.WARNING for f in findings)
    assert not any(f.severity == Severity.DANGER for f in findings)


def test_dunder_import_inside_function_not_flagged(tmp_path):
    code = "def load_plugin(name):\n    mod = __import__(name)\n    return mod\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    # __import__ inside a function is a legitimate plugin-loader pattern
    import_findings = [f for f in findings if "__import__" in f.title]
    assert import_findings == []


def _make_package_at(tmp_path: Path, rel: str, code: str) -> PackageFiles:
    """Create a package with the file at an arbitrary relative path."""
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(code)
    return PackageFiles(
        name="testpkg", version="0.1.0",
        source_dir=tmp_path, python_files=[f],
    )


def test_eval_in_test_file_not_flagged(tmp_path):
    """eval() in a test file should not produce findings (common for testing dynamic behaviour)."""
    pkg = _make_package_at(tmp_path, "tests/test_utils.py", "def test_eval():\n    assert eval('1+1') == 2\n")
    findings = scanner.scan(pkg)
    assert findings == []


def test_decode_chain_in_test_file_still_flagged(tmp_path):
    """decode-exec chains are always flagged — even inside test files."""
    code = "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n"
    pkg = _make_package_at(tmp_path, "tests/test_evil.py", code)
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.DANGER for f in findings)


def test_os_system_in_cli_file_is_info_not_danger(tmp_path):
    """os.system() in a file that imports click should be INFO, not DANGER."""
    code = "import click\nimport os\n\ndef run():\n    os.system('ls')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    os_findings = [f for f in findings if "os.system" in f.title.lower() or "shell command" in f.title.lower()]
    assert os_findings
    assert all(f.severity == Severity.INFO for f in os_findings)


def test_os_system_without_cli_import_is_danger(tmp_path):
    """os.system() in a file with no CLI framework import should stay DANGER."""
    code = "import os\nos.system('id')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    os_findings = [f for f in findings if "shell command" in f.title.lower()]
    assert any(f.severity == Severity.DANGER for f in os_findings)
