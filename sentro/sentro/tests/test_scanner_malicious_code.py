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


def test_eval_inside_function_is_info_not_danger(tmp_path):
    code = "def safe_eval(expr):\n    return eval(expr)\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.INFO for f in findings)
    assert not any(f.severity == Severity.DANGER for f in findings)


def test_dunder_import_at_module_level_is_info(tmp_path):
    code = "deps = ['os', 'sys']\nfor d in deps:\n    __import__(d)\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    import_findings = [f for f in findings if "__import__" in f.title]
    assert any(f.severity == Severity.INFO for f in import_findings)
    assert not any(f.severity == Severity.DANGER for f in import_findings)


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


def test_nosec_suppresses_os_system(tmp_path):
    code = "import os\nos.system('id')  # nosec\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert not any("os.system" in f.title.lower() for f in findings)


def test_shadowed_eval_not_flagged(tmp_path):
    """A locally imported 'eval' should not be treated as the builtin."""
    code = "from pandas.core.computation.eval import eval\nres = eval('x + y')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert not any("eval" in f.title.lower() for f in findings)


def test_eval_compile_exec_pattern_is_info(tmp_path):
    """exec(compile(..., 'exec')) is a standard file-loading pattern."""
    code = (
        "import types\n"
        "with open('config.py') as f:\n"
        "    exec(compile(f.read(), 'config.py', 'exec'), {} )\n"
    )
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    exec_findings = [f for f in findings if "exec" in f.title.lower()]
    assert any(f.severity == Severity.INFO for f in exec_findings)
    assert not any(f.severity == Severity.DANGER for f in exec_findings)


def test_duplicate_findings_collapsed(tmp_path):
    """Many identical findings in one file should be capped."""
    code = "\n".join([f"eval('x{i}')" for i in range(10)])
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    eval_findings = [f for f in findings if "Dynamic code execution: eval()" == f.title]
    assert len(eval_findings) <= 3
    assert any("additional occurrences" in f.title for f in findings)


def test_safe_subprocess_command_downgraded(tmp_path):
    """subprocess(..., shell=True, 'git log ...') should be WARNING not DANGER."""
    code = (
        "import subprocess\n"
        "subprocess.run('git log --pretty=format:%ct -1 HEAD', shell=True)\n"
    )
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    sp_findings = [f for f in findings if "subprocess" in f.title.lower()]
    assert any(f.severity == Severity.WARNING for f in sp_findings)
    assert not any(f.severity == Severity.DANGER for f in sp_findings)


def test_benign_eval_constant_is_zero_score(tmp_path):
    """eval('x + y') is a common parser pattern and should not contribute to risk score."""
    code = "def calc(expr):\n    return eval('a + b')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    eval_findings = [f for f in findings if "eval" in f.title.lower()]
    assert any(f.score == 0 for f in eval_findings)
    assert all(f.severity == Severity.INFO for f in eval_findings)


def test_compile_inside_function_skipped(tmp_path):
    """compile() inside a function is harmless by itself."""
    code = "def make_code(src):\n    return compile(src, '<string>', 'eval')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    compile_findings = [f for f in findings if "compile" in f.title.lower()]
    assert compile_findings == []


def test_dunder_import_module_level_zero_score(tmp_path):
    """__import__ at module level should be INFO with score 0."""
    code = "for mod in ['os', 'sys']:\n    __import__(mod)\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    import_findings = [f for f in findings if "__import__" in f.title]
    assert any(f.score == 0 for f in import_findings)
    assert all(f.severity == Severity.INFO for f in import_findings)


def test_os_system_without_cli_import_is_danger(tmp_path):
    """os.system() in a file with no CLI framework import should stay DANGER."""
    code = "import os\nos.system('id')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    os_findings = [f for f in findings if "shell command" in f.title.lower()]
    assert any(f.severity == Severity.DANGER for f in os_findings)


def test_sensitive_file_write_danger(tmp_path):
    """Writing to ~/.bashrc should be DANGER."""
    code = "with open('/home/user/.bashrc', 'a') as f:\n    f.write('evil')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.DANGER and "sensitive system file" in f.title.lower() for f in findings)


def test_safe_file_write_not_flagged(tmp_path):
    """Writing to a normal log file should not be flagged."""
    code = "with open('app.log', 'a') as f:\n    f.write('info')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert not any("sensitive system file" in f.title.lower() for f in findings)


def test_pip_install_via_subprocess_danger(tmp_path):
    """Using subprocess to install packages is a malware pattern."""
    code = (
        "import subprocess\n"
        "subprocess.run([sys.executable, '-m', 'pip', 'install', 'evil'])\n"
    )
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(
        f.severity == Severity.DANGER and "pip installation" in f.title.lower()
        for f in findings
    )


def test_pip_main_call_danger(tmp_path):
    """pip.main() is a known malware technique."""
    code = "import pip\npip.main(['install', 'evil'])\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(
        f.severity == Severity.DANGER and "pip installation" in f.title.lower()
        for f in findings
    )


def test_ctypes_load_warning(tmp_path):
    """Loading native libraries via ctypes is suspicious."""
    code = "import ctypes\nctypes.CDLL('./payload.so')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(
        f.severity == Severity.WARNING and "ctypes" in f.title.lower()
        for f in findings
    )


def test_getattr_builtins_evasion_danger(tmp_path):
    """getattr(__builtins__, 'eval') is reflection evasion."""
    code = "f = getattr(__builtins__, 'eval')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(
        f.severity == Severity.DANGER and "reflection evasion" in f.title.lower()
        for f in findings
    )


def test_importlib_dynamic_load_warning(tmp_path):
    """importlib.import_module with a variable argument is suspicious."""
    code = "import importlib\nmod = importlib.import_module(some_var)\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(
        f.severity == Severity.WARNING and "importlib" in f.title.lower()
        for f in findings
    )


def test_importlib_literal_not_flagged(tmp_path):
    """importlib.import_module('os') is normal and should not be flagged."""
    code = "import importlib\nmod = importlib.import_module('os')\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert not any("importlib" in f.title.lower() for f in findings)


def test_suspicious_url_request_warning(tmp_path):
    """requests to pastebin / discord webhooks should be flagged."""
    code = (
        "import requests\n"
        "requests.get('https://pastebin.com/raw/AbC123')\n"
    )
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(
        f.severity == Severity.WARNING and "suspicious url" in f.title.lower()
        for f in findings
    )


def test_socket_safe_public_ip_is_info(tmp_path):
    """socket.connect(('8.8.8.8', 80)) is a common local-IP trick and should be INFO."""
    code = "import socket\ns = socket.socket()\ns.connect(('8.8.8.8', 80))\n"
    pkg = _make_package(tmp_path, code)
    findings = scanner.scan(pkg)
    ip_findings = [f for f in findings if "8.8.8.8" in f.title]
    assert any(f.severity == Severity.INFO for f in ip_findings)
    assert not any(f.severity == Severity.DANGER for f in ip_findings)
