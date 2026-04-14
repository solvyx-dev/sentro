"""Tests for the obfuscation scanner."""

from __future__ import annotations

from pathlib import Path

from sentro.models import PackageFiles, Severity
from sentro.scanners.obfuscation import ObfuscationScanner

scanner = ObfuscationScanner()


def _make_pkg(tmp_path: Path, code: str) -> PackageFiles:
    f = tmp_path / "pkg" / "__init__.py"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(code)
    return PackageFiles(
        name="pkg", version="0.1.0",
        source_dir=tmp_path, python_files=[f],
    )


def test_clean_no_findings(tmp_path):
    pkg = _make_pkg(tmp_path, "def add(a, b):\n    return a + b\n")
    assert scanner.scan(pkg) == []


def test_exec_b64decode_chain_danger(tmp_path):
    code = "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n"
    pkg = _make_pkg(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.DANGER for f in findings)
    assert any("decode" in f.title.lower() or "obfuscation" in f.title.lower() for f in findings)


def test_exec_zlib_decompress_chain(tmp_path):
    code = "import zlib, base64\nexec(zlib.decompress(base64.b64decode('abc')))\n"
    pkg = _make_pkg(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.DANGER for f in findings)


def test_large_base64_constant(tmp_path):
    # A 600-char base64 string
    b64 = "A" * 596 + "AA=="
    code = f'payload = "{b64}"\n'
    pkg = _make_pkg(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any("base64" in f.title.lower() or "encoded" in f.title.lower() for f in findings)


def test_high_entropy_string(tmp_path):
    # Mix of all character classes → high entropy
    import random
    import string
    random.seed(42)
    chars = string.printable[:95]
    high_entropy = "".join(random.choices(chars, k=128))
    # Escape backslashes so the generated code is valid Python
    high_entropy = high_entropy.replace("\\", "\\\\").replace('"', '\\"')
    code = f'SECRET = "{high_entropy}"\n'
    pkg = _make_pkg(tmp_path, code)
    findings = scanner.scan(pkg)
    # May or may not trigger depending on exact entropy; just ensure no crash
    assert isinstance(findings, list)


def test_marshal_loads_chain(tmp_path):
    code = "import marshal\nexec(marshal.loads(b'\\x00' * 10))\n"
    pkg = _make_pkg(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.DANGER for f in findings)


def test_large_base64_with_safe_variable_name_not_flagged(tmp_path):
    """A large base64 constant assigned to a 'font'-style name should be skipped."""
    b64 = "A" * 596 + "AA=="
    code = f'FONT_DATA = "{b64}"\n'
    pkg = _make_pkg(tmp_path, code)
    findings = scanner.scan(pkg)
    assert not any("base64" in f.title.lower() for f in findings)


def test_high_entropy_standalone_not_flagged(tmp_path):
    """A high-entropy string alone should NOT produce a finding (co-occurrence required)."""
    import random, string
    random.seed(42)
    chars = string.printable[:95]
    s = "".join(random.choices(chars, k=200))
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    code = f'SECRET = "{s}"\n'
    pkg = _make_pkg(tmp_path, code)
    findings = scanner.scan(pkg)
    assert findings == []


def test_high_entropy_with_decode_chain_is_flagged(tmp_path):
    """A high-entropy string in a file that also has a decode-exec chain should be flagged."""
    import random, string
    random.seed(99)
    chars = string.printable[:95]
    s = "".join(random.choices(chars, k=200))
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    code = (
        f'import base64\n'
        f'exec(base64.b64decode("aW1wb3J0IG9z"))\n'
        f'SECRET = "{s}"\n'
    )
    pkg = _make_pkg(tmp_path, code)
    findings = scanner.scan(pkg)
    # The decode-exec chain must be flagged
    assert any(f.severity == Severity.DANGER for f in findings)


def _make_test_pkg(tmp_path: Path, code: str) -> PackageFiles:
    f = tmp_path / "pkg" / "tests" / "test_vectors.py"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(code)
    return PackageFiles(
        name="pkg", version="0.1.0",
        source_dir=tmp_path, python_files=[f],
    )


def test_encoded_constants_in_test_file_not_flagged(tmp_path):
    """Base64 constants inside test files should be skipped entirely."""
    b64 = "A" * 596 + "AA=="
    code = f'payload = "{b64}"\n'  # 'payload' name would normally trigger it
    pkg = _make_test_pkg(tmp_path, code)
    findings = scanner.scan(pkg)
    assert not any("base64" in f.title.lower() for f in findings)


def test_decode_chain_in_test_file_still_danger(tmp_path):
    """decode-exec chains must be flagged even inside test files."""
    code = "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n"
    pkg = _make_test_pkg(tmp_path, code)
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.DANGER for f in findings)
