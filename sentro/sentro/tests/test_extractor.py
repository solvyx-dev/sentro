"""Tests for extraction modules."""

from __future__ import annotations

import io
import zipfile
import tarfile

import pytest

from sentro.extraction.extractor import extract_package
from sentro.extraction.wheel_extractor import PathTraversalError, WheelExtractor


def test_wheel_extraction(safe_wheel, tmp_path):
    pkg = extract_package(safe_wheel, tmp_path / "extracted")
    assert pkg.name == "safe_pkg"
    assert pkg.version == "1.0.0"
    assert len(pkg.python_files) >= 1


def test_wheel_finds_python_files(safe_wheel, tmp_path):
    pkg = extract_package(safe_wheel, tmp_path / "extracted")
    names = [f.name for f in pkg.python_files]
    assert "__init__.py" in names


def test_sdist_extraction(safe_sdist, tmp_path):
    pkg = extract_package(safe_sdist, tmp_path / "extracted")
    assert pkg.name == "safe_sdist"
    assert pkg.version == "1.0.0"
    assert pkg.setup_py is not None


def test_wheel_path_traversal_blocked(tmp_path):
    evil_whl = tmp_path / "evil-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(evil_whl, "w") as zf:
        zf.writestr("../../../etc/passwd", "root:x:0:0\n")
    with pytest.raises(PathTraversalError):
        WheelExtractor().extract(evil_whl, tmp_path / "out")


def test_wheel_no_python_files(tmp_path):
    empty_whl = tmp_path / "empty-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(empty_whl, "w") as zf:
        zf.writestr("METADATA", "Name: empty\nVersion: 1.0.0\n")
    pkg = extract_package(empty_whl, tmp_path / "out")
    assert pkg.python_files == []
