"""Extract .tar.gz / .zip sdist files into a temp directory."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

from ..models import PackageFiles


class PathTraversalError(Exception):
    """Raised when an archive entry attempts path traversal."""


class SDistExtractor:
    def extract(self, sdist_path: Path, dest_dir: Path) -> PackageFiles:
        dest_dir.mkdir(parents=True, exist_ok=True)
        name_str = sdist_path.name

        if name_str.endswith(".tar.gz") or name_str.endswith(".tgz"):
            name, version = _parse_sdist_name(name_str)
            _extract_tarball(sdist_path, dest_dir)
        elif name_str.endswith(".zip"):
            name, version = _parse_sdist_name(name_str)
            _extract_zip(sdist_path, dest_dir)
        else:
            name, version = _parse_sdist_name(name_str)
            _extract_tarball(sdist_path, dest_dir)

        return _build_package_files(name, version, dest_dir)


def _parse_sdist_name(filename: str) -> tuple[str, str]:
    for suffix in (".tar.gz", ".tgz", ".zip"):
        if filename.endswith(suffix):
            stem = filename[: -len(suffix)]
            break
    else:
        stem = filename
    parts = stem.rsplit("-", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return stem, "unknown"


def _guard_tar_member(member: tarfile.TarInfo) -> bool:
    """Return True if safe, False to skip."""
    name = member.name
    if name.startswith("/") or name.startswith("\\"):
        return False
    normalized = Path(name)
    if ".." in normalized.parts:
        return False
    return True


def _extract_tarball(path: Path, dest: Path) -> None:
    if sys.version_info >= (3, 12):
        with tarfile.open(path, "r:gz") as tf:
            tf.extractall(dest, filter="data")
    else:
        with tarfile.open(path, "r:gz") as tf:
            safe_members = [m for m in tf.getmembers() if _guard_tar_member(m)]
            tf.extractall(dest, members=safe_members)


def _extract_zip(path: Path, dest: Path) -> None:
    with zipfile.ZipFile(path, "r") as zf:
        for member in zf.infolist():
            parts = Path(member.filename).parts
            if any(p in ("..", "") for p in parts) or Path(member.filename).is_absolute():
                raise PathTraversalError(f"Unsafe path in zip: {member.filename!r}")
        zf.extractall(dest)


def _build_package_files(name: str, version: str, root: Path) -> PackageFiles:
    python_files = [p for p in root.rglob("*.py") if p.name != "setup.py"]
    setup_py_candidates = list(root.rglob("setup.py"))
    setup_py = setup_py_candidates[0] if setup_py_candidates else None
    pyproject_candidates = list(root.rglob("pyproject.toml"))
    pyproject_toml = pyproject_candidates[0] if pyproject_candidates else None
    return PackageFiles(
        name=name,
        version=version,
        source_dir=root,
        python_files=python_files,
        setup_py=setup_py,
        pyproject_toml=pyproject_toml,
    )
