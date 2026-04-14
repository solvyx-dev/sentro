"""Extract .whl (zip) files into a temp directory."""

from __future__ import annotations

import zipfile
from pathlib import Path

from ..models import PackageFiles


class PathTraversalError(Exception):
    """Raised when a zip entry attempts path traversal."""


class WheelExtractor:
    def extract(self, wheel_path: Path, dest_dir: Path) -> PackageFiles:
        name, version = _parse_wheel_name(wheel_path.name)
        dest_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(wheel_path, "r") as zf:
            for member in zf.infolist():
                _guard_path(member.filename)
            zf.extractall(dest_dir)

        return _build_package_files(name, version, dest_dir)


def _guard_path(filename: str) -> None:
    parts = Path(filename).parts
    if any(p in ("..", "") for p in parts) or Path(filename).is_absolute():
        raise PathTraversalError(f"Unsafe path in archive: {filename!r}")


def _parse_wheel_name(filename: str) -> tuple[str, str]:
    # Wheel filename format: {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
    stem = filename.removesuffix(".whl")
    parts = stem.split("-")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return stem, "unknown"


def _build_package_files(name: str, version: str, root: Path) -> PackageFiles:
    python_files = list(root.rglob("*.py"))
    setup_py = root / "setup.py"
    pyproject_toml = root / "pyproject.toml"
    return PackageFiles(
        name=name,
        version=version,
        source_dir=root,
        python_files=python_files,
        setup_py=setup_py if setup_py.exists() else None,
        pyproject_toml=pyproject_toml if pyproject_toml.exists() else None,
    )
