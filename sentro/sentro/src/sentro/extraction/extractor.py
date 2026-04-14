"""Dispatcher: detect archive type and delegate to the correct extractor."""

from __future__ import annotations

from pathlib import Path

from ..models import PackageFiles
from .sdist_extractor import SDistExtractor
from .wheel_extractor import WheelExtractor


def extract_package(archive_path: Path, dest_dir: Path) -> PackageFiles:
    """
    Detect whether archive_path is a wheel or sdist and extract accordingly.
    Returns a populated PackageFiles.
    """
    name = archive_path.name
    if name.endswith(".whl"):
        return WheelExtractor().extract(archive_path, dest_dir)
    elif name.endswith((".tar.gz", ".tgz", ".zip")):
        return SDistExtractor().extract(archive_path, dest_dir)
    else:
        # Best-effort: try tarball first, then zip
        try:
            return SDistExtractor().extract(archive_path, dest_dir)
        except Exception:
            return WheelExtractor().extract(archive_path, dest_dir)
