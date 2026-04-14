"""Detect and invoke the available package installer (pip, uv, conda, poetry, etc.)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from enum import Enum
from typing import Optional


class InstallerType(str, Enum):
    PIP = "pip"
    UV = "uv"
    CONDA = "conda"
    MAMBA = "mamba"
    POETRY = "poetry"
    PIPENV = "pipenv"
    PDM = "pdm"
    UNKNOWN = "unknown"


def detect_installer() -> InstallerType:
    """
    Auto-detect the most appropriate installer in the current environment.

    Priority order:
      1. SENTRO_INSTALLER env var (explicit override)
      2. uv  (if in a uv-managed venv or uv is on PATH)
      3. conda / mamba (if CONDA_DEFAULT_ENV or CONDA_PREFIX is set)
      4. poetry (if pyproject.toml has [tool.poetry] and poetry is on PATH)
      5. pipenv (if Pipfile exists and pipenv is on PATH)
      6. pdm (if pyproject.toml has [tool.pdm] and pdm is on PATH)
      7. pip (always available as fallback)
    """
    # Explicit override
    override = os.environ.get("SENTRO_INSTALLER", "").lower()
    if override:
        for inst in InstallerType:
            if inst.value == override:
                return inst

    # uv: check UV_PROJECT_ENVIRONMENT or if uv binary exists
    if shutil.which("uv") and (
        os.environ.get("UV_PROJECT_ENVIRONMENT")
        or os.environ.get("VIRTUAL_ENV", "").endswith(".venv")
        or _uv_active()
    ):
        return InstallerType.UV

    # conda/mamba
    if os.environ.get("CONDA_DEFAULT_ENV") or os.environ.get("CONDA_PREFIX"):
        if shutil.which("mamba"):
            return InstallerType.MAMBA
        if shutil.which("conda"):
            return InstallerType.CONDA

    # poetry
    if shutil.which("poetry") and _has_poetry_pyproject():
        return InstallerType.POETRY

    # pipenv
    if shutil.which("pipenv") and _has_pipfile():
        return InstallerType.PIPENV

    # pdm
    if shutil.which("pdm") and _has_pdm_pyproject():
        return InstallerType.PDM

    # uv available but not in a managed venv — still prefer it over pip
    if shutil.which("uv"):
        return InstallerType.UV

    return InstallerType.PIP


def _uv_active() -> bool:
    """Return True if the current Python was invoked by uv."""
    return "uv" in sys.executable.lower() or bool(os.environ.get("UV_PYTHON"))


def _has_poetry_pyproject() -> bool:
    from pathlib import Path
    pp = Path.cwd() / "pyproject.toml"
    if not pp.exists():
        return False
    try:
        import sys
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib  # type: ignore
        with open(pp, "rb") as f:
            data = tomllib.load(f)
        return "poetry" in data.get("tool", {})
    except Exception:
        return False


def _has_pipfile() -> bool:
    from pathlib import Path
    return (Path.cwd() / "Pipfile").exists()


def _has_pdm_pyproject() -> bool:
    from pathlib import Path
    pp = Path.cwd() / "pyproject.toml"
    if not pp.exists():
        return False
    try:
        import sys
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib  # type: ignore
        with open(pp, "rb") as f:
            data = tomllib.load(f)
        return "pdm" in data.get("tool", {})
    except Exception:
        return False


def build_install_command(
    installer: InstallerType,
    packages: list[str],
    extra_args: list[str] | None = None,
) -> list[str]:
    """Build the install command for the given installer type."""
    extra = extra_args or []

    if installer == InstallerType.UV:
        return ["uv", "pip", "install"] + packages + extra

    elif installer == InstallerType.CONDA:
        return ["conda", "install", "--yes"] + packages + extra

    elif installer == InstallerType.MAMBA:
        return ["mamba", "install", "--yes"] + packages + extra

    elif installer == InstallerType.POETRY:
        # poetry add for new deps; poetry only supports one package at a time per add
        cmds = []
        for pkg in packages:
            cmds.extend(["poetry", "add", pkg])
        # Return just the first command — caller loops for multi-package
        if packages:
            return ["poetry", "add"] + packages + extra
        return ["poetry", "add"] + extra

    elif installer == InstallerType.PIPENV:
        return ["pipenv", "install"] + packages + extra

    elif installer == InstallerType.PDM:
        return ["pdm", "add"] + packages + extra

    else:  # pip
        return [sys.executable, "-m", "pip", "install"] + packages + extra


def run_installer(
    installer: InstallerType,
    packages: list[str],
    extra_args: list[str] | None = None,
) -> int:
    """Run the install command and return the exit code."""
    cmd = build_install_command(installer, packages, extra_args)
    result = subprocess.run(cmd)
    return result.returncode
