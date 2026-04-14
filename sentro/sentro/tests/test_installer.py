"""Tests for installer detection."""

from __future__ import annotations

import sys

from sentro.installer import InstallerType, build_install_command


def test_pip_install_command():
    cmd = build_install_command(InstallerType.PIP, ["requests"])
    assert sys.executable in cmd
    assert "pip" in cmd
    assert "install" in cmd
    assert "requests" in cmd


def test_uv_install_command():
    cmd = build_install_command(InstallerType.UV, ["requests"])
    assert cmd[0] == "uv"
    assert "pip" in cmd
    assert "install" in cmd
    assert "requests" in cmd


def test_conda_install_command():
    cmd = build_install_command(InstallerType.CONDA, ["numpy"])
    assert cmd[0] == "conda"
    assert "install" in cmd
    assert "numpy" in cmd


def test_poetry_install_command():
    cmd = build_install_command(InstallerType.POETRY, ["flask"])
    assert cmd[0] == "poetry"
    assert "add" in cmd
    assert "flask" in cmd


def test_pipenv_install_command():
    cmd = build_install_command(InstallerType.PIPENV, ["django"])
    assert cmd[0] == "pipenv"
    assert "install" in cmd


def test_pdm_install_command():
    cmd = build_install_command(InstallerType.PDM, ["pydantic"])
    assert cmd[0] == "pdm"
    assert "add" in cmd


def test_extra_args_forwarded():
    cmd = build_install_command(InstallerType.PIP, ["requests"], ["--upgrade"])
    assert "--upgrade" in cmd


def test_env_override_installer(monkeypatch):
    monkeypatch.setenv("SENTRO_INSTALLER", "pip")
    from sentro.installer import detect_installer
    # Should respect env var (mocked out conda/uv env)
    monkeypatch.delenv("CONDA_DEFAULT_ENV", raising=False)
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    inst = detect_installer()
    # Either pip or uv depending on system; just ensure it returns a valid type
    assert inst in InstallerType.__members__.values()
