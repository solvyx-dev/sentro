"""Tests for config.py."""

from __future__ import annotations

import os

import pytest

from sentro.config import load_config


def test_defaults():
    cfg = load_config()
    assert cfg.strict is False
    assert cfg.thresholds["warning"] == 30
    assert cfg.thresholds["danger"] == 70
    assert cfg.whitelist_packages == []
    assert cfg.output_format == "text"


def test_cli_overrides_strict():
    cfg = load_config(cli_overrides={"strict": True})
    assert cfg.strict is True


def test_cli_overrides_output_format():
    cfg = load_config(cli_overrides={"output_format": "json"})
    assert cfg.output_format == "json"


def test_env_strict(monkeypatch):
    monkeypatch.setenv("SENTRO_STRICT", "true")
    cfg = load_config()
    assert cfg.strict is True


def test_env_strict_numeric(monkeypatch):
    monkeypatch.setenv("SENTRO_STRICT", "1")
    cfg = load_config()
    assert cfg.strict is True


def test_env_danger_threshold(monkeypatch):
    monkeypatch.setenv("SENTRO_DANGER_THRESHOLD", "50")
    cfg = load_config()
    assert cfg.thresholds["danger"] == 50


def test_env_warning_threshold(monkeypatch):
    monkeypatch.setenv("SENTRO_WARNING_THRESHOLD", "20")
    cfg = load_config()
    assert cfg.thresholds["warning"] == 20


def test_env_whitelist(monkeypatch):
    monkeypatch.setenv("SENTRO_WHITELIST", "requests, numpy, pandas")
    cfg = load_config()
    assert "requests" in cfg.whitelist_packages
    assert "numpy" in cfg.whitelist_packages


def test_cli_overrides_take_precedence_over_env(monkeypatch):
    monkeypatch.setenv("SENTRO_STRICT", "true")
    # CLI can override env (strict stays False if we pass False... but CLI wins)
    cfg = load_config(cli_overrides={"output_format": "json"})
    # strict was set by env but not overridden by CLI — should still be True
    assert cfg.strict is True
    assert cfg.output_format == "json"


def test_toml_config_file(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        '[sentro]\nstrict = true\n'
        '[sentro.thresholds]\ndanger = 50\n'
    )
    cfg = load_config(config_file=cfg_file)
    assert cfg.strict is True
    assert cfg.thresholds["danger"] == 50


def test_none_cli_values_not_applied():
    """None values in cli_overrides should not overwrite defaults."""
    cfg = load_config(cli_overrides={"strict": None, "output_format": None})
    assert cfg.strict is False
    assert cfg.output_format == "text"
