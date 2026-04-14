"""Configuration loading with multi-source merge chain."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class Config:
    strict: bool = False
    thresholds: dict = field(default_factory=lambda: {"warning": 30, "danger": 70})
    whitelist_packages: list[str] = field(default_factory=list)
    scanners_enabled: list[str] = field(default_factory=list)   # empty = all enabled
    scanners_disabled: list[str] = field(default_factory=list)
    pypi_timeout: int = 10
    prefer_wheel: bool = True
    output_format: str = "text"


def load_config(
    cli_overrides: Optional[dict[str, Any]] = None,
    config_file: Optional[Path] = None,
) -> Config:
    """
    Merge chain (lowest → highest priority):
      1. Built-in defaults
      2. ~/.config/sentro/config.toml
      3. pyproject.toml [tool.sentro] in cwd
      4. .sentro.toml in cwd
      5. Explicit --config path
      6. SENTRO_* environment variables
      7. CLI flags
    """
    merged: dict[str, Any] = {}

    # 2. User-level config
    user_cfg = Path.home() / ".config" / "sentro" / "config.toml"
    if user_cfg.exists():
        merged.update(_load_toml_section(user_cfg))

    # 3. pyproject.toml in cwd
    cwd_pyproject = Path.cwd() / "pyproject.toml"
    if cwd_pyproject.exists():
        merged.update(_load_toml_section(cwd_pyproject, "sentro"))

    # 4. .sentro.toml in cwd
    cwd_sentro = Path.cwd() / ".sentro.toml"
    if cwd_sentro.exists():
        merged.update(_load_toml_section(cwd_sentro))

    # 5. Explicit config file
    if config_file is not None:
        merged.update(_load_toml_section(Path(config_file)))

    # 6. Environment variables
    merged.update(_apply_env_overrides())

    # 7. CLI flags (only non-None values)
    if cli_overrides:
        for k, v in cli_overrides.items():
            if v is not None:
                merged[k] = v

    return _build_config(merged)


def _load_toml_section(path: Path, section: str = "sentro") -> dict[str, Any]:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        # Support [tool.sentro] and [sentro]
        tool_section = data.get("tool", {}).get(section, {})
        top_section = data.get(section, {})
        result = {}
        result.update(top_section)
        result.update(tool_section)
        return result
    except Exception:
        return {}


def _apply_env_overrides() -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    if os.environ.get("SENTRO_STRICT", "").lower() in ("1", "true", "yes"):
        overrides["strict"] = True
    if val := os.environ.get("SENTRO_DANGER_THRESHOLD"):
        try:
            overrides.setdefault("thresholds", {})["danger"] = int(val)
        except ValueError:
            pass
    if val := os.environ.get("SENTRO_WARNING_THRESHOLD"):
        try:
            overrides.setdefault("thresholds", {})["warning"] = int(val)
        except ValueError:
            pass
    if val := os.environ.get("SENTRO_WHITELIST"):
        overrides["whitelist_packages"] = [p.strip() for p in val.split(",") if p.strip()]
    if val := os.environ.get("SENTRO_OUTPUT_FORMAT"):
        overrides["output_format"] = val
    return overrides


def _build_config(data: dict[str, Any]) -> Config:
    cfg = Config()
    if "strict" in data:
        cfg.strict = bool(data["strict"])
    if "thresholds" in data:
        cfg.thresholds.update(data["thresholds"])
    if "whitelist_packages" in data:
        cfg.whitelist_packages = list(data["whitelist_packages"])
    if "scanners_enabled" in data:
        cfg.scanners_enabled = list(data["scanners_enabled"])
    if "scanners_disabled" in data:
        cfg.scanners_disabled = list(data["scanners_disabled"])
    if "pypi_timeout" in data:
        cfg.pypi_timeout = int(data["pypi_timeout"])
    if "prefer_wheel" in data:
        cfg.prefer_wheel = bool(data["prefer_wheel"])
    if "output_format" in data:
        cfg.output_format = str(data["output_format"])
    return cfg
