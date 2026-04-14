"""BaseScanner ABC and auto-registration registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import Config
    from ..models import Finding, PackageFiles

SCANNER_REGISTRY: dict[str, type["BaseScanner"]] = {}


class BaseScanner(ABC):
    name: str = ""
    description: str = ""
    default_enabled: bool = True

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if cls.name:
            SCANNER_REGISTRY[cls.name] = cls

    @abstractmethod
    def scan(self, package: "PackageFiles") -> list["Finding"]:
        """Run all checks; return zero or more Finding objects."""

    def is_enabled(self, config: "Config") -> bool:
        if self.name in config.scanners_disabled:
            return False
        if config.scanners_enabled and self.name not in config.scanners_enabled:
            return False
        return self.default_enabled


def get_all_scanners() -> list[BaseScanner]:
    """Instantiate and return one of each registered scanner."""
    # Import side-effects register all scanners
    from . import (  # noqa: F401
        dependency_confusion,
        malicious_code,
        metadata,
        obfuscation,
        setup_hooks,
        typosquatting,
    )
    return [cls() for cls in SCANNER_REGISTRY.values()]
