"""PyPI JSON API and pypistats client (stdlib urllib only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Optional

from .._version import __version__

_USER_AGENT = f"sentro/{__version__} (security scanner)"


class PackageNotFoundError(Exception):
    """Raised when a package does not exist on PyPI."""


class PyPIClient:
    PYPI_BASE = "https://pypi.org/pypi"
    STATS_BASE = "https://pypistats.org/api/packages"

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def get_package_metadata(self, name: str, version: Optional[str] = None) -> dict:
        """
        Fetch package metadata from PyPI.
        Returns the full JSON response dict.
        Raises PackageNotFoundError on 404.
        """
        if version:
            url = f"{self.PYPI_BASE}/{name}/{version}/json"
        else:
            url = f"{self.PYPI_BASE}/{name}/json"

        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise PackageNotFoundError(
                    f"Package '{name}' not found on PyPI."
                ) from exc
            raise

    def get_download_stats(self, name: str) -> dict:
        """
        Fetch recent download stats from pypistats.org.
        Returns {"last_day": int, "last_week": int, "last_month": int}.
        Returns empty dict on any failure (non-critical data).
        """
        url = f"{self.STATS_BASE}/{name}/recent"
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
            return data.get("data", {})
        except Exception:
            return {}

    def resolve_download_urls(
        self,
        name: str,
        version: Optional[str] = None,
        prefer_wheel: bool = True,
    ) -> list[dict]:
        """
        Return a sorted list of file dicts from PyPI.
        Each dict has: filename, url, packagetype, digests (sha256), size.
        Wheels are returned first when prefer_wheel=True.
        """
        metadata = self.get_package_metadata(name, version)
        urls: list[dict] = metadata.get("urls", [])

        if prefer_wheel:
            wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel"]
            sdists = [u for u in urls if u.get("packagetype") == "sdist"]
            return wheels + sdists
        else:
            sdists = [u for u in urls if u.get("packagetype") == "sdist"]
            wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel"]
            return sdists + wheels
