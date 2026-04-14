"""Top-level scan orchestration: ties together PyPI, download, extraction, and scanning."""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import Config
from .installer import InstallerType, detect_installer, run_installer
from .models import PackageFiles, RiskLevel, ScanReport
from .pypi.client import PackageNotFoundError, PyPIClient
from .pypi.downloader import PackageDownloader
from .extraction.extractor import extract_package
from .scanners.base import BaseScanner, get_all_scanners


class ScannerPipeline:
    def __init__(self, scanners: list[BaseScanner]) -> None:
        self.scanners = scanners

    def run(self, package: PackageFiles, config: Config) -> list:
        findings = []
        for scanner in self.scanners:
            if scanner.is_enabled(config):
                findings.extend(scanner.scan(package))
        return findings


def _compute_package_age_days(pypi_data: dict) -> int | None:
    releases = pypi_data.get("releases", {})
    upload_times: list[datetime] = []
    for version_files in releases.values():
        for file_info in version_files:
            upload_time_str = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
            if upload_time_str:
                try:
                    ts = upload_time_str.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(ts)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    upload_times.append(dt)
                except ValueError:
                    pass
    if not upload_times:
        return None
    oldest = min(upload_times)
    now = datetime.now(tz=timezone.utc)
    return (now - oldest).days


def _compute_reputation_discount(pypi_data: dict, download_stats: dict) -> float:
    """Return a score discount for well-established packages.

    New / low-download packages get no discount (1.0).
    Established packages get a discount so that minor code-pattern
    warnings (e.g. a few eval() calls) do not trigger false-positive WARNING.
    Real DANGER findings bypass the discount in ScanReport.risk_score.
    """
    age_days = _compute_package_age_days(pypi_data)
    last_month = download_stats.get("last_month") if download_stats else None
    if last_month is None:
        last_month = 0

    if age_days is None:
        return 1.0

    # Very established packages: deep discount
    if last_month > 50_000 and age_days > 365:
        return 0.25
    # Established packages
    if last_month > 10_000 and age_days > 90:
        return 0.5
    # Moderately established
    if last_month > 1_000 and age_days > 30:
        return 0.75

    return 1.0


class ScanOrchestrator:
    def __init__(
        self,
        config: Config,
        pypi_client: Optional[PyPIClient] = None,
        scanners: Optional[list[BaseScanner]] = None,
    ) -> None:
        self.config = config
        self._pypi = pypi_client or PyPIClient(timeout=config.pypi_timeout)
        self._scanners = scanners if scanners is not None else get_all_scanners()
        self._pipeline = ScannerPipeline(self._scanners)

    def scan_package(
        self,
        name: str,
        version: Optional[str] = None,
    ) -> ScanReport:
        # 1. Whitelist check
        normalized = name.lower().replace("-", "_")
        if normalized in {p.lower().replace("-", "_") for p in self.config.whitelist_packages}:
            return ScanReport(
                package_name=name,
                package_version=version or "any",
                pypi_verified=True,
                findings=[],
            )

        # 2. PyPI metadata
        pypi_metadata: dict = {}
        pypi_verified = False
        try:
            pypi_metadata = self._pypi.get_package_metadata(name, version)
            pypi_verified = True
        except PackageNotFoundError:
            pass
        except Exception:
            pass

        # 3. Download stats (non-blocking)
        download_stats: dict = {}
        if pypi_verified:
            try:
                download_stats = self._pypi.get_download_stats(name)
            except Exception:
                pass

        # 4. Resolve download URLs
        try:
            urls = self._pypi.resolve_download_urls(
                name, version, prefer_wheel=self.config.prefer_wheel
            )
        except Exception:
            urls = []

        # 5 & 6. Download + extract
        with tempfile.TemporaryDirectory(prefix="sentro-") as tmpdir:
            tmp_path = Path(tmpdir)
            package_files: Optional[PackageFiles] = None

            if urls:
                file_info = urls[0]
                url = file_info.get("url", "")
                sha256 = file_info.get("digests", {}).get("sha256", "")
                filename = file_info.get("filename", "package.whl")

                try:
                    downloader = PackageDownloader(tmp_dir=tmp_path / "download", timeout=self.config.pypi_timeout)
                    (tmp_path / "download").mkdir(parents=True, exist_ok=True)
                    archive_path = downloader.download(url, sha256, filename)
                    extract_dir = tmp_path / "extracted"
                    package_files = extract_package(archive_path, extract_dir)
                except Exception:
                    package_files = None

            if package_files is None:
                # Create minimal PackageFiles for metadata-only scanning
                pkg_version = version or (pypi_metadata.get("info", {}).get("version") or "unknown")
                package_files = PackageFiles(
                    name=name,
                    version=pkg_version,
                    source_dir=tmp_path,
                    python_files=[],
                )

            # 7. Attach metadata
            package_files.pypi_metadata = pypi_metadata
            package_files.download_stats = download_stats

            # 8. Run scanner pipeline
            findings = self._pipeline.run(package_files, self.config)

        pkg_version = package_files.version
        if not pkg_version or pkg_version == "unknown":
            pkg_version = pypi_metadata.get("info", {}).get("version") or version or "unknown"

        reputation_discount = _compute_reputation_discount(pypi_metadata, download_stats)
        age_days = _compute_package_age_days(pypi_metadata)

        return ScanReport(
            package_name=name,
            package_version=pkg_version,
            pypi_verified=pypi_verified,
            findings=findings,
            reputation_discount=reputation_discount,
            age_days=age_days,
            download_stats=download_stats,
        )

    def install_packages(
        self,
        packages: list[str],
        installer: Optional[InstallerType] = None,
        extra_pip_args: Optional[list[str]] = None,
    ) -> int:
        if installer is None:
            installer = detect_installer()
        return run_installer(installer, packages, extra_pip_args)
