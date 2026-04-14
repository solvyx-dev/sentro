"""Scanner: analyze PyPI metadata for risk signals."""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import Finding, PackageFiles, Severity
from .base import BaseScanner

_NEW_PACKAGE_DANGER_DAYS = 7
_NEW_PACKAGE_WARNING_DAYS = 30
_LOW_DOWNLOAD_THRESHOLD = 100  # last month


class MetadataScanner(BaseScanner):
    name = "metadata"
    description = "Checks package age, download count, and completeness of metadata"

    def scan(self, package: PackageFiles) -> list[Finding]:
        if not package.pypi_metadata:
            return []

        findings: list[Finding] = []
        info = package.pypi_metadata.get("info", {})
        releases = package.pypi_metadata.get("releases", {})

        findings.extend(self._check_package_age(package.pypi_metadata))
        findings.extend(self._check_download_count(package.download_stats))
        findings.extend(self._check_single_release(releases))
        findings.extend(self._check_missing_metadata(info))
        return findings

    def _check_package_age(self, pypi_data: dict) -> list[Finding]:
        """Check age based on oldest release upload time."""
        releases = pypi_data.get("releases", {})
        upload_times: list[datetime] = []
        for version_files in releases.values():
            for file_info in version_files:
                upload_time_str = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
                if upload_time_str:
                    try:
                        # Handle both ISO 8601 with Z and without
                        ts = upload_time_str.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(ts)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        upload_times.append(dt)
                    except ValueError:
                        pass

        if not upload_times:
            return []

        oldest = min(upload_times)
        now = datetime.now(tz=timezone.utc)
        age_days = (now - oldest).days

        if age_days < _NEW_PACKAGE_DANGER_DAYS:
            return [Finding(
                scanner=self.name,
                severity=Severity.DANGER,
                title=f"Package is only {age_days} day(s) old",
                detail=(
                    f"This package was first published {age_days} day(s) ago. "
                    "Very new packages have not been vetted by the community and "
                    "are frequently used in typosquatting campaigns."
                ),
                score=40,
            )]
        elif age_days < _NEW_PACKAGE_WARNING_DAYS:
            return [Finding(
                scanner=self.name,
                severity=Severity.WARNING,
                title=f"Package is only {age_days} days old",
                detail=(
                    f"This package was first published {age_days} days ago. "
                    "New packages have limited community vetting."
                ),
                score=20,
            )]
        return []

    def _check_download_count(self, stats: dict) -> list[Finding]:
        if not stats:
            return []
        last_month = stats.get("last_month", 0)
        if last_month is None:
            return []
        if last_month < _LOW_DOWNLOAD_THRESHOLD:
            return [Finding(
                scanner=self.name,
                severity=Severity.WARNING,
                title=f"Very low download count: {last_month:,} downloads last month",
                detail=(
                    f"This package has only {last_month:,} downloads in the last month. "
                    "Low-traffic packages haven't been reviewed by many users and may carry higher risk."
                ),
                score=15,
            )]
        return []

    def _check_single_release(self, releases: dict) -> list[Finding]:
        if len(releases) <= 1:
            return [Finding(
                scanner=self.name,
                severity=Severity.WARNING,
                title="Package has only one release",
                detail=(
                    "This package has never had more than one release. "
                    "Malicious packages are often created, used in an attack, and never updated."
                ),
                score=15,
            )]
        return []

    def _check_missing_metadata(self, info: dict) -> list[Finding]:
        has_author = bool(info.get("author") or info.get("author_email"))
        has_home = bool(info.get("home_page") or info.get("project_url") or info.get("project_urls"))
        has_summary = bool(info.get("summary"))

        if not has_author and not has_home and not has_summary:
            return [Finding(
                scanner=self.name,
                severity=Severity.WARNING,
                title="Package has no author, homepage, or description",
                detail=(
                    "This package has no author information, homepage, or description. "
                    "Legitimate packages almost always have at least some metadata. "
                    "Missing metadata is common in hastily created malicious packages."
                ),
                score=15,
            )]
        return []
