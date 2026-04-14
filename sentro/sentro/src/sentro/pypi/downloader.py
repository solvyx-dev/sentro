"""Package downloader with SHA-256 hash verification."""

from __future__ import annotations

import hashlib
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional

from .._version import __version__

_USER_AGENT = f"sentro/{__version__} (security scanner)"
_CHUNK = 65536  # 64 KiB read chunks


class HashMismatchError(Exception):
    """Raised when downloaded file hash does not match PyPI-provided hash."""


class DownloadError(Exception):
    """Raised on network or I/O failure during download."""


class PackageDownloader:
    def __init__(self, tmp_dir: Optional[Path] = None, timeout: int = 10) -> None:
        self.timeout = timeout
        self._managed = tmp_dir is None
        if self._managed:
            self._tmpdir_obj = tempfile.TemporaryDirectory(prefix="sentro-")
            self.tmp_dir = Path(self._tmpdir_obj.name)
        else:
            self.tmp_dir = tmp_dir  # type: ignore[assignment]
            self._tmpdir_obj = None

    def download(self, url: str, expected_sha256: str, filename: str) -> Path:
        """
        Stream-download url into tmp_dir/filename, verify SHA-256, return path.
        Raises HashMismatchError if hash doesn't match.
        Raises DownloadError on network failure.
        """
        dest = self.tmp_dir / filename
        hasher = hashlib.sha256()

        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                with open(dest, "wb") as fh:
                    while chunk := resp.read(_CHUNK):
                        fh.write(chunk)
                        hasher.update(chunk)
        except Exception as exc:
            raise DownloadError(f"Failed to download {url}: {exc}") from exc

        actual = hasher.hexdigest()
        if actual != expected_sha256:
            dest.unlink(missing_ok=True)
            raise HashMismatchError(
                f"SHA-256 mismatch for {filename}:\n"
                f"  expected: {expected_sha256}\n"
                f"  actual:   {actual}"
            )
        return dest

    def __enter__(self) -> "PackageDownloader":
        return self

    def __exit__(self, *_) -> None:
        if self._managed and self._tmpdir_obj is not None:
            self._tmpdir_obj.cleanup()
