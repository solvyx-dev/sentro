"""Tests for the CLI."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from sentro.cli import cli
from sentro.models import Finding, RiskLevel, ScanReport, Severity


def _safe_report(name="requests"):
    return ScanReport(name, "2.31.0", True, [])


def _danger_report(name="evilpkg"):
    return ScanReport(
        name, "0.1.0", False,
        [Finding(scanner="malicious_code", severity=Severity.DANGER,
                 title="exec detected", detail="bad", score=80)],
    )


@pytest.fixture
def runner():
    return CliRunner()


def test_install_safe_package_exits_0(runner):
    with patch("sentro.cli.ScanOrchestrator") as MockOrch, \
         patch("sentro.cli._forward_to_installer", return_value=0):
        mock_inst = MockOrch.return_value
        mock_inst.scan_package.return_value = _safe_report()
        result = runner.invoke(cli, ["install", "requests"])
    assert result.exit_code == 0


def test_install_no_install_flag(runner):
    with patch("sentro.cli.ScanOrchestrator") as MockOrch:
        mock_inst = MockOrch.return_value
        mock_inst.scan_package.return_value = _safe_report()
        result = runner.invoke(cli, ["install", "requests", "--no-install"])
    assert result.exit_code == 0
    mock_inst.install_packages.assert_not_called()


def test_strict_mode_blocks_on_danger(runner):
    with patch("sentro.cli.ScanOrchestrator") as MockOrch:
        mock_inst = MockOrch.return_value
        mock_inst.scan_package.return_value = _danger_report()
        result = runner.invoke(cli, ["install", "evilpkg", "--strict", "--no-install"])
    assert result.exit_code == 1


def test_strict_mode_allows_safe_package(runner):
    with patch("sentro.cli.ScanOrchestrator") as MockOrch, \
         patch("sentro.cli._forward_to_installer", return_value=0):
        mock_inst = MockOrch.return_value
        mock_inst.scan_package.return_value = _safe_report()
        result = runner.invoke(cli, ["install", "requests", "--strict"])
    assert result.exit_code == 0


def test_output_format_json():
    # Separate stdout from stderr so the JSON is cleanly parseable
    separated_runner = CliRunner(mix_stderr=False)
    with patch("sentro.cli.ScanOrchestrator") as MockOrch:
        mock_inst = MockOrch.return_value
        mock_inst.scan_package.return_value = _safe_report()
        result = separated_runner.invoke(
            cli, ["install", "requests", "--output-format", "json", "--no-install"]
        )
    assert result.exit_code == 0
    import json
    data = json.loads(result.output)
    assert data["risk_level"] == "SAFE"


def test_skip_scan_forwards_to_installer(runner):
    with patch("sentro.cli._forward_to_installer", return_value=0) as mock_fwd:
        result = runner.invoke(cli, ["install", "requests", "--skip-scan"])
    assert result.exit_code == 0
    mock_fwd.assert_called_once()


def test_detect_installer_command(runner):
    result = runner.invoke(cli, ["detect-installer"])
    assert result.exit_code == 0
    assert "Detected installer" in result.output


def test_version_flag(runner):
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1" in result.output


def test_requirements_file_flag(runner, tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests\nclick\n# comment\n\n--index-url https://example.com\n")
    with patch("sentro.cli.ScanOrchestrator") as MockOrch:
        mock_inst = MockOrch.return_value
        mock_inst.scan_package.return_value = _safe_report()
        result = runner.invoke(cli, ["install", "-r", str(req_file), "--no-install"])
    assert result.exit_code == 0
    # Should scan exactly the two non-comment, non-option lines
    assert mock_inst.scan_package.call_count == 2
    calls = [c.args[0] for c in mock_inst.scan_package.call_args_list]
    assert "requests" in calls
    assert "click" in calls


def test_requirements_file_combined_with_packages(runner, tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("click\n")
    with patch("sentro.cli.ScanOrchestrator") as MockOrch:
        mock_inst = MockOrch.return_value
        mock_inst.scan_package.return_value = _safe_report()
        result = runner.invoke(cli, ["install", "requests", "-r", str(req_file), "--no-install"])
    assert result.exit_code == 0
    assert mock_inst.scan_package.call_count == 2


def test_no_packages_and_no_requirements_exits_1(runner):
    result = runner.invoke(cli, ["install"])
    assert result.exit_code == 1
