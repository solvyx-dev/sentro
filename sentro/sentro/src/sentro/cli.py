"""CLI entry point."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from ._version import __version__
from .config import load_config
from .installer import InstallerType, detect_installer
from .models import RiskLevel
from .orchestrator import ScanOrchestrator
from .reporting.reporter import render_report

_console = Console(stderr=True)


@click.group()
@click.version_option(__version__, prog_name="sentro")
def cli() -> None:
    """sentro: pip with a security conscience.

    Scans Python packages for malicious code before installing them.
    Detects typosquatting, obfuscated payloads, malicious install hooks,
    dependency confusion, and more.
    """


@cli.command(
    name="install",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("packages", nargs=-1, required=False)
@click.option(
    "-r",
    "--requirements",
    "requirements_file",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Scan and install packages from a requirements.txt file.",
)
@click.option(
    "--strict",
    is_flag=True,
    envvar="SENTRO_STRICT",
    help="Block installation if any package scores DANGER.",
)
@click.option(
    "--no-install",
    is_flag=True,
    help="Scan only — do not invoke the package installer.",
)
@click.option(
    "--skip-scan",
    is_flag=True,
    help="Skip all scanning and forward directly to the installer.",
)
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default=None,
    envvar="SENTRO_OUTPUT_FORMAT",
    help="Output format for the scan report.",
)
@click.option(
    "--installer",
    type=click.Choice(["pip", "uv", "conda", "mamba", "poetry", "pipenv", "pdm", "auto"]),
    default="auto",
    envvar="SENTRO_INSTALLER",
    help="Package installer to use after scanning. Defaults to auto-detect.",
    show_default=True,
)
@click.option(
    "--config",
    "config_file",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to a TOML config file.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    envvar="SENTRO_VERBOSE",
    help="Show detailed findings and progress during scanning/installation.",
)
@click.pass_context
def install_cmd(
    ctx: click.Context,
    packages: tuple[str, ...],
    requirements_file: Optional[Path],
    strict: bool,
    no_install: bool,
    skip_scan: bool,
    output_format: Optional[str],
    installer: str,
    config_file: Optional[Path],
    verbose: bool,
) -> None:
    """Install PACKAGES after scanning them for malicious code.

    Unknown options (e.g. --index-url, --constraint) are forwarded to the
    package installer verbatim.

    Examples:

      sentro install requests

      sentro install requests==2.28.0 --strict

      sentro install -r requirements.txt

      sentro install numpy --no-install --output-format json

      sentro install mypackage --installer uv
    """
    cli_overrides = {}
    if strict:
        cli_overrides["strict"] = True
    if output_format:
        cli_overrides["output_format"] = output_format
    if verbose:
        cli_overrides["verbose"] = True

    config = load_config(cli_overrides=cli_overrides, config_file=config_file)

    # Build full package list (CLI args + requirements file)
    all_packages = list(packages)
    if requirements_file:
        all_packages.extend(_parse_requirements(requirements_file))

    if not all_packages:
        _console.print("[red]Error: no packages specified. Pass package names or use -r requirements.txt[/red]")
        sys.exit(1)

    if config.verbose:
        _console.print(f"[dim]Packages to process:[/dim] {', '.join(all_packages)}")

    # Resolve installer
    if skip_scan:
        resolved_installer = _resolve_installer(installer)
        rc = _forward_to_installer(resolved_installer, all_packages, ctx.args, verbose=config.verbose)
        sys.exit(rc)

    orchestrator = ScanOrchestrator(config=config)
    out_console = Console()

    blocked = False
    scanned_packages: list[str] = []

    for idx, package_spec in enumerate(all_packages, 1):
        name, _, version = package_spec.partition("==")
        name = name.strip()
        version = version.strip() or None

        if config.verbose:
            _console.print(
                f"[dim][{idx}/{len(all_packages)}] Scanning[/dim] [bold]{package_spec}[/bold]...",
                highlight=False,
            )
        else:
            _console.print(f"[dim]Scanning[/dim] [bold]{package_spec}[/bold]...", highlight=False)

        try:
            report = orchestrator.scan_package(name, version)
        except Exception as exc:
            _console.print(f"[red]Error scanning {package_spec}: {exc}[/red]")
            if config.strict:
                sys.exit(2)
            continue

        if config.verbose:
            _console.print(
                f"[dim]  → {len(report.findings)} finding(s), risk={report.risk_level(config.thresholds).value} "
                f"(score {report.risk_score})[/dim]",
                highlight=False,
            )

        render_report(report, config, console=out_console)

        level = report.risk_level(config.thresholds)
        if level == RiskLevel.DANGER and config.strict:
            blocked = True
        else:
            scanned_packages.append(package_spec)

    if blocked:
        _console.print(
            "[bold red]Installation BLOCKED[/bold red] — one or more packages scored DANGER "
            "and --strict mode is enabled."
        )
        sys.exit(1)

    if no_install:
        if config.verbose:
            _console.print("[dim]--no-install set; skipping installation.[/dim]")
        sys.exit(0)

    # Determine which installer to use
    resolved_installer = _resolve_installer(installer)
    _console.print(
        f"[dim]Installing via[/dim] [bold]{resolved_installer.value}[/bold]..."
    )

    packages_to_install = all_packages  # install all, including warned ones
    rc = _forward_to_installer(resolved_installer, packages_to_install, ctx.args, verbose=config.verbose)
    sys.exit(rc)


@cli.command(name="detect-installer")
def detect_installer_cmd() -> None:
    """Show which package installer would be used automatically."""
    inst = detect_installer()
    click.echo(f"Detected installer: {inst.value}")


def _resolve_installer(installer_str: str) -> InstallerType:
    if installer_str == "auto":
        return detect_installer()
    for inst in InstallerType:
        if inst.value == installer_str:
            return inst
    return InstallerType.PIP


def _parse_requirements(path: Path) -> list[str]:
    """Parse a requirements.txt file and return a list of package specs."""
    packages = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        # Skip empty lines, comments, and options like --index-url
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip inline comments
        line = line.split("#")[0].strip()
        if line:
            packages.append(line)
    return packages


def _forward_to_installer(
    installer: InstallerType,
    packages: list[str],
    extra_args: list[str],
    verbose: bool = False,
) -> int:
    from .installer import build_install_command
    import subprocess
    cmd = build_install_command(installer, packages, extra_args)
    if verbose:
        _console.print(f"[dim]Running installer command:[/dim] {' '.join(cmd)}")
        return subprocess.run(cmd).returncode
    # Suppress installer output unless it fails; stream stderr for progress feedback
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        if result.stderr:
            _console.print(result.stderr)
        if result.stdout:
            _console.print(result.stdout)
    return result.returncode
