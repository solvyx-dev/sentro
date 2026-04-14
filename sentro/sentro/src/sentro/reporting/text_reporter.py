"""Rich-based terminal reporter."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from ..models import RiskLevel, ScanReport, Severity

_SEVERITY_COLORS = {
    Severity.INFO: "blue",
    Severity.WARNING: "yellow",
    Severity.DANGER: "red",
}

_RISK_COLORS = {
    RiskLevel.SAFE: "bold green",
    RiskLevel.WARNING: "bold yellow",
    RiskLevel.DANGER: "bold red",
}

_RISK_ICONS = {
    RiskLevel.SAFE: "[green]SAFE[/green]",
    RiskLevel.WARNING: "[yellow]WARNING[/yellow]",
    RiskLevel.DANGER: "[red]DANGER[/red]",
}


def render_text_report(
    report: ScanReport,
    thresholds: dict,
    console: Console | None = None,
) -> None:
    if console is None:
        console = Console()

    level = report.risk_level(thresholds)
    icon = _RISK_ICONS[level]

    header = (
        f"  Package : [bold]{report.package_name}[/bold] {report.package_version}\n"
        f"  PyPI    : {'[green]verified[/green]' if report.pypi_verified else '[red]NOT FOUND[/red]'}\n"
        f"  Risk    : {icon}  (score {report.risk_score}/100)"
    )

    panel_style = {
        RiskLevel.SAFE: "green",
        RiskLevel.WARNING: "yellow",
        RiskLevel.DANGER: "red",
    }[level]

    console.print(Panel(header, title="sentro scan", border_style=panel_style))

    if not report.findings:
        console.print("  [green]No issues found.[/green]\n")
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Scanner", width=22)
    table.add_column("Finding")
    table.add_column("File", width=28)
    table.add_column("Line", width=6, justify="right")

    for finding in sorted(report.findings, key=lambda f: _severity_order(f.severity)):
        color = _SEVERITY_COLORS[finding.severity]
        table.add_row(
            f"[{color}]{finding.severity.value}[/{color}]",
            finding.scanner,
            finding.title,
            finding.file_path or "",
            str(finding.line_number) if finding.line_number else "",
        )

    console.print(table)

    # Show code snippets for DANGER findings
    for finding in report.findings:
        if finding.severity == Severity.DANGER and finding.code_snippet:
            console.print(
                Panel(
                    f"[dim]{finding.file_path}:{finding.line_number}[/dim]\n"
                    f"[red]{finding.code_snippet}[/red]",
                    title=f"[red]{finding.title}[/red]",
                    border_style="red",
                )
            )

    console.print()


def _severity_order(s: Severity) -> int:
    return {Severity.DANGER: 0, Severity.WARNING: 1, Severity.INFO: 2}.get(s, 3)
