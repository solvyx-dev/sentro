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
    verbose: bool = False,
) -> None:
    if console is None:
        console = Console()

    level = report.risk_level(thresholds)
    icon = _RISK_ICONS[level]

    header_lines = [
        f"  Package : [bold]{report.package_name}[/bold] {report.package_version}",
        f"  PyPI    : {'[green]verified[/green]' if report.pypi_verified else '[red]NOT FOUND[/red]'}",
        f"  Risk    : {icon}  (score {report.risk_score}/100)",
    ]

    if verbose:
        if report.age_days is not None:
            header_lines.append(f"  Age     : {report.age_days} day(s) old")
        last_month = report.download_stats.get("last_month")
        if last_month is not None:
            header_lines.append(f"  Downloads last month : {last_month:,}")
        if report.reputation_discount != 1.0:
            header_lines.append(f"  Reputation discount  : {report.reputation_discount:.0%}")

    panel_style = {
        RiskLevel.SAFE: "green",
        RiskLevel.WARNING: "yellow",
        RiskLevel.DANGER: "red",
    }[level]

    console.print(Panel("\n".join(header_lines), title="sentro scan", border_style=panel_style))

    if not report.findings:
        console.print("  [green]No issues found.[/green]\n")
        return

    # Verbose scanner summary table
    if verbose and report.scanner_summary:
        summary_table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        summary_table.add_column("Scanner", width=24)
        summary_table.add_column("INFO", width=6, justify="right")
        summary_table.add_column("WARNING", width=8, justify="right")
        summary_table.add_column("DANGER", width=7, justify="right")
        for scanner_name, counts in sorted(report.scanner_summary.items()):
            summary_table.add_row(
                scanner_name,
                str(counts.get("INFO", 0)) if counts.get("INFO", 0) else "-",
                f"[yellow]{counts.get('WARNING', 0)}[/yellow]" if counts.get("WARNING", 0) else "-",
                f"[red]{counts.get('DANGER', 0)}[/red]" if counts.get("DANGER", 0) else "-",
            )
        console.print(summary_table)
        console.print()

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Scanner", width=22)
    if verbose:
        table.add_column("Finding", width=30)
        table.add_column("Detail")
    else:
        table.add_column("Finding")
    table.add_column("File", width=28)
    table.add_column("Line", width=6, justify="right")

    for finding in sorted(report.findings, key=lambda f: _severity_order(f.severity)):
        color = _SEVERITY_COLORS[finding.severity]
        row: list[str] = [
            f"[{color}]{finding.severity.value}[/{color}]",
            finding.scanner,
        ]
        if verbose:
            row.extend([
                finding.title,
                finding.detail,
            ])
        else:
            row.append(finding.title)
        row.extend([
            finding.file_path or "",
            str(finding.line_number) if finding.line_number else "",
        ])
        table.add_row(*row)

    console.print(table)

    # Show code snippets for DANGER findings always; WARNING too when verbose
    snippet_thresholds = {Severity.DANGER}
    if verbose:
        snippet_thresholds.add(Severity.WARNING)

    for finding in report.findings:
        if finding.severity in snippet_thresholds and finding.code_snippet:
            console.print(
                Panel(
                    f"[dim]{finding.file_path}:{finding.line_number}[/dim]\n"
                    f"[{_SEVERITY_COLORS[finding.severity]}]{finding.code_snippet}[/{_SEVERITY_COLORS[finding.severity]}]",
                    title=f"[{_SEVERITY_COLORS[finding.severity]}]{finding.title}[/{_SEVERITY_COLORS[finding.severity]}]",
                    border_style=_SEVERITY_COLORS[finding.severity],
                )
            )

    console.print()


def _severity_order(s: Severity) -> int:
    return {Severity.DANGER: 0, Severity.WARNING: 1, Severity.INFO: 2}.get(s, 3)
