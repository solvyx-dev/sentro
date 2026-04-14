"""Dispatcher: route to text or JSON reporter based on format."""

from __future__ import annotations

from rich.console import Console

from ..config import Config
from ..models import ScanReport
from .json_reporter import render_json_report
from .text_reporter import render_text_report


def render_report(
    report: ScanReport,
    config: Config,
    console: Console | None = None,
) -> None:
    if config.output_format == "json":
        import click
        click.echo(render_json_report(report, config.thresholds))
    else:
        render_text_report(report, config.thresholds, console=console)
